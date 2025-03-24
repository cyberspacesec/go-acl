package domain

import (
	"errors"
	"strings"

	"github.com/cyberspacesec/go-acl/pkg/types"
)

// 错误定义
var (
	// ErrDomainNotFound 表示请求的域名不在访问控制列表中
	ErrDomainNotFound = errors.New("域名不在列表中")
	// ErrInvalidDomain 表示提供的域名格式无效
	ErrInvalidDomain = errors.New("无效的域名格式")
)

// DomainACL 实现了域名访问控制
// 支持黑名单和白名单两种模式，可选择是否匹配子域名
//
// 用法示例:
//
//	// 创建一个阻止特定域名及其子域名的黑名单
//	blacklist := domain.NewDomainACL(
//	    []string{"badsite.com", "malware.org"},
//	    types.Blacklist,
//	    true // 包含子域名
//	)
//
//	// 创建一个只允许特定域名的白名单
//	whitelist := domain.NewDomainACL(
//	    []string{"mycompany.com", "trusted-partner.org"},
//	    types.Whitelist,
//	    false // 不包含子域名
//	)
type DomainACL struct {
	// domains 存储控制的域名列表
	domains []string
	// listType 标识这是黑名单还是白名单
	listType types.ListType
	// includeSubdomains 标识是否检查子域名
	includeSubdomains bool
}

// NewDomainACL 创建一个新的域名访问控制列表
//
// 参数:
//   - domains: 要控制的域名列表
//     示例: []string{"example.com", "mydomain.org", "sub.domain.net"}
//   - listType: 列表类型（黑名单或白名单）
//     可用值: types.Blacklist（默认拒绝列表中的域名）或 types.Whitelist（只允许列表中的域名）
//   - includeSubdomains: 是否包含子域名匹配
//     true: "example.com"将匹配"sub.example.com"和"www.example.com"等
//     false: 只匹配完全相同的域名
//
// 返回:
//   - *DomainACL: 新创建的域名访问控制列表
//
// 所有域名在添加前都会被自动标准化（移除协议前缀、www前缀、端口号等）。
// 空域名或格式无效的域名会被忽略。
//
// 示例:
//
//	// 创建域名黑名单
//	blacklist := domain.NewDomainACL(
//	    []string{
//	        "bad-site.com",          // 将阻止bad-site.com
//	        "malicious-domain.org",  // 将阻止malicious-domain.org
//	    },
//	    types.Blacklist,
//	    true  // 启用子域名匹配
//	)
//
//	// 创建域名白名单（只允许列表中域名）
//	whitelist := domain.NewDomainACL(
//	    []string{
//	        "example.com",         // 允许example.com
//	        "trusted-partner.net", // 允许trusted-partner.net
//	    },
//	    types.Whitelist,
//	    true  // 启用子域名匹配
//	)
func NewDomainACL(domains []string, listType types.ListType, includeSubdomains bool) *DomainACL {
	acl := &DomainACL{
		listType:          listType,
		includeSubdomains: includeSubdomains,
	}

	// 添加域名前标准化
	acl.Add(domains...)
	return acl
}

// Add 向访问控制列表添加一个或多个域名
//
// 参数:
//   - domains: 要添加的一个或多个域名
//     例如: "example.com", "www.domain.org", "https://sub.another.net"
//
// 所有域名在添加前都会被自动标准化：
//   - 移除协议前缀 (http://, https://)
//   - 移除www前缀
//   - 移除端口号和路径
//   - 转换为小写
//
// 空域名或重复域名会被忽略，不会导致错误。
//
// 示例:
//
//	// 添加单个域名
//	acl.Add("example.com")
//
//	// 添加多个域名，包含各种格式
//	acl.Add(
//	    "https://www.domain.org",  // 会被标准化为 "domain.org"
//	    "Sub.Example.NET",         // 会被标准化为 "sub.example.net"
//	    "blog.site.com:8080/path", // 会被标准化为 "blog.site.com"
//	)
func (d *DomainACL) Add(domains ...string) {
	for _, domain := range domains {
		normalizedDomain := normalizeDomain(domain)
		if normalizedDomain == "" {
			continue
		}

		// 检查是否已存在
		exists := false
		for _, existingDomain := range d.domains {
			if existingDomain == normalizedDomain {
				exists = true
				break
			}
		}

		if !exists {
			d.domains = append(d.domains, normalizedDomain)
		}
	}
}

// Remove 从访问控制列表移除一个或多个域名
//
// 参数:
//   - domains: 要移除的一个或多个域名
//     例如: "example.com", "www.domain.org"
//
// 返回:
//   - error: 如果任何一个域名不在列表中，返回ErrDomainNotFound
//     如果找到部分域名，仍会移除这些域名，但仍返回错误
//
// 域名在移除前会被自动标准化，与Add方法使用相同的标准化规则。
//
// 示例:
//
//	// 移除单个域名
//	err := acl.Remove("example.com")
//	if err != nil {
//	    log.Printf("移除域名失败: %v", err)
//	}
//
//	// 移除多个域名
//	err = acl.Remove("domain1.com", "domain2.org")
//	if errors.Is(err, domain.ErrDomainNotFound) {
//	    log.Println("一个或多个域名不在列表中")
//	}
func (d *DomainACL) Remove(domains ...string) error {
	var notFoundErr error
	var newDomains []string

	for _, existingDomain := range d.domains {
		keep := true

		for _, domainToRemove := range domains {
			normalizedToRemove := normalizeDomain(domainToRemove)
			if normalizedToRemove == "" {
				continue
			}

			if existingDomain == normalizedToRemove {
				keep = false
				break
			}
		}

		if keep {
			newDomains = append(newDomains, existingDomain)
		}
	}

	// 检查是否所有要移除的域名都找到了
	if len(newDomains) == len(d.domains) {
		notFoundErr = ErrDomainNotFound
	} else {
		d.domains = newDomains
	}

	return notFoundErr
}

// GetDomains 获取访问控制列表中的所有域名
//
// 返回:
//   - []string: 域名列表的副本
//     例如: []string{"example.com", "mydomain.org", "sub.domain.net"}
//
// 返回的是当前域名列表的一个副本，对返回值的修改不会影响原始列表。
// 返回的所有域名都已经过标准化。
//
// 示例:
//
//	// 获取并显示当前域名列表
//	domains := acl.GetDomains()
//	fmt.Printf("访问控制列表包含 %d 个域名:\n", len(domains))
//	for i, domain := range domains {
//	    fmt.Printf("%d. %s\n", i+1, domain)
//	}
func (d *DomainACL) GetDomains() []string {
	// 返回副本以防止外部修改
	result := make([]string, len(d.domains))
	copy(result, d.domains)
	return result
}

// GetListType 获取访问控制列表的类型（黑名单或白名单）
//
// 返回:
//   - types.ListType: 列表类型
//   - types.Blacklist: 黑名单模式（默认允许，除了列表中的域名）
//   - types.Whitelist: 白名单模式（默认拒绝，除了列表中的域名）
//
// 示例:
//
//	// 获取并显示列表类型
//	listType := acl.GetListType()
//	if listType == types.Blacklist {
//	    fmt.Println("当前使用黑名单模式，默认允许访问")
//	} else {
//	    fmt.Println("当前使用白名单模式，默认拒绝访问")
//	}
func (d *DomainACL) GetListType() types.ListType {
	return d.listType
}

// Check 检查指定域名是否允许访问
//
// 参数:
//   - domain: 要检查的域名
//     例如: "example.com", "www.mydomain.org", "https://sub.domain.net/path"
//
// 返回:
//   - types.Permission: 访问权限
//   - types.Allowed: 允许访问
//   - types.Denied: 拒绝访问
//   - error: 如果提供的域名格式无效，返回ErrInvalidDomain
//
// 域名在检查前会被自动标准化。
// 如果设置了includeSubdomains=true，将检查子域名匹配。
//
// 权限决定逻辑:
//   - 黑名单模式: 默认返回Allowed，除非域名在列表中
//   - 白名单模式: 默认返回Denied，除非域名在列表中
//
// 示例:
//
//	// 检查域名是否允许访问
//	permission, err := acl.Check("api.example.com")
//	if err != nil {
//	    log.Printf("检查域名失败: %v", err)
//	    return
//	}
//
//	if permission == types.Allowed {
//	    log.Println("允许访问域名")
//	    // 处理允许的情况...
//	} else {
//	    log.Println("拒绝访问域名")
//	    // 处理拒绝的情况...
//	}
func (d *DomainACL) Check(domain string) (types.Permission, error) {
	normalizedDomain := normalizeDomain(domain)
	if normalizedDomain == "" {
		return types.Denied, ErrInvalidDomain
	}

	matched := d.matchDomain(normalizedDomain)

	// 根据列表类型和匹配结果确定权限
	if d.listType == types.Blacklist {
		if matched {
			return types.Denied, nil
		}
		return types.Allowed, nil
	} else { // Whitelist
		if matched {
			return types.Allowed, nil
		}
		return types.Denied, nil
	}
}

// matchDomain 检查域名是否匹配访问控制列表中的任何域名
//
// 参数:
//   - domain: 要检查的已标准化域名
//
// 返回:
//   - bool: 如果域名匹配列表中的任何域名，返回true
//
// 如果设置了includeSubdomains=true，将检查子域名匹配。
// 例如，如果列表中有"example.com"，且includeSubdomains=true，
// 则"sub.example.com"和"api.sub.example.com"都会匹配。
//
// 如果includeSubdomains=false，则只有完全相同的域名才会匹配。
func (d *DomainACL) matchDomain(domain string) bool {
	if domain == "" {
		return false
	}

	for _, aclDomain := range d.domains {
		// 完全匹配
		if domain == aclDomain {
			return true
		}

		// 如果启用了子域名匹配，检查是否是受控域名的子域名
		if d.includeSubdomains {
			if strings.HasSuffix(domain, "."+aclDomain) {
				return true
			}
		}
	}

	return false
}

// normalizeDomain 标准化域名，删除不必要的部分
//
// 参数:
//   - domain: 要标准化的域名
//     例如: "https://www.example.com:8080/path?query#fragment"
//
// 返回:
//   - string: 标准化后的域名
//     例如: "example.com"
//
// 标准化过程包括:
//   - 移除协议前缀 (http://, https://)
//   - 移除"www."前缀
//   - 移除用户名和密码部分
//   - 移除端口号
//   - 移除路径、查询参数和片段标识符
//   - 转换为小写
//   - 移除首尾空白
//
// 如果输入为空或经处理后为空，则返回空字符串。
//
// 示例:
//
//	normalizeDomain("https://www.Example.COM:8080/path?q=1") // 返回 "example.com"
//	normalizeDomain("sub.DOMAIN.org") // 返回 "sub.domain.org"
//	normalizeDomain("user:pass@site.net") // 返回 "site.net"
func normalizeDomain(domain string) string {
	// 转小写并去除首尾空格
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return ""
	}

	// 处理特殊的双斜杠开头格式 (//example.com)
	domain = strings.TrimPrefix(domain, "//")

	// 移除协议前缀
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// 移除用户名和密码部分
	if atIndex := strings.Index(domain, "@"); atIndex != -1 {
		domain = domain[atIndex+1:]
	}

	// 移除路径、查询参数和片段标识符
	for _, sep := range []string{"/", "?", "#"} {
		if sepIndex := strings.Index(domain, sep); sepIndex != -1 {
			domain = domain[:sepIndex]
		}
	}

	// 移除端口号，但要注意IPv6地址的格式
	// 在IPv6中，地址部分可能包含冒号并被方括号包围，如 [2001:db8::1]:8080
	var portIndex int
	if strings.HasPrefix(domain, "[") && strings.Contains(domain, "]:") {
		// 是IPv6地址加端口
		portIndex = strings.Index(domain, "]:")
		if portIndex != -1 {
			domain = domain[:portIndex+1] // 保留IPv6地址部分，包含右括号
		}
	} else {
		// 普通域名或IPv4地址加端口
		portIndex = strings.LastIndex(domain, ":")
		if portIndex != -1 {
			domain = domain[:portIndex]
		}
	}

	// 移除www前缀
	domain = strings.TrimPrefix(domain, "www.")

	return domain
}
