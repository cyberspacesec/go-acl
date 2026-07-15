package domain

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/cyberspacesec/acl-skills/pkg/types"
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
	// mu 保护 domains 的并发访问；listType 与 includeSubdomains 在构造后不可变
	mu      sync.RWMutex
	domains []string
	// domainSet 是 domains 的 set 镜像，用于 includeSubdomains=false 时的 O(1) 精确匹配
	domainSet map[string]struct{}
	// wildcardSuffixes 存放通配规则 *.example.com 的裸后缀，用于仅子域名匹配（不含主域本身）
	wildcardSuffixes []string
	// prefixes 存放前缀规则 api.* 的裸前缀，匹配 api.example.com 但不匹配 example.com
	prefixes []string
	// looseSuffixes 存放宽松后缀规则 *example.com 的裸后缀，匹配 example.com 主域本身及其任意子域（标签边界匹配）
	looseSuffixes []string
	// regexes 存放正则规则 /pattern/ 编译后的正则，按声明顺序匹配
	regexes []*regexp.Regexp
	// regexSources 存放正则规则的原文（用于 GetDomains 还原与 Remove 匹配）
	regexSources      []string
	listType          types.ListType
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
		domainSet:         make(map[string]struct{}),
	}

	// 添加域名前标准化
	_ = acl.Add(domains...)
	return acl
}

// NewDomainACLWithDefaults 创建一个新的域名访问控制列表，同时加入预定义的域名集合
//
// 参数:
//   - domains: 基础域名列表
//   - listType: 列表类型（黑名单或白名单）
//   - includeSubdomains: 是否包含子域名匹配
//   - predefinedSets: 要包含的预定义域名集合列表
//     例如: []PredefinedSet{Shorteners, DisposableEmail}
//   - allowDefaultSets: 预定义集合的处理方式
//   - 对于黑名单，false 表示阻止这些域名（添加到黑名单）
//   - 对于白名单，true 表示允许这些域名（添加到白名单）
//
// 返回:
//   - *DomainACL: 创建的域名访问控制列表
//   - error: ErrInvalidPredefinedSet 指定的预定义集合不存在
//
// 此函数是创建具有安全防护功能 ACL 的便捷方法，特别适用于一键阻止高风险域名类别。
//
// 示例:
//
//	// 创建黑名单，阻止短链与一次性邮箱域名
//	blacklist, err := domain.NewDomainACLWithDefaults(
//	    []string{"malware.example.com"},
//	    types.Blacklist,
//	    true,
//	    []domain.PredefinedSet{
//	        domain.Shorteners,
//	        domain.DisposableEmail,
//	    },
//	    false, // 添加到黑名单阻止这些域名
//	)
//	if err != nil {
//	    log.Printf("创建域名黑名单失败: %v", err)
//	    return
//	}
func NewDomainACLWithDefaults(domains []string, listType types.ListType, includeSubdomains bool, predefinedSets []PredefinedSet, allowDefaultSets bool) (*DomainACL, error) {
	acl := NewDomainACL(domains, listType, includeSubdomains)
	for _, setName := range predefinedSets {
		if err := acl.AddPredefinedSet(setName, allowDefaultSets); err != nil {
			return nil, err
		}
	}
	return acl, nil
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
func (d *DomainACL) Add(domains ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, domain := range domains {
		// 正则规则 /pattern/ 必须用原文判断与处理：normalizeDomain 会把首字符 "/" 当作
		// 路径分隔符截断、且 ToLower 会破坏 \D 等大小写敏感的正则转义，故正则规则绕过标准化。
		if isRegexRule(domain) {
			pattern := stripRegexSlashes(domain)
			if pattern == "" {
				continue
			}
			// 已存在原文则跳过
			found := false
			for _, src := range d.regexSources {
				if src == pattern {
					found = true
					break
				}
			}
			if found {
				continue
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("无效的正则规则 %q: %w", pattern, err)
			}
			d.regexes = append(d.regexes, re)
			d.regexSources = append(d.regexSources, pattern)
			continue
		}

		normalizedDomain := normalizeDomain(domain)
		if normalizedDomain == "" {
			// 空域名或经标准化后为空，按既有语义忽略
			continue
		}

		// 通配规则 *.example.com → 存裸后缀，仅匹配其子域（不含主域本身）
		if isWildcardDomain(normalizedDomain) {
			suffix := stripWildcard(normalizedDomain)
			if suffix == "" {
				continue
			}
			// 去重
			found := false
			for _, existing := range d.wildcardSuffixes {
				if existing == suffix {
					found = true
					break
				}
			}
			if !found {
				d.wildcardSuffixes = append(d.wildcardSuffixes, suffix)
			}
			continue
		}

		// 前缀规则 api.* → 存裸前缀，匹配 api.example.com 但不匹配 example.com
		if isPrefixDomain(normalizedDomain) {
			prefix := stripPrefix(normalizedDomain)
			if prefix == "" {
				continue
			}
			found := false
			for _, existing := range d.prefixes {
				if existing == prefix {
					found = true
					break
				}
			}
			if !found {
				d.prefixes = append(d.prefixes, prefix)
			}
			continue
		}

		// 宽松后缀规则 *example.com → 存裸后缀，匹配 example.com 主域本身及其任意子域（标签边界匹配）
		if isLooseSuffixDomain(normalizedDomain) {
			suffix := stripStar(normalizedDomain)
			if suffix == "" {
				continue
			}
			found := false
			for _, existing := range d.looseSuffixes {
				if existing == suffix {
					found = true
					break
				}
			}
			if !found {
				d.looseSuffixes = append(d.looseSuffixes, suffix)
			}
			continue
		}

		// 普通规则进主表
		exists := false
		for _, existingDomain := range d.domains {
			if existingDomain == normalizedDomain {
				exists = true
				break
			}
		}

		if !exists {
			d.domains = append(d.domains, normalizedDomain)
			if d.domainSet != nil {
				d.domainSet[normalizedDomain] = struct{}{}
			}
		}
	}
	return nil
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
	// 零参数：no-op，不视为错误
	if len(domains) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// 构建待删除的标准化集合，区分各特殊语法
	var wildcardToRemove []string
	var prefixToRemove []string
	var looseSuffixToRemove []string
	var regexToRemove []string
	toRemove := make(map[string]struct{}, len(domains))
	for _, dom := range domains {
		// 正则规则用原文判断，绕过 normalizeDomain（同 Add）
		if isRegexRule(dom) {
			regexToRemove = append(regexToRemove, stripRegexSlashes(dom))
			continue
		}
		n := normalizeDomain(dom)
		if n == "" {
			continue
		}
		switch {
		case isWildcardDomain(n):
			wildcardToRemove = append(wildcardToRemove, stripWildcard(n))
		case isPrefixDomain(n):
			prefixToRemove = append(prefixToRemove, stripPrefix(n))
		case isLooseSuffixDomain(n):
			looseSuffixToRemove = append(looseSuffixToRemove, stripStar(n))
		default:
			toRemove[n] = struct{}{}
		}
	}
	// 传入了参数但全部标准化后为空：视为未找到，保持与旧版一致的错误语义
	if len(toRemove) == 0 && len(wildcardToRemove) == 0 && len(prefixToRemove) == 0 && len(looseSuffixToRemove) == 0 && len(regexToRemove) == 0 {
		return ErrDomainNotFound
	}

	removed := 0

	// 通配删除（就地过滤复用底层数组）
	if len(wildcardToRemove) > 0 {
		newSuffixes := d.wildcardSuffixes[:0]
		for _, existing := range d.wildcardSuffixes {
			drop := false
			for _, w := range wildcardToRemove {
				if existing == w {
					drop = true
					break
				}
			}
			if drop {
				removed++
				continue
			}
			newSuffixes = append(newSuffixes, existing)
		}
		d.wildcardSuffixes = newSuffixes
	}

	// 前缀删除
	if len(prefixToRemove) > 0 {
		newPrefixes := d.prefixes[:0]
		for _, existing := range d.prefixes {
			drop := false
			for _, p := range prefixToRemove {
				if existing == p {
					drop = true
					break
				}
			}
			if drop {
				removed++
				continue
			}
			newPrefixes = append(newPrefixes, existing)
		}
		d.prefixes = newPrefixes
	}

	// 宽松后缀删除
	if len(looseSuffixToRemove) > 0 {
		newLoose := d.looseSuffixes[:0]
		for _, existing := range d.looseSuffixes {
			drop := false
			for _, s := range looseSuffixToRemove {
				if existing == s {
					drop = true
					break
				}
			}
			if drop {
				removed++
				continue
			}
			newLoose = append(newLoose, existing)
		}
		d.looseSuffixes = newLoose
	}

	// 正则删除（regexes 与 regexSources 索引一一对应，同步过滤）
	if len(regexToRemove) > 0 {
		newRegexes := d.regexes[:0]
		newSources := d.regexSources[:0]
		for i, src := range d.regexSources {
			drop := false
			for _, r := range regexToRemove {
				if src == r {
					drop = true
					break
				}
			}
			if drop {
				removed++
				continue
			}
			newRegexes = append(newRegexes, d.regexes[i])
			newSources = append(newSources, src)
		}
		d.regexes = newRegexes
		d.regexSources = newSources
	}

	// 普通删除
	var newDomains []string
	for _, existing := range d.domains {
		if _, drop := toRemove[existing]; drop {
			removed++
			continue
		}
		newDomains = append(newDomains, existing)
	}

	if removed == 0 {
		return ErrDomainNotFound
	}

	// 更新 domains 与 domainSet 镜像
	d.domains = newDomains
	newSet := make(map[string]struct{}, len(newDomains))
	for _, dom := range newDomains {
		newSet[dom] = struct{}{}
	}
	d.domainSet = newSet
	return nil
}

// AddPredefinedSet 向域名访问控制列表添加一个预定义域名集合
//
// 参数:
//   - setName: 预定义集合名称
//     可用值: domain.Shorteners, domain.DisposableEmail, domain.AllMaliciousDomains 等
//   - allowSet: 预定义集合的处理方式
//   - 对于黑名单，false 表示阻止这些域名（添加到黑名单）
//   - 对于白名单，true 表示允许这些域名（添加到白名单）
//
// 返回:
//   - error: 可能的错误:
//   - ErrInvalidPredefinedSet: 如果提供了无效的预定义集合名称
//
// 域名在添加前会经 normalizeDomain 自动标准化，与 Add 行为一致。
// 当 listType 与 allowSet 的组合表示"不实际添加"时，本方法为 no-op 并返回 nil。
//
// 示例:
//
//	// 向黑名单添加短链域名（阻止访问）
//	err := acl.AddPredefinedSet(domain.Shorteners, false)
//	// 向白名单添加可信 CDN 域名（允许访问）
//	err := acl.AddPredefinedSet(domain.TrustedCDN, true)
func (d *DomainACL) AddPredefinedSet(setName PredefinedSet, allowSet bool) error {
	domains, err := getPredefinedSet(setName)
	if err != nil {
		return err
	}
	// 与 IP 侧语义一致：黑名单+!allowSet 添加为阻止项；白名单+allowSet 添加为允许项
	if (d.listType == types.Blacklist && !allowSet) || (d.listType == types.Whitelist && allowSet) {
		return d.Add(domains...)
	}
	return nil
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
	d.mu.RLock()
	defer d.mu.RUnlock()

	// 返回副本以防止外部修改
	result := make([]string, 0, len(d.domains)+len(d.wildcardSuffixes)+len(d.prefixes)+len(d.looseSuffixes)+len(d.regexSources))
	result = append(result, d.domains...)
	for _, s := range d.wildcardSuffixes {
		result = append(result, "*."+s)
	}
	for _, p := range d.prefixes {
		result = append(result, p+".*")
	}
	for _, s := range d.looseSuffixes {
		result = append(result, "*"+s)
	}
	for _, src := range d.regexSources {
		result = append(result, "/"+src+"/")
	}
	return result
}

// GetRules 返回当前域名规则列表的副本
//
// 这是 MutableACL 接口要求的统一命名方法，等同于 GetDomains。
// 旧代码可继续使用 GetDomains，二者行为一致。
func (d *DomainACL) GetRules() []string {
	return d.GetDomains()
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
	d.mu.RLock()
	defer d.mu.RUnlock()

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

	d.mu.RLock()
	defer d.mu.RUnlock()

	matched := d.matchDomain(normalizedDomain)

	// 根据列表类型确定权限（黑名单命中→拒绝；白名单未命中→拒绝）
	return types.DecideByListType(d.listType, matched), nil
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

	// 通配规则：*.example.com 仅匹配 example.com 的子域，不含 example.com 本身
	for _, suffix := range d.wildcardSuffixes {
		if strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}

	// 前缀规则：api.* 匹配 api.example.com 等以 api. 开头者，但不含 example.com 本身
	for _, prefix := range d.prefixes {
		if strings.HasPrefix(domain, prefix+".") {
			return true
		}
	}

	// 宽松后缀规则：*example.com 匹配 example.com 主域本身及其任意子域（在标签边界匹配，避免 notevil.com 这类相邻域名误命中）
	for _, suffix := range d.looseSuffixes {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}

	// 正则规则：按声明顺序 MatchString，命中即返回。
	// 注意：Check 会先将待查域名经 normalizeDomain 小写化，故正则匹配的是小写域名主体。
	// 这是域名大小写不敏感（DNS 规范）的后果：正则中不应依赖 [A-Z] 等大写字符类，
	// 应按小写形式书写（如 /^api-\d+\.example\.com$/）。
	for _, re := range d.regexes {
		if re.MatchString(domain) {
			return true
		}
	}

	// 不含子域名匹配：O(1) 精确查找
	if !d.includeSubdomains {
		if d.domainSet != nil {
			_, ok := d.domainSet[domain]
			return ok
		}
		// 兜底：domainSet 未初始化时回退线性扫描
		for _, aclDomain := range d.domains {
			if domain == aclDomain {
				return true
			}
		}
		return false
	}

	// 含子域名匹配：精确命中或后缀命中
	for _, aclDomain := range d.domains {
		// 完全匹配
		if domain == aclDomain {
			return true
		}
		if strings.HasSuffix(domain, "."+aclDomain) {
			return true
		}
	}

	return false
}

// isWildcardDomain 判断规则是否为通配形式 *.example.com
func isWildcardDomain(d string) bool {
	return strings.HasPrefix(d, "*.")
}

// stripWildcard 去除 *. 前缀，返回裸后缀
func stripWildcard(d string) string {
	return strings.TrimPrefix(d, "*.")
}

// isPrefixDomain 判断规则是否为前缀形式 api.*
func isPrefixDomain(d string) bool {
	return strings.HasSuffix(d, ".*")
}

// stripPrefix 去除 .* 后缀，返回裸前缀
func stripPrefix(d string) string {
	return strings.TrimSuffix(d, ".*")
}

// isLooseSuffixDomain 判断规则是否为宽松后缀形式 *example.com（无点，含主域及其子域）
// 注意：*.example.com（含点）是通配仅子域规则，由 isWildcardDomain 处理，不在此列
func isLooseSuffixDomain(d string) bool {
	return strings.HasPrefix(d, "*") && !strings.HasPrefix(d, "*.")
}

// stripStar 去除 * 前缀，返回裸后缀
func stripStar(d string) string {
	return strings.TrimPrefix(d, "*")
}

// isRegexRule 判断规则是否为正则形式 /pattern/（首尾斜杠包围）
func isRegexRule(d string) bool {
	return len(d) >= 2 && strings.HasPrefix(d, "/") && strings.HasSuffix(d, "/")
}

// stripRegexSlashes 去除首尾斜杠，返回正则原文
func stripRegexSlashes(d string) string {
	return d[1 : len(d)-1]
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

	// 剥除末尾点（FQDN 根标签），使 example.com. 与 example.com 等价
	domain = strings.TrimSuffix(domain, ".")

	return domain
}
