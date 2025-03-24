package domain

import (
	"errors"
	"strings"

	"github.com/cyberspacesec/go-acl/pkg/types"
)

var (
	// ErrInvalidDomain 表示提供的域名格式无效
	ErrInvalidDomain = errors.New("invalid domain format")
	// ErrDomainNotFound 表示指定的域名不存在
	ErrDomainNotFound = errors.New("domain not found")
)

// DomainAcl 实现了对域名的访问控制
type DomainAcl struct {
	// domains 存储控制的域名列表
	domains []string
	// listType 标识这是黑名单还是白名单
	listType types.ListType
	// includeSubdomains 标识是否检查子域名
	includeSubdomains bool
}

// NewDomainAcl 创建一个新的域名访问控制列表
func NewDomainAcl(domains []string, listType types.ListType, includeSubdomains bool) *DomainAcl {
	// 确保所有域名格式正确并移除前导的 "www." 和 "."
	normalizedDomains := make([]string, 0, len(domains))
	for _, domain := range domains {
		// 使用通用的域名规范化函数处理域名
		normalizedDomain := normalizeDomain(domain)

		// 忽略空域名
		if normalizedDomain != "" {
			normalizedDomains = append(normalizedDomains, normalizedDomain)
		}
	}

	return &DomainAcl{
		domains:           normalizedDomains,
		listType:          listType,
		includeSubdomains: includeSubdomains,
	}
}

// Add 添加一个或多个域名到访问控制列表
func (d *DomainAcl) Add(domains ...string) {
	for _, domain := range domains {
		// 标准化域名
		normalizedDomain := normalizeDomain(domain)

		// 忽略空域名
		if normalizedDomain == "" {
			continue
		}

		// 检查域名是否已存在
		exists := false
		for _, existingDomain := range d.domains {
			if existingDomain == normalizedDomain {
				exists = true
				break
			}
		}

		// 如果不存在，则添加
		if !exists {
			d.domains = append(d.domains, normalizedDomain)
		}
	}
}

// Remove 从访问控制列表中移除一个或多个域名
// 如果指定的域名不在列表中，返回ErrDomainNotFound错误
func (d *DomainAcl) Remove(domains ...string) error {
	if len(domains) == 0 {
		return nil
	}

	var errDomainNotFound error

	for _, domain := range domains {
		// 标准化域名
		normalizedDomain := normalizeDomain(domain)
		if normalizedDomain == "" {
			continue
		}

		// 查找并移除域名
		found := false
		for idx, existingDomain := range d.domains {
			if existingDomain == normalizedDomain {
				// 找到后移除
				d.domains = append(d.domains[:idx], d.domains[idx+1:]...)
				found = true
				break
			}
		}

		// 如果没找到，记录错误
		if !found {
			errDomainNotFound = ErrDomainNotFound
		}
	}

	return errDomainNotFound
}

// GetDomains 返回当前ACL中的所有域名
func (d *DomainAcl) GetDomains() []string {
	// 返回域名列表的副本，防止外部修改
	domains := make([]string, len(d.domains))
	copy(domains, d.domains)
	return domains
}

// GetListType 返回当前ACL的列表类型（黑名单或白名单）
func (d *DomainAcl) GetListType() types.ListType {
	return d.listType
}

// Check 检查给定的域名是否允许访问
func (d *DomainAcl) Check(domain string) (types.Permission, error) {
	if domain == "" {
		return types.Denied, ErrInvalidDomain
	}

	// 标准化域名
	normalizedDomain := normalizeDomain(domain)
	if normalizedDomain == "" {
		return types.Denied, ErrInvalidDomain
	}

	// 执行匹配逻辑
	found := d.matchDomain(normalizedDomain)

	// 根据列表类型和匹配结果确定权限
	if d.listType == types.Blacklist {
		if found {
			return types.Denied, nil
		}
		return types.Allowed, nil
	} else { // 白名单
		if found {
			return types.Allowed, nil
		}
		return types.Denied, nil
	}
}

// matchDomain 检查域名是否匹配规则列表
func (d *DomainAcl) matchDomain(domain string) bool {
	for _, checkDomain := range d.domains {
		// 精确匹配
		if domain == checkDomain {
			return true
		}

		// 子域名匹配
		if d.includeSubdomains && strings.HasSuffix(domain, "."+checkDomain) {
			return true
		}
	}
	return false
}

// normalizeDomain 规范化域名，移除协议前缀、www前缀、用户名密码、端口号、路径、查询参数和锚点等
func normalizeDomain(domain string) string {
	// 移除空格并转换为小写，便于后续处理
	domain = strings.TrimSpace(domain)
	lowerDomain := strings.ToLower(domain)

	// 处理以双斜杠开头但无协议的URL (//example.com/path)
	if strings.HasPrefix(lowerDomain, "//") {
		domain = domain[2:]
		lowerDomain = strings.ToLower(domain)
	}

	// 移除可能的 http:// 或 https:// 前缀，处理大小写
	if strings.HasPrefix(lowerDomain, "http://") {
		domain = domain[7:]
		lowerDomain = strings.ToLower(domain)
	} else if strings.HasPrefix(lowerDomain, "https://") {
		domain = domain[8:]
		lowerDomain = strings.ToLower(domain)
	}

	// 移除用户名和密码部分 (user:password@example.com)
	if idx := strings.Index(domain, "@"); idx != -1 {
		domain = domain[idx+1:]
		lowerDomain = strings.ToLower(domain)
	}

	// 移除可能的端口号部分 (example.com:8080)
	if idx := strings.LastIndex(domain, ":"); idx != -1 {
		// 确保这不是IPv6地址
		if !strings.Contains(domain[0:idx], "[") {
			// 检查冒号后面是否全部是数字（端口号）
			isPort := true
			portPart := domain[idx+1:]

			// 检查下一个分隔符（如果有的话）
			slashIndex := strings.Index(portPart, "/")
			questionIndex := strings.Index(portPart, "?")
			hashIndex := strings.Index(portPart, "#")

			// 找到最近的分隔符
			endIndex := len(portPart)
			if slashIndex != -1 && slashIndex < endIndex {
				endIndex = slashIndex
			}
			if questionIndex != -1 && questionIndex < endIndex {
				endIndex = questionIndex
			}
			if hashIndex != -1 && hashIndex < endIndex {
				endIndex = hashIndex
			}

			// 截取实际的端口部分
			portPart = portPart[:endIndex]

			// 检查是否全为数字
			for _, c := range portPart {
				if c < '0' || c > '9' {
					isPort = false
					break
				}
			}

			if isPort && portPart != "" {
				domain = domain[0:idx]
				lowerDomain = strings.ToLower(domain)
			}
		}
	}

	// 移除可能的路径部分 (example.com/path)
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[0:idx]
		lowerDomain = strings.ToLower(domain)
	}

	// 移除可能的查询参数 (example.com?param=value)
	if idx := strings.Index(domain, "?"); idx != -1 {
		domain = domain[0:idx]
		lowerDomain = strings.ToLower(domain)
	}

	// 移除可能的锚点 (example.com#section)
	if idx := strings.Index(domain, "#"); idx != -1 {
		domain = domain[0:idx]
		lowerDomain = strings.ToLower(domain)
	}

	// 移除 www. 前缀，处理大小写
	if strings.HasPrefix(lowerDomain, "www.") {
		domain = domain[4:]
	}

	// 返回小写形式
	return strings.ToLower(strings.TrimSpace(domain))
}
