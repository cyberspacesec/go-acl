package acl

import (
	"sync"

	"github.com/cyberspacesec/acl-skills/pkg/domain"
	"github.com/cyberspacesec/acl-skills/pkg/ip"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// Manager 是访问控制列表管理器，整合了域名和IP访问控制
// 它提供了一个统一的接口来管理不同类型的访问控制规则
// 内部使用读写锁确保并发安全
//
// 主要功能：
//   - 管理域名访问控制（黑/白名单）
//   - 管理IP访问控制（黑/白名单）
//   - 支持从文件加载和保存IP规则
//   - 支持预定义的IP集合（如私有网络、云元数据等）
//
// 用法示例：
//
//	// 创建管理器
//	manager := acl.NewManager()
//
//	// 设置域名白名单
//	manager.SetDomainACL([]string{"example.com"}, types.Whitelist, true)
//
//	// 设置IP黑名单
//	err := manager.SetIPACL([]string{"192.168.1.1", "10.0.0.0/8"}, types.Blacklist)
//
//	// 检查访问权限
//	domainPerm, _ := manager.CheckDomain("sub.example.com")
//	ipPerm, _ := manager.CheckIP("8.8.8.8")
type Manager struct {
	// mu 仅保护 acls map 的增删查；各子 ACL 自带锁保护自身规则。
	// 这样查询不同 kind 的 ACL 互不阻塞。
	mu   sync.RWMutex
	acls map[string]types.MutableACL
}

// ACL kind 常量，用于标识 Manager 中注册的不同 ACL 类型
const (
	// KindDomain 域名 ACL 的注册键
	KindDomain = "domain"
	// KindIP IP ACL 的注册键
	KindIP = "ip"
)

// NewManager 创建一个新的ACL管理器
//
// 返回:
//   - *Manager: 一个初始化的、空的ACL管理器实例
//
// 新创建的管理器不包含任何访问控制规则。在使用前，
// 需要至少设置一种ACL（域名或IP）才能进行有效的访问控制。
//
// 示例:
//
//	manager := acl.NewManager()
//	// 继续配置...
func NewManager() *Manager {
	return &Manager{
		acls: make(map[string]types.MutableACL),
	}
}

// ipACL 取出已注册的 *ip.IPACL，若未注册或类型不符返回 nil
//
// 供依赖 IPACL 具体方法（如 SaveToFile、AddPredefinedSet）的旧 API 使用。
func (m *Manager) ipACL() *ip.IPACL {
	a, ok := m.GetACL(KindIP)
	if !ok {
		return nil
	}
	if ipACL, ok := a.(*ip.IPACL); ok {
		return ipACL
	}
	return nil
}

// domainACL 取出已注册的 *domain.DomainACL，若未注册或类型不符返回 nil
func (m *Manager) domainACL() *domain.DomainACL {
	a, ok := m.GetACL(KindDomain)
	if !ok {
		return nil
	}
	if domainACL, ok := a.(*domain.DomainACL); ok {
		return domainACL
	}
	return nil
}

// SetDomainACL 设置域名访问控制列表
//
// 参数:
//   - domains: 要控制的域名列表
//     例如: []string{"example.com", "mydomain.org"}
//   - listType: 列表类型（黑名单或白名单）
//     可用值: types.Blacklist（黑名单）或 types.Whitelist（白名单）
//   - includeSubdomains: 是否包含子域名
//     true: 例如允许"example.com"时，也会允许"sub.example.com"
//     false: 只匹配完全相同的域名
//
// 此方法会覆盖之前设置的任何域名访问控制列表。
// 域名会被自动标准化（移除"www."前缀、协议、端口等）。
//
// 示例:
//
//	// 设置白名单，只允许example.com及其子域名
//	manager.SetDomainACL([]string{"example.com"}, types.Whitelist, true)
//
//	// 设置黑名单，阻止特定域名（不含子域名）
//	manager.SetDomainACL([]string{"ads.example.com", "malware.com"}, types.Blacklist, false)
func (m *Manager) SetDomainACL(domains []string, listType types.ListType, includeSubdomains bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acls[KindDomain] = domain.NewDomainACL(domains, listType, includeSubdomains)
}

// SetDomainACLStrict 设置域名访问控制列表，返回无效域名错误。
//
// 与 SetDomainACL 行为一致，但在解析域名失败时返回 error 而非静默忽略，
// 使调用方能感知无效输入。与 SetIPACL 的错误返回语义对称。
//
// 参数:
//   - domains: 要控制的域名列表
//   - listType: 列表类型（黑名单或白名单）
//   - includeSubdomains: 是否包含子域名匹配
//
// 返回:
//   - error: 域名解析失败时返回错误（具体错误类型由 domain 层定义）
//
// 此方法覆盖之前设置的任何域名访问控制列表。
//
// 示例:
//
//	err := manager.SetDomainACLStrict(
//	    []string{"malware.example.com", "bad..domain"},
//	    types.Blacklist,
//	    true,
//	)
//	if err != nil {
//	    log.Printf("设置域名ACL失败: %v", err)
//	}
func (m *Manager) SetDomainACLStrict(domains []string, listType types.ListType, includeSubdomains bool) error {
	a, err := domain.NewDomainACLStrict(domains, listType, includeSubdomains)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acls[KindDomain] = a
	return nil
}

// SetDomainACLWithDefaults 设置域名访问控制列表，并包含预定义的域名集合
//
// 参数:
//   - domains: 自定义的域名列表
//   - listType: 列表类型（黑名单或白名单）
//   - includeSubdomains: 是否包含子域名匹配
//   - predefinedSets: 要包含的预定义域名集合
//     例如: []domain.PredefinedSet{domain.Shorteners, domain.DisposableEmail}
//   - allowDefaultSets: 预定义集合的处理方式
//   - 对于黑名单，false 表示阻止这些域名（添加到黑名单）
//   - 对于白名单，true 表示允许这些域名（添加到白名单）
//
// 返回:
//   - error: ErrInvalidPredefinedSet 指定的预定义集合不存在
//
// 此方法会覆盖之前设置的任何域名访问控制列表，适合用于快速创建具有安全防护的域名 ACL。
//
// 示例:
//
//	// 创建黑名单，阻止短链与一次性邮箱域名
//	err := manager.SetDomainACLWithDefaults(
//	    []string{"malware.example.com"},
//	    types.Blacklist,
//	    true,
//	    []domain.PredefinedSet{
//	        domain.Shorteners,
//	        domain.DisposableEmail,
//	    },
//	    false,
//	)
func (m *Manager) SetDomainACLWithDefaults(domains []string, listType types.ListType, includeSubdomains bool, predefinedSets []domain.PredefinedSet, allowDefaultSets bool) error {
	newACL, err := domain.NewDomainACLWithDefaults(domains, listType, includeSubdomains, predefinedSets, allowDefaultSets)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acls[KindDomain] = newACL
	return nil
}

// SetIPACL 设置IP访问控制列表
//
// 参数:
//   - ipRanges: 要控制的IP或CIDR列表
//     例如: []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
//   - listType: 列表类型（黑名单或白名单）
//     可用值: types.Blacklist（黑名单）或 types.Whitelist（白名单）
//
// 返回:
//   - error: 如果IP格式无效则返回错误
//
// 此方法会覆盖之前设置的任何IP访问控制列表。
// 支持IPv4和IPv6地址，单个IP或CIDR格式。
//
// 示例:
//
//	// 设置IP黑名单
//	err := manager.SetIPACL([]string{
//	    "192.168.1.100",  // 单个IPv4
//	    "10.0.0.0/8",     // IPv4 CIDR
//	    "2001:db8::/32",  // IPv6 CIDR
//	}, types.Blacklist)
//
//	if err != nil {
//	    log.Fatalf("设置IP ACL失败: %v", err)
//	}
func (m *Manager) SetIPACL(ipRanges []string, listType types.ListType) error {
	newACL, err := ip.NewIPACL(ipRanges, listType)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.acls[KindIP] = newACL
	return nil
}

// SetIPACLFromFile 从文件加载IP访问控制列表
//
// 参数:
//   - filePath: 包含IP列表的文件路径
//     例如: "/path/to/blacklist.txt", "./config/whitelist.txt"
//   - listType: 列表类型（黑名单或白名单）
//     可用值: types.Blacklist（黑名单）或 types.Whitelist（白名单）
//
// 返回:
//   - error: 打开文件、解析IP或创建ACL时的错误
//
// 文件格式说明:
//   - 每行一个IP或CIDR
//   - 支持#开头的注释行
//   - 支持行内注释（# 后的内容被忽略）
//   - 空行会被忽略
//
// 示例文件内容:
//
//	# 这是我的IP黑名单
//	192.168.1.100  # 恶意IP
//	10.0.0.0/8     # 整个内网范围
//	2001:db8::/32  # IPv6范围
//
// 示例:
//
//	// 从文件加载IP黑名单
//	err := manager.SetIPACLFromFile("./blacklist.txt", types.Blacklist)
//	if err != nil {
//	    log.Printf("加载黑名单失败: %v", err)
//	}
func (m *Manager) SetIPACLFromFile(filePath string, listType types.ListType) error {
	newACL, err := ip.NewIPACLFromFile(filePath, listType)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.acls[KindIP] = newACL
	return nil
}

// SaveIPACLToFile 将当前IP访问控制列表保存到文件
// 如果文件已存在，overwrite参数决定是否覆盖文件
//
// 参数:
//   - filePath: 要保存的文件路径
//     例如: "/path/to/saved_blacklist.txt", "./config/whitelist.txt"
//   - overwrite: 是否覆盖现有文件
//     true: 如果文件已存在，将覆盖
//     false: 如果文件已存在，将返回错误
//
// 返回:
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置IP ACL
//   - config.ErrFileExists: 如果文件已存在且overwrite=false
//   - config.ErrFilePermission: 如果无权限写入文件
//
// 生成的文件将包含:
//   - 描述性注释头
//   - 生成时间戳
//   - 当前所有IP范围，每行一个
//
// 示例:
//
//	// 保存当前IP列表到文件（不覆盖现有文件）
//	err := manager.SaveIPACLToFile("./my_acl.txt", false)
//	if err != nil {
//	    if errors.Is(err, config.ErrFileExists) {
//	        log.Println("文件已存在，未覆盖")
//	    } else if errors.Is(err, types.ErrNoACL) {
//	        log.Println("未设置IP ACL，无需保存")
//	    } else {
//	        log.Printf("保存失败: %v", err)
//	    }
//	}
func (m *Manager) SaveIPACLToFile(filePath string, overwrite bool) error {
	ipA := m.ipACL()
	if ipA == nil {
		return types.ErrNoACL
	}
	return ipA.SaveToFile(filePath, overwrite)
}

// SaveIPACLToFileWithOverwrite 兼容旧版API，默认覆盖已存在的文件
// 已废弃：请改用 SaveIPACLToFile
//
// 参数:
//   - filePath: 要保存的文件路径
//
// 返回:
//   - error: 保存过程中的错误
//
// 此方法等同于调用 SaveIPACLToFile(filePath, true)
//
// 示例:
//
//	// 保存并覆盖现有文件
//	err := manager.SaveIPACLToFileWithOverwrite("./my_acl.txt")
func (m *Manager) SaveIPACLToFileWithOverwrite(filePath string) error {
	return m.SaveIPACLToFile(filePath, true)
}

// SetDomainACLFromFile 从文件加载域名访问控制列表
//
// 参数:
//   - filePath: 包含域名列表的文件路径（每行一个域名，# 注释）
//   - listType: 列表类型（黑名单或白名单）
//   - includeSubdomains: 是否包含子域名匹配
//
// 返回:
//   - error: 文件读取或解析错误
//
// 此方法会覆盖之前设置的任何域名访问控制列表。文件格式与 SetIPACLFromFile 相同。
//
// 示例:
//
//	err := manager.SetDomainACLFromFile("./domain_blacklist.txt", types.Blacklist, true)
func (m *Manager) SetDomainACLFromFile(filePath string, listType types.ListType, includeSubdomains bool) error {
	newACL, err := domain.NewDomainACLFromFile(filePath, listType, includeSubdomains)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.acls[KindDomain] = newACL
	return nil
}

// SaveDomainACLToFile 将当前域名访问控制列表保存到文件
//
// 参数:
//   - filePath: 要保存的文件路径
//   - overwrite: 是否覆盖现有文件
//
// 返回:
//   - error: types.ErrNoACL / config.ErrFileExists / config.ErrFilePermission
func (m *Manager) SaveDomainACLToFile(filePath string, overwrite bool) error {
	domA := m.domainACL()
	if domA == nil {
		return types.ErrNoACL
	}
	return domA.SaveToFile(filePath, overwrite)
}

// AddDomainFromFile 从文件添加域名到现有域名访问控制列表
//
// 参数:
//   - filePath: 包含要添加域名的文件路径
//
// 返回:
//   - error: types.ErrNoACL / 文件读取或解析错误
//
// 与 SetDomainACLFromFile 不同，此方法不替换现有 ACL，而是向其追加内容。
func (m *Manager) AddDomainFromFile(filePath string) error {
	domA := m.domainACL()
	if domA == nil {
		return types.ErrNoACL
	}
	return domA.AddFromFile(filePath)
}

// AddIPFromFile 从文件添加IP或CIDR到IP访问控制列表
//
// 参数:
//   - filePath: 包含要添加的IP的文件路径
//     例如: "/path/to/additional_ips.txt", "./more_ips.txt"
//
// 返回:
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置IP ACL
//   - config.ErrFileNotFound: 如果文件不存在
//   - ip.ErrInvalidIP/ip.ErrInvalidCIDR: 如果文件中包含无效IP
//
// 与SetIPACLFromFile不同，此方法不会替换现有ACL，而是向其添加内容。
// 文件格式与SetIPACLFromFile相同。
//
// 示例:
//
//	// 向现有IP列表添加更多IP
//	err := manager.AddIPFromFile("./additional_ips.txt")
//	if err != nil {
//	    if errors.Is(err, types.ErrNoACL) {
//	        log.Println("请先设置IP ACL")
//	    } else {
//	        log.Printf("添加IP失败: %v", err)
//	    }
//	}
func (m *Manager) AddIPFromFile(filePath string) error {
	ipA := m.ipACL()
	if ipA == nil {
		return types.ErrNoACL
	}
	return ipA.AddFromFile(filePath)
}

// SetIPACLWithDefaults 设置IP访问控制列表，并包含预定义的安全IP集合
//
// 参数:
//   - ipRanges: 自定义的IP或CIDR列表
//     例如: []string{"203.0.113.0/24", "198.51.100.1"}
//   - listType: 列表类型（黑名单或白名单）
//     可用值: types.Blacklist（黑名单）或 types.Whitelist（白名单）
//   - predefinedSets: 要包含的预定义IP集合
//     例如: []ip.PredefinedSet{ip.PrivateNetworks, ip.CloudMetadata}
//   - allowDefaultSets: 预定义集合的处理方式
//   - 对于黑名单，false表示阻止这些IP（推荐用于安全防护）
//   - 对于白名单，true表示允许这些IP
//
// 返回:
//   - error: 创建ACL时的错误
//
// 此方法适合用于快速创建具有安全防护的ACL，特别是在创建防止SSRF等攻击的黑名单时。
//
// 示例:
//
//	// 创建防SSRF的黑名单，阻止内网和云元数据访问
//	err := manager.SetIPACLWithDefaults(
//	    []string{"203.0.113.0/24"}, // 自定义阻止的IP范围
//	    types.Blacklist,
//	    []ip.PredefinedSet{
//	        ip.PrivateNetworks,  // 内网地址
//	        ip.CloudMetadata,    // 云服务商元数据地址
//	    },
//	    false, // 将这些预定义集合作为黑名单
//	)
//
//	// 创建针对特定服务的白名单，允许公共DNS服务
//	err := manager.SetIPACLWithDefaults(
//	    []string{"203.0.113.5"}, // 自定义允许的IP
//	    types.Whitelist,
//	    []ip.PredefinedSet{
//	        ip.PublicDNS, // 公共DNS服务
//	    },
//	    true, // 将这些预定义集合作为白名单
//	)
func (m *Manager) SetIPACLWithDefaults(ipRanges []string, listType types.ListType, predefinedSets []ip.PredefinedSet, allowDefaultSets bool) error {
	newACL, err := ip.NewIPACLWithDefaults(ipRanges, listType, predefinedSets, allowDefaultSets)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.acls[KindIP] = newACL
	return nil
}

// AddIP 向IP访问控制列表添加一个或多个IP或CIDR
//
// 参数:
//   - ipRanges: 要添加的一个或多个IP或CIDR
//     例如: "192.168.1.1", "10.0.0.0/8", "2001:db8::/32"
//
// 返回:
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置IP ACL
//   - ip.ErrInvalidIP: 如果提供了无效IP
//   - ip.ErrInvalidCIDR: 如果提供了无效CIDR
//
// 此方法可用于在不替换整个ACL的情况下添加单个或多个IP范围。
//
// 示例:
//
//	// 添加单个IP
//	err := manager.AddIP("192.168.1.5")
//
//	// 添加多个IP和CIDR
//	err := manager.AddIP("8.8.8.8", "8.8.4.4", "192.168.0.0/16")
//	if err != nil {
//	    if errors.Is(err, types.ErrNoACL) {
//	        log.Println("请先设置IP ACL")
//	    } else {
//	        log.Printf("添加IP失败: %v", err)
//	    }
//	}
func (m *Manager) AddIP(ipRanges ...string) error {
	ipA := m.ipACL()
	if ipA == nil {
		return types.ErrNoACL
	}
	return ipA.Add(ipRanges...)
}

// RemoveIP 从IP访问控制列表移除一个或多个IP或CIDR
//
// 参数:
//   - ipRanges: 要移除的一个或多个IP或CIDR
//     例如: "192.168.1.1", "10.0.0.0/8", "2001:db8::/32"
//
// 返回:
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置IP ACL
//   - ip.ErrIPNotFound: 如果要移除的IP不在列表中
//
// 示例:
//
//	// 移除单个IP
//	err := manager.RemoveIP("192.168.1.5")
//
//	// 移除多个IP和CIDR
//	err := manager.RemoveIP("8.8.8.8", "10.0.0.0/8")
//	if err != nil {
//	    if errors.Is(err, types.ErrNoACL) {
//	        log.Println("未设置IP ACL")
//	    } else if errors.Is(err, ip.ErrIPNotFound) {
//	        log.Println("要移除的IP不在列表中")
//	    } else {
//	        log.Printf("移除IP失败: %v", err)
//	    }
//	}
func (m *Manager) RemoveIP(ipRanges ...string) error {
	ipA := m.ipACL()
	if ipA == nil {
		return types.ErrNoACL
	}
	return ipA.Remove(ipRanges...)
}

// AddPredefinedIPSet 向现有的IP访问控制列表添加一个预定义IP集合
// 如果当前没有设置IP访问控制列表，则会返回错误
//
// 参数:
//   - setName: 预定义集合名称
//     可用值: ip.PrivateNetworks, ip.LoopbackNetworks, ip.CloudMetadata等
//   - allowSet: 预定义集合的处理方式
//   - 对于黑名单，false表示阻止这些IP（添加到黑名单）
//   - 对于白名单，true表示允许这些IP（添加到白名单）
//
// 返回:
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置IP ACL
//   - ip.ErrInvalidPredefinedSet: 如果提供了无效的预定义集合名称
//
// 预定义集合包含常见的特殊网络，如内网地址、云元数据地址等，
// 可用于快速增强ACL的安全性。
//
// 示例:
//
//	// 向黑名单添加内网地址（阻止内网访问）
//	err := manager.AddPredefinedIPSet(ip.PrivateNetworks, false)
//
//	// 向白名单添加公共DNS服务器（允许访问公共DNS）
//	err := manager.AddPredefinedIPSet(ip.PublicDNS, true)
//
//	if err != nil {
//	    log.Printf("添加预定义集合失败: %v", err)
//	}
func (m *Manager) AddPredefinedIPSet(setName ip.PredefinedSet, allowSet bool) error {
	ipA := m.ipACL()
	if ipA == nil {
		return types.ErrNoACL
	}
	return ipA.AddPredefinedSet(setName, allowSet)
}

// AddPredefinedDomainSet 向现有的域名访问控制列表添加一个预定义域名集合
// 如果当前没有设置域名访问控制列表，则会返回错误
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
//   - types.ErrNoACL: 如果未设置域名 ACL
//   - domain.ErrInvalidPredefinedSet: 如果提供了无效的预定义集合名称
//
// 示例:
//
//	// 向黑名单添加短链域名（阻止访问）
//	err := manager.AddPredefinedDomainSet(domain.Shorteners, false)
//	// 向白名单添加可信 CDN 域名（允许访问）
//	err := manager.AddPredefinedDomainSet(domain.TrustedCDN, true)
func (m *Manager) AddPredefinedDomainSet(setName domain.PredefinedSet, allowSet bool) error {
	domA := m.domainACL()
	if domA == nil {
		return types.ErrNoACL
	}
	return domA.AddPredefinedSet(setName, allowSet)
}

// AddAllSpecialNetworks 添加所有特殊网络到黑名单（用于安全防护）
// 这是一个简便方法，用于快速增强安全性
//
// 返回:
//   - error: 添加过程中的错误
//
// 此方法等同于调用 AddPredefinedIPSet(ip.AllSpecialNetworks, false)
// 它会将所有特殊网络（内网、回环、链路本地、云元数据等）添加到黑名单中，
// 这在防止SSRF等安全威胁时非常有用。
//
// 示例:
//
//	// 快速增强安全性，阻止对所有特殊网络的访问
//	if err := manager.AddAllSpecialNetworks(); err != nil {
//	    log.Printf("添加特殊网络到黑名单失败: %v", err)
//	}
func (m *Manager) AddAllSpecialNetworks() error {
	return m.AddPredefinedIPSet(ip.AllSpecialNetworks, false)
}

// CheckDomain 检查域名是否允许访问
//
// 参数:
//   - domain: 要检查的域名
//     例如: "example.com", "sub.domain.com", "https://www.example.org/path"
//
// 返回:
//   - types.Permission: 访问权限结果
//   - types.Allowed: 允许访问
//   - types.Denied: 拒绝访问
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置域名ACL
//   - domain.ErrInvalidDomain: 如果提供了无效域名
//
// 域名会自动标准化（移除协议、www前缀、端口号等）。
// 如果在创建DomainACL时设置了includeSubdomains=true，
// 则子域名也会被匹配。
//
// 示例:
//
//	// 检查域名是否允许访问
//	permission, err := manager.CheckDomain("sub.example.com")
//	if err != nil {
//	    if errors.Is(err, types.ErrNoACL) {
//	        log.Println("未设置域名ACL")
//	    } else {
//	        log.Printf("检查域名错误: %v", err)
//	    }
//	} else if permission == types.Allowed {
//	    log.Println("允许访问此域名")
//	} else {
//	    log.Println("拒绝访问此域名")
//	}
func (m *Manager) CheckDomain(domain string) (types.Permission, error) {
	domA := m.domainACL()
	if domA == nil {
		return types.Denied, types.ErrNoACL
	}
	return domA.Check(domain)
}

// CheckIP 检查IP是否允许访问
//
// 参数:
//   - ip: 要检查的IP地址
//     例如: "192.168.1.1", "8.8.8.8", "2001:db8::1"
//
// 返回:
//   - types.Permission: 访问权限结果
//   - types.Allowed: 允许访问
//   - types.Denied: 拒绝访问
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置IP ACL
//   - ip.ErrInvalidIP: 如果提供了无效IP
//
// 支持IPv4和IPv6地址，不支持CIDR格式（仅检查单个IP）。
//
// 示例:
//
//	// 检查IP是否允许访问
//	permission, err := manager.CheckIP("8.8.8.8")
//	if err != nil {
//	    if errors.Is(err, types.ErrNoACL) {
//	        log.Println("未设置IP ACL")
//	    } else if errors.Is(err, ip.ErrInvalidIP) {
//	        log.Println("无效的IP格式")
//	    } else {
//	        log.Printf("检查IP错误: %v", err)
//	    }
//	} else if permission == types.Allowed {
//	    log.Println("允许访问此IP")
//	} else {
//	    log.Println("拒绝访问此IP")
//	}
func (m *Manager) CheckIP(ip string) (types.Permission, error) {
	ipA := m.ipACL()
	if ipA == nil {
		return types.Denied, types.ErrNoACL
	}
	return ipA.Check(ip)
}

// LookupIP 返回包含该 IP 的最长前缀匹配 CIDR 规则串
//
// 参数:
//   - ip: 要查询的IP地址
//     例如: "192.168.1.1", "8.8.8.8", "2001:db8::1"
//
// 返回:
//   - string: 命中的 CIDR 规则串，无匹配时为 ""
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置IP ACL
//   - ip.ErrInvalidIP: 如果提供了无效IP
//
// 与 CheckIP 不同，此方法不判定权限，而是返回最长前缀匹配的具体 CIDR，
// 便于规则反查、审计与诊断。
//
// 示例:
//
//	manager.SetIPACL([]string{"10.0.0.0/8", "10.1.0.0/16"}, types.Blacklist)
//	cidr, _ := manager.LookupIP("10.1.2.3") // 返回 "10.1.0.0/16"
//	cidr, _ = manager.LookupIP("10.2.0.1")  // 返回 "10.0.0.0/8"
func (m *Manager) LookupIP(ip string) (string, error) {
	ipAcl := m.ipACL()
	if ipAcl == nil {
		return "", types.ErrNoACL
	}
	return ipAcl.Lookup(ip)
}

// GetIPRanges 获取当前IP访问控制列表中的所有IP范围
//
// 返回:
//   - []string: IP范围列表，每个元素是一个IP或CIDR
//     例如: []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
//
// 如果未设置IP ACL，则返回nil。
//
// 此方法可用于查看当前ACL中的所有IP规则，便于调试或显示。
//
// 示例:
//
//	// 获取所有IP范围
//	ranges := manager.GetIPRanges()
//	if ranges == nil {
//	    log.Println("未设置IP ACL")
//	} else {
//	    log.Printf("当前有 %d 个IP范围规则:", len(ranges))
//	    for _, r := range ranges {
//	        log.Println(" -", r)
//	    }
//	}
func (m *Manager) GetIPRanges() []string {
	ipA := m.ipACL()
	if ipA == nil {
		return nil
	}
	return ipA.GetIPRanges()
}

// GetIPACLType 获取当前IP访问控制列表的类型（黑名单或白名单）
//
// 返回:
//   - types.ListType: 列表类型
//   - types.Blacklist: 黑名单模式
//   - types.Whitelist: 白名单模式
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置IP ACL
//
// 此方法可用于确定当前IP ACL的工作模式。
//
// 示例:
//
//	// 获取IP ACL类型
//	listType, err := manager.GetIPACLType()
//	if err != nil {
//	    if errors.Is(err, types.ErrNoACL) {
//	        log.Println("未设置IP ACL")
//	    }
//	} else if listType == types.Blacklist {
//	    log.Println("当前IP ACL为黑名单模式")
//	} else {
//	    log.Println("当前IP ACL为白名单模式")
//	}
func (m *Manager) GetIPACLType() (types.ListType, error) {
	ipA := m.ipACL()
	if ipA == nil {
		return 0, types.ErrNoACL
	}
	return ipA.GetListType(), nil
}

// AddDomain 向域名访问控制列表添加一个或多个域名
//
// 参数:
//   - domains: 要添加的一个或多个域名
//     例如: "example.com", "mydomain.org", "sub.example.net"
//
// 返回:
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置域名ACL
//
// 域名会自动标准化（移除协议、www前缀、端口号等）。
// 空域名或格式无效的域名会被忽略。
//
// 示例:
//
//	// 添加单个域名
//	err := manager.AddDomain("example.com")
//
//	// 添加多个域名
//	err := manager.AddDomain("domain1.com", "domain2.org", "domain3.net")
//	if err != nil {
//	    if errors.Is(err, types.ErrNoACL) {
//	        log.Println("请先设置域名ACL")
//	    } else {
//	        log.Printf("添加域名失败: %v", err)
//	    }
//	}
func (m *Manager) AddDomain(domains ...string) error {
	domA := m.domainACL()
	if domA == nil {
		return types.ErrNoACL
	}
	return domA.Add(domains...)
}

// RemoveDomain 从域名访问控制列表移除一个或多个域名
//
// 参数:
//   - domains: 要移除的一个或多个域名
//     例如: "example.com", "mydomain.org", "sub.example.net"
//
// 返回:
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置域名ACL
//   - domain.ErrDomainNotFound: 如果要移除的域名不在列表中
//
// 域名会自动标准化（移除协议、www前缀、端口号等）。
// 如果任何一个域名不在列表中，将返回ErrDomainNotFound错误，
// 但已找到的域名仍会被移除。
//
// 示例:
//
//	// 移除单个域名
//	err := manager.RemoveDomain("example.com")
//
//	// 移除多个域名
//	err := manager.RemoveDomain("domain1.com", "domain2.org")
//	if err != nil {
//	    if errors.Is(err, types.ErrNoACL) {
//	        log.Println("未设置域名ACL")
//	    } else if errors.Is(err, domain.ErrDomainNotFound) {
//	        log.Println("一个或多个域名不在列表中")
//	    } else {
//	        log.Printf("移除域名失败: %v", err)
//	    }
//	}
func (m *Manager) RemoveDomain(domains ...string) error {
	domA := m.domainACL()
	if domA == nil {
		return types.ErrNoACL
	}
	return domA.Remove(domains...)
}

// GetDomains 获取当前域名访问控制列表中的所有域名
//
// 返回:
//   - []string: 域名列表
//     例如: []string{"example.com", "mydomain.org", "sub.example.net"}
//
// 如果未设置域名ACL，则返回nil。
//
// 示例:
//
//	// 获取所有域名
//	domains := manager.GetDomains()
//	if domains == nil {
//	    log.Println("未设置域名ACL")
//	} else {
//	    log.Printf("当前有 %d 个域名规则:", len(domains))
//	    for _, d := range domains {
//	        log.Println(" -", d)
//	    }
//	}
func (m *Manager) GetDomains() []string {
	domA := m.domainACL()
	if domA == nil {
		return nil
	}
	return domA.GetDomains()
}

// GetDomainACLType 获取当前域名访问控制列表的类型（黑名单或白名单）
//
// 返回:
//   - types.ListType: 列表类型
//   - types.Blacklist: 黑名单模式
//   - types.Whitelist: 白名单模式
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置域名ACL
//
// 此方法可用于确定当前域名ACL的工作模式。
//
// 示例:
//
//	// 获取域名ACL类型
//	listType, err := manager.GetDomainACLType()
//	if err != nil {
//	    if errors.Is(err, types.ErrNoACL) {
//	        log.Println("未设置域名ACL")
//	    }
//	} else if listType == types.Blacklist {
//	    log.Println("当前域名ACL为黑名单模式")
//	} else {
//	    log.Println("当前域名ACL为白名单模式")
//	}
func (m *Manager) GetDomainACLType() (types.ListType, error) {
	domA := m.domainACL()
	if domA == nil {
		return 0, types.ErrNoACL
	}
	return domA.GetListType(), nil
}

// Reset 重置所有访问控制列表
//
// 此方法会清除所有域名和IP访问控制设置，使管理器恢复到初始状态。
// 调用此方法后，CheckDomain和CheckIP等方法将返回ErrNoACL错误，
// 直到重新设置相应的ACL。
//
// 示例:
//
//	// 重置所有ACL设置
//	manager.Reset()
//
//	// 验证已重置
//	_, err := manager.CheckDomain("example.com")
//	if errors.Is(err, types.ErrNoACL) {
//	    log.Println("域名ACL已成功重置")
//	}
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.acls = make(map[string]types.MutableACL)
}
