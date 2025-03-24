package acl

import (
	"sync"

	"github.com/cyberspacesec/go-acl/pkg/types"
	"github.com/cyberspacesec/go-acl/pkg/domain"
	"github.com/cyberspacesec/go-acl/pkg/ip"
)

// Manager 是访问控制列表管理器，整合了域名和IP访问控制
type Manager struct {
	mu        sync.RWMutex
	domainAcl *domain.DomainAcl
	ipAcl     *ip.IPAcl
}

// NewManager 创建一个新的ACL管理器
func NewManager() *Manager {
	return &Manager{}
}

// SetDomainAcl 设置域名访问控制列表
func (m *Manager) SetDomainAcl(domains []string, listType types.ListType, includeSubdomains bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.domainAcl = domain.NewDomainAcl(domains, listType, includeSubdomains)
}

// SetIPAcl 设置IP访问控制列表
func (m *Manager) SetIPAcl(ipRanges []string, listType types.ListType) error {
	acl, err := ip.NewIPAcl(ipRanges, listType)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAcl = acl
	return nil
}

// SetIPAclFromFile 从文件加载IP访问控制列表
func (m *Manager) SetIPAclFromFile(filePath string, listType types.ListType) error {
	acl, err := ip.NewIPAclFromFile(filePath, listType)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAcl = acl
	return nil
}

// SaveIPAclToFile 将当前IP访问控制列表保存到文件
// 如果文件已存在，overwrite参数决定是否覆盖文件
func (m *Manager) SaveIPAclToFile(filePath string, overwrite bool) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ipAcl == nil {
		return types.ErrNoAcl
	}

	return m.ipAcl.SaveToFile(filePath, overwrite)
}

// SaveIPAclToFileWithOverwrite 兼容旧版API，默认覆盖已存在的文件
// 已废弃：请改用 SaveIPAclToFile
func (m *Manager) SaveIPAclToFileWithOverwrite(filePath string) error {
	return m.SaveIPAclToFile(filePath, true)
}

// AddIPFromFile 从文件添加IP或CIDR到IP访问控制列表
func (m *Manager) AddIPFromFile(filePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ipAcl == nil {
		return types.ErrNoAcl
	}

	return m.ipAcl.AddFromFile(filePath)
}

// SetIPAclWithDefaults 设置IP访问控制列表，并包含预定义的安全IP集合
func (m *Manager) SetIPAclWithDefaults(ipRanges []string, listType types.ListType, predefinedSets []ip.PredefinedSet, allowDefaultSets bool) error {
	acl, err := ip.NewIPAclWithDefaults(ipRanges, listType, predefinedSets, allowDefaultSets)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAcl = acl
	return nil
}

// AddIP 向IP访问控制列表添加一个或多个IP或CIDR
func (m *Manager) AddIP(ipRanges ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ipAcl == nil {
		return types.ErrNoAcl
	}

	return m.ipAcl.Add(ipRanges...)
}

// RemoveIP 从IP访问控制列表移除一个或多个IP或CIDR
func (m *Manager) RemoveIP(ipRanges ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ipAcl == nil {
		return types.ErrNoAcl
	}

	return m.ipAcl.Remove(ipRanges...)
}

// AddPredefinedIPSet 向现有的IP访问控制列表添加一个预定义IP集合
// 如果当前没有设置IP访问控制列表，则会返回错误
func (m *Manager) AddPredefinedIPSet(setName ip.PredefinedSet, allowSet bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ipAcl == nil {
		return types.ErrNoAcl
	}

	return m.ipAcl.AddPredefinedSet(setName, allowSet)
}

// AddAllSpecialNetworks 添加所有特殊网络到黑名单（用于安全防护）
// 这是一个简便方法，用于快速增强安全性
func (m *Manager) AddAllSpecialNetworks() error {
	return m.AddPredefinedIPSet(ip.AllSpecialNetworks, false)
}

// CheckDomain 检查域名是否允许访问
func (m *Manager) CheckDomain(domain string) (types.Permission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.domainAcl == nil {
		return types.Denied, types.ErrNoAcl
	}
	return m.domainAcl.Check(domain)
}

// CheckIP 检查IP是否允许访问
func (m *Manager) CheckIP(ip string) (types.Permission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ipAcl == nil {
		return types.Denied, types.ErrNoAcl
	}
	return m.ipAcl.Check(ip)
}

// GetIPRanges 获取当前IP访问控制列表中的所有IP范围
func (m *Manager) GetIPRanges() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ipAcl == nil {
		return nil
	}
	return m.ipAcl.GetIPRanges()
}

// GetIPAclType 获取当前IP访问控制列表的类型（黑名单或白名单）
func (m *Manager) GetIPAclType() (types.ListType, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ipAcl == nil {
		return 0, types.ErrNoAcl
	}
	return m.ipAcl.GetListType(), nil
}

// AddDomain 向域名访问控制列表添加一个或多个域名
func (m *Manager) AddDomain(domains ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.domainAcl == nil {
		return types.ErrNoAcl
	}

	m.domainAcl.Add(domains...)
	return nil
}

// RemoveDomain 从域名访问控制列表移除一个或多个域名
func (m *Manager) RemoveDomain(domains ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.domainAcl == nil {
		return types.ErrNoAcl
	}

	return m.domainAcl.Remove(domains...)
}

// GetDomains 获取当前域名访问控制列表中的所有域名
func (m *Manager) GetDomains() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.domainAcl == nil {
		return nil
	}
	return m.domainAcl.GetDomains()
}

// GetDomainAclType 获取当前域名访问控制列表的类型（黑名单或白名单）
func (m *Manager) GetDomainAclType() (types.ListType, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.domainAcl == nil {
		return 0, types.ErrNoAcl
	}
	return m.domainAcl.GetListType(), nil
}

// Reset 重置所有访问控制列表
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.domainAcl = nil
	m.ipAcl = nil
}
