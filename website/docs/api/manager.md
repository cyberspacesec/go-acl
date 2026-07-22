# acl 包 — 统一 Manager

## NewManager

```go
func NewManager() *Manager
```

创建空的 Manager 实例。

## 注册与自定义 ACL

```go
func (m *Manager) RegisterACL(kind string, a types.MutableACL) error
func (m *Manager) UnregisterACL(kind string)
func (m *Manager) GetACL(kind string) (types.MutableACL, bool)
func (m *Manager) RegisteredKinds() []string
```

`RegisterACL` 注册自定义 ACL 到指定 kind，kind 已占用返回 `ErrACLAlreadyRegistered`。同一实例可注册到多个 kind。

## 统一入口

```go
func (m *Manager) CheckKind(kind, value string) (types.Permission, error)
func (m *Manager) AddRule(kind string, rules ...string) error
func (m *Manager) RemoveRule(kind string, rules ...string) error
func (m *Manager) GetRules(kind string) []string
func (m *Manager) GetACLType(kind string) (types.ListType, error)
```

通过 kind 字符串委托给任意 ACL 实例，适用于自定义 ACL 的统一管理。

## 域名操作

```go
func (m *Manager) SetDomainACL(domains []string, listType types.ListType, includeSubdomains bool)
func (m *Manager) SetDomainACLStrict(domains []string, listType types.ListType, includeSubdomains bool) error
func (m *Manager) SetDomainACLWithDefaults(domains []string, listType types.ListType, includeSubdomains bool, predefinedSets []domain.PredefinedSet, allowDefaultSets bool) error
func (m *Manager) SetDomainACLFromFile(filePath string, listType types.ListType, includeSubdomains bool) error
func (m *Manager) SaveDomainACLToFile(filePath string, overwrite bool) error
func (m *Manager) AddDomain(domains ...string) error
func (m *Manager) RemoveDomain(domains ...string) error
func (m *Manager) AddDomainFromFile(filePath string) error
func (m *Manager) AddPredefinedDomainSet(setName domain.PredefinedSet, allowSet bool) error
func (m *Manager) CheckDomain(domain string) (types.Permission, error)
func (m *Manager) GetDomains() []string
func (m *Manager) GetDomainACLType() (types.ListType, error)
```

## IP 操作

```go
func (m *Manager) SetIPACL(ipRanges []string, listType types.ListType) error
func (m *Manager) SetIPACLWithDefaults(ipRanges []string, listType types.ListType, predefinedSets []ip.PredefinedSet, allowDefaultSets bool) error
func (m *Manager) SetIPACLFromFile(filePath string, listType types.ListType) error
func (m *Manager) SaveIPACLToFile(filePath string, overwrite bool) error
func (m *Manager) AddIP(ipRanges ...string) error
func (m *Manager) RemoveIP(ipRanges ...string) error
func (m *Manager) AddIPFromFile(filePath string) error
func (m *Manager) AddPredefinedIPSet(setName ip.PredefinedSet, allowSet bool) error
func (m *Manager) AddAllSpecialNetworks() error
func (m *Manager) CheckIP(ip string) (types.Permission, error)
func (m *Manager) LookupIP(ip string) (string, error)
func (m *Manager) GetIPRanges() []string
func (m *Manager) GetIPACLType() (types.ListType, error)
```

## 策略与重置

```go
func (m *Manager) ApplyPolicy(p *config.Policy) error
func (m *Manager) Reset()
```

| 方法 | 说明 |
|------|------|
| `ApplyPolicy` | 注入 JSON Policy，失败不半应用 |
| `Reset` | 清空所有 ACL，恢复初始状态 |