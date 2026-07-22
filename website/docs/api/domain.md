# domain 包 — 域名 ACL

## DomainACL

```go
type DomainACL struct { ... }
```

域名访问控制列表，支持五种匹配维度。

## 构造函数

```go
func NewDomainACL(domains []string, listType types.ListType, includeSubdomains bool) *DomainACL
func NewDomainACLStrict(domains []string, listType types.ListType, includeSubdomains bool) (*DomainACL, error)
func NewDomainACLWithDefaults(domains []string, listType types.ListType, includeSubdomains bool, predefinedSets []PredefinedSet, allowDefaultSets bool) (*DomainACL, error)
func NewDomainACLFromFile(filePath string, listType types.ListType, includeSubdomains bool) (*DomainACL, error)
```

`NewDomainACL` 静默忽略无效域名；`NewDomainACLStrict` 返回错误。

## 增删查

```go
func (d *DomainACL) Add(domains ...string) error
func (d *DomainACL) Remove(domains ...string) error
func (d *DomainACL) Check(domain string) (types.Permission, error)
func (d *DomainACL) GetDomains() []string
func (d *DomainACL) GetRules() []string
func (d *DomainACL) GetListType() types.ListType
```

## 预定义集合

```go
func (d *DomainACL) AddPredefinedSet(setName PredefinedSet, allowSet bool) error
```

## 文件操作

```go
func (d *DomainACL) SaveToFile(filePath string, overwrite bool) error
func (d *DomainACL) AddFromFile(filePath string) error
```

## 预定义集合常量

```go
type PredefinedSet string

const Shorteners       PredefinedSet = "Shorteners"
const PublicFileSharing  PredefinedSet = "PublicFileSharing"
const CodeHosting        PredefinedSet = "CodeHosting"
const SocialMedia        PredefinedSet = "SocialMedia"
const WebmailProviders   PredefinedSet = "WebmailProviders"
const TorExitNodes       PredefinedSet = "TorExitNodes"
const DisposableEmail    PredefinedSet = "DisposableEmail"
const TrustedCDN         PredefinedSet = "TrustedCDN"
const AllMaliciousDomains PredefinedSet = "AllMaliciousDomains"
```

## 哨兵错误

```go
var ErrInvalidPredefinedSet = errors.New("无效的预定义域名集合")
var ErrInvalidDomain = errors.New("无效的域名格式")
```