# ip 包 — IP ACL

## IPACL

```go
type IPACL struct { ... }
```

IP 访问控制列表，基于 IPv4/IPv6 双前缀树，O(prefixLen) 匹配。

## IPRange

```go
type IPRange struct {
    Original string     // 规范化后的 IP/CIDR 字符串
    IP       net.IP     // 解析后的 IP 地址
    IPNet    *net.IPNet // 网络范围
}
```

## 构造函数

```go
func NewIPACL(ipRanges []string, listType types.ListType) (*IPACL, error)
func NewIPACLWithDefaults(ipRanges []string, listType types.ListType, predefinedSets []PredefinedSet, allowDefaultSets bool) (*IPACL, error)
func NewIPACLFromFile(filePath string, listType types.ListType) (*IPACL, error)
```

## 增删查

```go
func (a *IPACL) Add(ipRanges ...string) error
func (a *IPACL) Remove(ipRanges ...string) error
func (a *IPACL) Check(ip string) (types.Permission, error)
func (a *IPACL) Lookup(ip string) (string, error)
func (a *IPACL) GetIPRanges() []string
func (a *IPACL) GetRules() []string
func (a *IPACL) GetListType() types.ListType
```

## 预定义集合

```go
func (a *IPACL) AddPredefinedSet(setName PredefinedSet, allowSet bool) error
```

## 文件操作

```go
func (a *IPACL) SaveToFile(filePath string, overwrite bool) error
func (a *IPACL) AddFromFile(filePath string) error
```

## 预定义集合常量

```go
type PredefinedSet string

const PrivateNetworks         PredefinedSet = "PrivateNetworks"
const LoopbackNetworks        PredefinedSet = "LoopbackNetworks"
const LinkLocalNetworks       PredefinedSet = "LinkLocalNetworks"
const CloudMetadata           PredefinedSet = "CloudMetadata"
const DockerNetworks          PredefinedSet = "DockerNetworks"
const PublicDNS               PredefinedSet = "PublicDNS"
const BroadcastAddresses      PredefinedSet = "BroadcastAddresses"
const MulticastAddresses      PredefinedSet = "MulticastAddresses"
const ReservedAddresses       PredefinedSet = "ReservedAddresses"
const TestNetworks            PredefinedSet = "TestNetworks"
const K8sServiceAddresses     PredefinedSet = "K8sServiceAddresses"
const CarrierGradeNAT         PredefinedSet = "CarrierGradeNAT"
const UniqueLocalAddresses    PredefinedSet = "UniqueLocalAddresses"
const AllSpecialNetworks      PredefinedSet = "AllSpecialNetworks"
```

## 哨兵错误

```go
var ErrInvalidIP            = errors.New("无效的IP地址格式")
var ErrInvalidCIDR          = errors.New("无效的CIDR格式")
var ErrInvalidIPRange       = errors.New("无效的IP范围区间格式")
var ErrIPNotFound           = errors.New("IP不在列表中")
var ErrInvalidPredefinedSet = errors.New("无效的预定义IP集合")
```