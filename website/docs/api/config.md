# config 包 — JSON Policy 与文件 I/O

## Policy 结构

```go
type Policy struct {
    Domain *DomainPolicy `json:"domain,omitempty"`
    IP     *IPPolicy     `json:"ip,omitempty"`
}
```

任一为 nil 表示不配置该类型 ACL。

## DomainPolicy

```go
type DomainPolicy struct {
    Domains          []string `json:"domains"`
    ListType         string   `json:"listType"`
    IncludeSubdomains bool    `json:"includeSubdomains"`
    PredefinedSets   []string `json:"predefinedSets,omitempty"`
    AllowPredefined  bool     `json:"allowPredefined,omitempty"`
    File             string   `json:"file,omitempty"`
}
```

## IPPolicy

```go
type IPPolicy struct {
    Ranges          []string `json:"ranges"`
    ListType        string   `json:"listType"`
    PredefinedSets  []string `json:"predefinedSets,omitempty"`
    AllowPredefined bool     `json:"allowPredefined,omitempty"`
    File            string   `json:"file,omitempty"`
}
```

## 加载函数

```go
func LoadPolicyFromBytes(data []byte) (*Policy, error)
func LoadPolicyFromFile(filePath string) (*Policy, error)
```

## 文件 I/O

```go
func ReadIPACL(filePath string) ([]string, error)
func SaveIPACL(filePath string, ipList []string, overwrite bool) error
func SaveIPACLWithHeader(filePath string, ipList []string, header string, overwrite bool) error
```

## 哨兵错误

```go
var ErrFileNotFound   = errors.New("file not found")
var ErrEmptyFile      = errors.New("file is empty")
var ErrFileExists     = errors.New("file already exists")
var ErrFilePermission = errors.New("permission denied")
```