# 安装

## 前置条件

- Go 1.18 或更高版本
- 无需外部依赖，仅使用 Go 标准库

## 安装

```bash
go get github.com/cyberspacesec/acl-skills
```

导入：

```go
import (
    "github.com/cyberspacesec/acl-skills/pkg/acl"
    "github.com/cyberspacesec/acl-skills/pkg/types"
    "github.com/cyberspacesec/acl-skills/pkg/domain"
    "github.com/cyberspacesec/acl-skills/pkg/ip"
    "github.com/cyberspacesec/acl-skills/pkg/middleware"
    "github.com/cyberspacesec/acl-skills/pkg/config"
)
```

## 验证安装

```go
package main

import (
    "fmt"
    "github.com/cyberspacesec/acl-skills/pkg/ip"
    "github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
    acl, err := ip.NewIPACL([]string{"10.0.0.0/8"}, types.Blacklist)
    if err != nil {
        panic(err)
    }
    perm, _ := acl.Check("10.0.0.1")
    fmt.Println(perm) // Denied
}
```

## 最小 Go 版本

```mermaid
gantt
    title 版本兼容性
    dateFormat  YYYY-MM
    axisFormat  %Y-%m

    section Go 版本
    Go 1.18 : 2022-02, 2024-12
    Go 1.19 : 2022-08, 2025-01
    Go 1.20 : 2023-02, 2025-06
    Go 1.21 : 2023-08, 2026-08
    Go 1.22 : 2024-02, 2026-12
    Go 1.23 : 2024-08, 2027-02
    Go 1.24 : 2025-02, 2027-06

    section acl-skills
    v1.0.0 支持 1.18+ : 2026-07, 2027-12
```