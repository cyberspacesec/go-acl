# 欢迎使用 acl-skills

**acl-skills** 是一个强大、高效、易用的 Go 访问控制列表（ACL）库，零外部依赖，专注于保护您的应用免受未授权访问。

## 为什么选择 acl-skills？

```mermaid
mindmap
  root((acl-skills))
    域名匹配
      精确匹配
      通配子域
      前缀匹配
      宽松后缀
      正则匹配
    IP 匹配
      IPv4 / IPv6
      CIDR 网段
      IP 区间
      Zone ID 剥离
    安全设计
      白名单 fail-closed
      并发安全
      预定义集合
      零外部依赖
    部署集成
      HTTP 中间件
      JSON Policy
      文件持久化
      自定义 ACL
```

## 核心特性

| 特性 | 说明 |
|------|------|
| 🚀 **高性能** | IP 匹配基于前缀树（Trie），O(prefixLen) 与规则数无关；域名精确匹配 O(1) |
| 🔒 **安全优先** | 白名单模式 fail-closed，空值/空输入默认拒绝 |
| 🌐 **双维度** | 域名 5 种匹配维度 + IP 全语法（v4/v6/CIDR/区间） |
| 📦 **零依赖** | 纯 Go 标准库实现，无外部依赖，`go get` 即用 |
| 🧵 **并发安全** | 内置 `sync.RWMutex`，不同 ACL 类型互不阻塞 |
| ⚙️ **灵活集成** | HTTP 中间件、JSON Policy 配置、文件持久化、自定义 ACL 注册 |

## 架构概览

```mermaid
flowchart TB
    subgraph 用户层
        APP[应用代码]
        HTTP[HTTP 请求]
        JSON[JSON 策略文件]
    end

    subgraph 核心层
        M[acl.Manager]
        AP[ApplyPolicy]
        MW[HTTP Middleware]
    end

    subgraph ACL 实现
        D[domain.DomainACL]
        I[ip.IPACL]
        C[自定义 ACL]
    end

    subgraph 存储层
        F[文件系统]
        MEM[内存]
    end

    APP -->|RegisterACL| M
    APP -->|SetDomainACL| M
    APP -->|SetIPACL| M
    HTTP --> MW
    JSON --> AP --> M
    M --> D
    M --> I
    M --> C
    D --> MEM
    I --> MEM
    M -->|SaveToFile| F
    F -->|SetFromFile| M
```

## 快速示例

```go
package main

import (
    "fmt"
    "github.com/cyberspacesec/acl-skills/pkg/acl"
    "github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
    m := acl.NewManager()

    // 阻止内网 IP
    m.SetIPACL([]string{"10.0.0.0/8", "192.168.0.0/16"}, types.Blacklist)
    // 阻止恶意域名
    m.SetDomainACL([]string{"evil.example.com", "*.malware.test"}, types.Blacklist, true)

    // 检查
    fmt.Println(m.CheckIP("10.0.0.1"))    // Denied
    fmt.Println(m.CheckIP("8.8.8.8"))      // Allowed
    fmt.Println(m.CheckDomain("evil.example.com")) // Denied
}
```

## 下一步

- [快速开始：安装](quickstart/installation.md) — 安装与导入
- [核心架构](architecture.md) — 深入了解设计
- [GitHub 仓库](https://github.com/cyberspacesec/acl-skills) — 源码与 issues