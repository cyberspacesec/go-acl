# JSON Policy 配置

## 策略文件结构

支持通过 JSON 文件定义完整的 ACL 策略，实现配置与代码分离：

```json
{
  "ip": {
    "ranges": ["10.0.0.0/8", "192.168.0.0/16"],
    "listType": "blacklist",
    "predefinedSets": ["PrivateNetworks", "CloudMetadata"],
    "allowPredefined": false,
    "file": "config/ip_blacklist.txt"
  },
  "domain": {
    "domains": ["evil.example.com", "*.malware.test"],
    "listType": "blacklist",
    "includeSubdomains": true,
    "predefinedSets": ["Shorteners", "DisposableEmail"],
    "allowPredefined": false,
    "file": "config/domain_blacklist.txt"
  }
}
```

## 应用策略

```go
package main

import (
    "fmt"
    "github.com/cyberspacesec/acl-skills/pkg/acl"
    "github.com/cyberspacesec/acl-skills/pkg/config"
)

func main() {
    m := acl.NewManager()

    // 从文件加载策略
    policy, err := config.LoadPolicyFromFile("security_policy.json")
    if err != nil {
        panic(err)
    }

    // 注入 Manager
    if err := m.ApplyPolicy(policy); err != nil {
        panic(err)
    }

    // 验证
    fmt.Println(m.CheckIP("10.0.0.1"))       // Denied
    fmt.Println(m.CheckDomain("bit.ly"))     // Denied（短链预定义集合）
}
```

## 策略处理流程

```mermaid
flowchart TB
    A[JSON 策略文件] -->|LoadPolicyFromFile| B[Policy 结构体]
    A2[原始 JSON 字节] -->|LoadPolicyFromBytes| B

    B --> C{Policy 解析}

    C --> D{有 Domain 段?}
    C --> E{有 IP 段?}

    D -->|无| F[跳过域名 ACL]
    D -->|有| G[解析 listType]
    G --> H{有 File?}
    H -->|是| I[读文件合并到 Domains]
    H -->|否| J[直接用 Domains]

    I --> K{有 PredefinedSets?}
    J --> K
    K -->|是| L[SetDomainACLWithDefaults]
    K -->|否| M[SetDomainACLStrict]

    E -->|无| N[跳过 IP ACL]
    E -->|有| O[解析 listType]
    O --> P{有 File?}
    P -->|是| Q[读文件合并到 Ranges]
    P -->|否| R[直接用 Ranges]

    Q --> S{有 PredefinedSets?}
    R --> S
    S -->|是| T[SetIPACLWithDefaults]
    S -->|否| U[SetIPACL]
```

## 文件格式

辅助文件（被 Policy 的 `file` 字段引用）每行一条规则，支持注释：

```text
# 内网 IP 黑名单（行注释）
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

# 云元数据
169.254.169.254/32  # 行内注释

# IPv6
fd00::/8
```

## 完整示例：安全策略

```json
{
  "ip": {
    "ranges": ["10.0.0.0/8", "192.168.0.0/16"],
    "listType": "blacklist",
    "predefinedSets": [
      "PrivateNetworks",
      "CloudMetadata",
      "DockerNetworks",
      "K8sServiceAddresses"
    ],
    "allowPredefined": false
  },
  "domain": {
    "domains": ["evil.example.com", "*.malware.test"],
    "listType": "blacklist",
    "includeSubdomains": true,
    "predefinedSets": [
      "Shorteners",
      "DisposableEmail",
      "TorExitNodes",
      "AllMaliciousDomains"
    ],
    "allowPredefined": false
  }
}
```

## 错误处理

```mermaid
flowchart TB
    A[ApplyPolicy] --> B{Policy 为 nil?}
    B -->|是| C[直接返回 nil]

    B -->|否| D{有 Domain 段?}
    D -->|是| E[解析 listType]
    E --> F{listType 有效?}
    F -->|否| G[返回错误，不注入]

    F -->|是| H{有 File 配置?}
    H -->|是| I[读文件]
    I --> J{文件存在?}
    J -->|否| K[返回错误，不注入]

    J -->|是| L{有预定义集合?}
    L -->|是| M[SetDomainACLWithDefaults]
    L -->|否| N[SetDomainACLStrict]
    M --> O{成功?}
    N --> O
    O -->|否| P[返回错误]

    O -->|是| Q{有 IP 段?}
    Q -->|是| R[...重复同上流程...]
    Q -->|否| S[返回 nil]
```

**失败语义**：任何子步骤出错都会在注入 Manager 之前返回，避免 Manager 被部分写入的半应用状态。