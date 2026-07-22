# 核心架构

## 三层接口设计

acl-skills 围绕三层接口构建，从抽象到具体逐层扩展：

```mermaid
classDiagram
    class ACL {
        <<interface>>
        +Check(value string) Permission~error~
    }
    class ListTypeACL {
        <<interface>>
        +GetListType() ListType
    }
    class MutableACL {
        <<interface>>
        +Add(rules ...string) error
        +Remove(rules ...string) error
        +GetRules() []string
    }
    ACL <|-- ListTypeACL
    ListTypeACL <|-- MutableACL
    MutableACL <|.. DomainACL : 实现
    MutableACL <|.. IPACL : 实现
```

| 接口 | 职责 | 方法 |
|------|------|------|
| `ACL` | 最底层，仅判定权限 | `Check(value string) (Permission, error)` |
| `ListTypeACL` | 暴露黑/白名单模式 | 继承 `ACL` + `GetListType()` |
| `MutableACL` | 支持运行时增删查 | 继承 `ListTypeACL` + `Add`/`Remove`/`GetRules` |

## Manager 统一管理

```mermaid
flowchart LR
    subgraph Manager
        direction TB
        MU[ sync.RWMutex ]
        MAP[ acls map[string]MutableACL ]
    end

    subgraph 注册的ACL
        D[domain: DomainACL]
        I[ip: IPACL]
        C[custom: 自定义ACL]
    end

    MAP -->|"kind='domain'"| D
    MAP -->|"kind='ip'"| I
    MAP -->|"kind='custom'"| C

    D -->|自带锁| DL[domain.RWMutex]
    I -->|自带锁| IL[ip.RWMutex]
    C -->|自带锁| CL[custom.RWMutex]

    style MU fill:#f96,stroke:#333
    style D fill:#6cf,stroke:#333
    style I fill:#6cf,stroke:#333
    style C fill:#6cf,stroke:#333
```

**并发安全模型：**

- `Manager.mu` 仅保护 `kind → ACL` 映射的增删查（轻量锁）
- 各子 ACL 自带 `sync.RWMutex` 保护自身规则数据
- 查询不同 kind 的 ACL 互不阻塞
- 读操作（Check）只取读锁，多个读操作可并发

## 请求处理流程

```mermaid
sequenceDiagram
    participant Client as 客户端
    participant MW as HTTP Middleware
    participant M as acl.Manager
    participant D as DomainACL
    participant I as IPACL

    Client->>MW: HTTP 请求
    MW->>MW: 提取 Host 与 Client IP
    MW->>MW: 白名单下空 Host 或空 IP 直接拒绝

    alt CheckHost 启用
        MW->>M: CheckDomain(host)
        M->>D: Check(domain)
        D-->>M: Permission
        M-->>MW: 结果
    end

    alt CheckClientIP 启用
        MW->>M: CheckIP(ip)
        M->>I: Check(ip)
        I-->>M: Permission
        M-->>MW: 结果
    end

    alt 任一检查返回 Denied
        MW->>MW: 调用 Denied handler
        MW-->>Client: 403 Forbidden
    else 全部通过
        MW->>MW: 调用下一个 handler
        MW-->>Client: 200 OK
    end
```

## 域名匹配流程

```mermaid
flowchart TB
    Input[输入域名] --> Normalize[标准化域名]
    Normalize -->|小写化| Lower[全部转小写]
    Normalize -->|剥协议| Strip[移除 http:// https://]
    Normalize -->|剥端口| Port[移除端口号]
    Normalize -->|剥路径| Path[移除路径参数]

    Lower --> Match{匹配维度判断}

    Match -->|精确匹配| Exact[map O1 查找]
    Match -->|通配子域| Wildcard[HasSuffix .example.com]
    Match -->|前缀匹配| Prefix[HasPrefix api.]
    Match -->|宽松后缀| Loose[domain==suffix 或 HasSuffix .suffix]
    Match -->|正则匹配| Regex[regexp.MatchString]

    Exact --> Result{是否命中}
    Wildcard --> Result
    Prefix --> Result
    Loose --> Result
    Regex --> Result

    Result -->|命中| Decide{黑/白名单决策}
    Result -->|未命中| Decide

    Decide -->|黑名单命中 或 白名单未命中| Denied[返回 Denied]
    Decide -->|黑名单未命中 或 白名单命中| Allowed[返回 Allowed]
```

## IP 匹配流程

```mermaid
flowchart TB
    Input[输入 IP] --> Parse[解析 IP]
    Parse -->|net.ParseIP| Parsed{成功?}

    Parsed -->|否| Err[返回 ErrInvalidIP]
    Parsed -->|是| Classify{IPv4 / IPv6?}

    Classify -->|IPv4| V4[进入 v4 前缀树]
    Classify -->|IPv6| V6[进入 v6 前缀树]

    subgraph 前缀树匹配
        V4 --> Walk[按位遍历 32 位]
        V6 --> Walk2[按位遍历 128 位]
        Walk --> Found{找到最长前缀匹配?}
        Walk2 --> Found
    end

    Found -->|是| Matched[命中]
    Found -->|否| NotMatched[未命中]

    Matched --> Decide{黑/白名单决策}
    NotMatched --> Decide

    Decide -->|黑名单命中 或 白名单未命中| Denied[返回 Denied / 403]
    Decide -->|黑名单未命中 或 白名单命中| Allowed[返回 Allowed / 200]
```

## 数据流：JSON Policy 到运行时 ACL

```mermaid
flowchart LR
    JSON[JSON 策略文件] -->|LoadPolicyFromFile| Policy[config.Policy]
    Policy -->|ApplyPolicy| Manager[acl.Manager]

    subgraph Policy 结构
        D2[DomainPolicy]
        I2[IPPolicy]
    end

    Policy --> D2
    Policy --> I2

    D2 -->|Domains + File + PredefinedSets| SetDomain[SetDomainACL / SetDomainACLStrict]
    I2 -->|Ranges + File + PredefinedSets| SetIP[SetIPACL / SetIPACLWithDefaults]

    SetDomain --> DomainACL[domain.DomainACL]
    SetIP --> IPACL[ip.IPACL]

    DomainACL -->|Check| DomainResult{域名判定}
    IPACL -->|Check| IPResult{IP 判定}
```

## 六层包依赖

```mermaid
graph TB
    subgraph 用户层
        APP[应用代码]
        HTTP2[HTTP 请求]
        CONFIG[JSON 配置文件]
    end

    subgraph 集成层
        MW[ pkg/middleware ]
        POL[ pkg/acl.ApplyPolicy ]
    end

    subgraph 管理层
        MGR[ pkg/acl.Manager ]
    end

    subgraph 抽象层
        TYPES[ pkg/types ]
    end

    subgraph 实现层
        DOMAIN[ pkg/domain ]
        IP[ pkg/ip ]
    end

    subgraph 辅助层
        CFG[ pkg/config ]
        UTIL[ pkg/aclutil ]
    end

    APP --> MGR
    HTTP2 --> MW
    CONFIG --> CFG

    MW --> MGR
    POL --> MGR

    MGR --> TYPES
    MGR --> DOMAIN
    MGR --> IP

    DOMAIN --> TYPES
    IP --> TYPES
    DOMAIN --> UTIL
    IP --> UTIL
    CFG --> MGR

    style TYPES fill:#f9f,stroke:#333
    style MGR fill:#f96,stroke:#333
```

## 模块职责

| 包 | 职责 | 依赖 |
|----|------|------|
| `pkg/types` | 接口定义（ACL / ListTypeACL / MutableACL）、枚举、决策函数 | 无 |
| `pkg/acl` | Manager 统一入口、ApplyPolicy、自定义 ACL 注册 | types |
| `pkg/domain` | 域名 ACL 五维匹配 | types |
| `pkg/ip` | IP ACL 前缀树匹配 | types |
| `pkg/config` | JSON Policy 解析、文件 I/O | acl |
| `pkg/middleware` | HTTP 中间件 | acl |
| `pkg/aclutil` | 辅助函数（去重追加、移除匹配） | 无 |