# 预定义集合

## 概述

预定义集合是内置的常见 IP 和域名范围，开箱即用，无需手动枚举：

```mermaid
flowchart LR
    subgraph 预定义集合
        PrivateNetworks
        CloudMetadata
        Shorteners
        DisposableEmail
        Malicious
    end

    PrivateNetworks -->|AddPredefinedSet| A[黑名单]
    Shorteners -->|AddPredefinedSet| A
    CloudMetadata -->|AddPredefinedSet| A

    A --> B[SSRF 防护]
    A --> C[内网保护]
    A --> D[安全加固]
```

## 域名预定义集合

```go
m.AddPredefinedDomainSet(domain.Shorteners, false)       // 阻止短链
m.AddPredefinedDomainSet(domain.DisposableEmail, false)  // 阻止一次性邮箱
m.AddPredefinedDomainSet(domain.AllMaliciousDomains, false) // 阻止所有恶意域名
```

### 完整清单

| 集合 | 常量 | 说明 | 典型用途 |
|------|------|------|---------|
| 短链 | `Shorteners` | bit.ly, t.co, tinyurl 等 | 防止 URL 重定向绕过 |
| 公开文件分享 | `PublicFileSharing` | dropbox, google drive 等 | 数据泄露防护 |
| 代码托管 | `CodeHosting` | github, gitlab, bitbucket 等 | 代码泄露防护 |
| 社交媒体 | `SocialMedia` | facebook, twitter, linkedin 等 | 访问控制 |
| 网页邮箱 | `WebmailProviders` | gmail, outlook, yahoo mail 等 | 数据泄露防护 |
| Tor 出口节点 | `TorExitNodes` | Tor 网络出口节点域名 | 匿名访问防护 |
| 一次性邮箱 | `DisposableEmail` | 10minutemail, guerrillamail 等 | 注册滥用防护 |
| 可信 CDN | `TrustedCDN` | cloudflare, akamai, fastly 等 | 白名单放行 |
| 全部恶意域名 | `AllMaliciousDomains` | 以上所有集合的并集 | 一站式安全加固 |

## IP 预定义集合

```go
m.AddPredefinedIPSet(ip.PrivateNetworks, false)     // 阻止私有网络
m.AddPredefinedIPSet(ip.CloudMetadata, false)        // 阻止云元数据
m.AddPredefinedIPSet(ip.AllSpecialNetworks, false)   // 阻止所有特殊网络
```

### 完整清单

```mermaid
mindmap
  IP 预定义集合
    私有网络
      10.0.0.0/8
      172.16.0.0/12
      192.168.0.0/16
    云元数据
      169.254.169.254/32
      fd00:ec2::/32
      fd00:ec4::/32
      fd00:ec6::/32
      fd00:ec8::/32
      fd00:eca::/32
      fd00:ecc::/32
      fd00:ece::/32
    Docker 网络
      127.0.0.0/8
      172.17.0.0/16
      172.18.0.0/16
      172.19.0.0/16
      172.20.0.0/14
    K8s 服务地址
      10.96.0.0/12
      10.244.0.0/16
      10.254.0.0/16
    公共 DNS
      8.8.8.8/32
      8.8.4.4/32
      1.1.1.1/32
      1.0.0.1/32
      208.67.222.222/32
      208.67.220.220/32
```

## 使用场景：SSRF 防护

```mermaid
sequenceDiagram
    participant App as 应用
    participant M as Manager
    participant IPACL
    participant User as 用户请求

    App->>M: AddPredefinedIPSet(PrivateNetworks, false)
    App->>M: AddPredefinedIPSet(CloudMetadata, false)
    App->>M: AddPredefinedIPSet(LoopbackNetworks, false)

    User->>App: 请求访问 http://169.254.169.254/latest/meta-data/
    App->>M: CheckIP("169.254.169.254")
    M->>IPACL: Check(ip)
    IPACL-->>M: Denied
    M-->>App: Denied
    App-->>User: 403 Forbidden（SSRF 攻击被阻止）
```

## 使用场景：黑名单短链

```mermaid
sequenceDiagram
    participant User as 用户
    participant App as 应用
    participant M as Manager
    participant DomainACL

    App->>M: AddPredefinedDomainSet(Shorteners, false)
    App->>M: AddPredefinedDomainSet(DisposableEmail, false)

    User->>App: 注册请求，邮箱 guerrillamail.com
    App->>M: CheckDomain("guerrillamail.com")
    M->>DomainACL: Check(domain)
    DomainACL-->>M: Denied
    M-->>App: Denied
    App-->>User: 注册被拒绝（一次性邮箱不允许）
```

## 使用场景：白名单仅允许公共 DNS

```mermaid
flowchart LR
    subgraph 白名单
        PDNS[PublicDNS]
    end

    A[DNS 查询请求] --> B{IP 在白名单?}
    B -->|是| C[允许 ✅]
    B -->|否| D[拒绝 ❌]

    D --> E["8.8.8.8 → 允许"]
    D --> F["1.1.1.1 → 允许"]
    D --> G["10.0.0.1 → 拒绝"]
    D --> H["192.168.1.1 → 拒绝"]
```