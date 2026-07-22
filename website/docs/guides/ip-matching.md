# IP 匹配深入理解

## 前缀树（Trie）匹配

IPACL 使用双前缀树（IPv4/IPv6 各一棵独立子树）实现 O(prefixLen) 匹配，与规则数无关：

```mermaid
flowchart TB
    subgraph IPv4 前缀树
        Root4[根节点] --> B0[bit 0]
        Root4 --> B1[bit 1]
        B0 --> C0[bit 00]
        B0 --> C1[bit 01]
        B1 --> C2[bit 10]
        B1 --> C3[bit 11]

        C0 --> D0[10.0.0.0/8]
        C1 --> D1[...]
        C2 --> D2[192.0.0.0/8]
        C3 --> D3[...]

        D0 --> E0[10.1.0.0/16]
        D0 --> E1[10.2.0.0/16]
    end

    subgraph IPv6 前缀树
        Root6[根节点] --> F0[...]
        Root6 --> F1[...]
    end
```

## 匹配 vs 最长前缀 Lookup

```mermaid
sequenceDiagram
    participant 用户
    participant IPACL
    participant Trie

    Note over 用户, Trie: Check 判定
    用户->>IPACL: Check("10.1.2.3")
    IPACL->>Trie: Contains(ip)
    Trie->>Trie: 按位遍历，找到任意匹配
    Trie-->>IPACL: true（任何命中即返回）
    IPACL-->>用户: Denied

    Note over 用户, Trie: Lookup 反查
    用户->>IPACL: Lookup("10.1.2.3")
    IPACL->>Trie: Lookup(ip)
    Trie->>Trie: 按位遍历，记录最长路径
    Trie-->>IPACL: 10.1.0.0/16（最长前缀）
    IPACL-->>用户: "10.1.0.0/16"
```

## 区间展开算法

`a-b` 区间语法使用 `math/big` 进行 CIDR 展开，避免 IPv6 巨区间溢出：

```mermaid
flowchart TB
    A[输入: 192.168.1.10-192.168.1.20] --> B[start=192.168.1.10, end=192.168.1.20]
    B --> C[计算 cur 的 trailing zeros]
    C --> D{cur 的块大小}
    D --> E{块末尾 <= end?}
    E -->|是| F[添加 CIDR 块]
    E -->|否| G[缩小块大小]
    G --> E
    F --> H[推进到块末尾+1]
    H --> I{cur <= end?}
    I -->|是| C
    I -->|否| J[完成]

    J --> K[输出: 最少不重叠 CIDR 块]
    K --> L["192.168.1.10/31<br>192.168.1.12/30<br>192.168.1.16/29"]
```

## Zone ID 处理

IPv6 链路本地地址 (`fe80::1%eth0`) 中的 zone id 会在检查前自动剥离：

```mermaid
flowchart LR
    A["fe80::1%eth0"] --> B[stripZone]
    B --> C["fe80::1"]
    C --> D[net.ParseIP]
    D --> E[IP 对象]
    E --> F[进入 v6 前缀树匹配]
```

## 去重与规范化

```mermaid
flowchart LR
    A["2001:0db8::0000:0000:0000:0000:0001"] --> B[net.ParseIP]
    B --> C[ip.String 规范化]
    C --> D["2001:db8::1"]
    D --> E[去重：同一 Original 只入一次]
    F["2001:db8::1"] --> C
    G["2001:0db8::1"] --> C
```

## 预定义 IP 集合

```mermaid
mindmap
  预定义 IP 集合
    私有网络
      10.0.0.0/8
      172.16.0.0/12
      192.168.0.0/16
    云元数据
      169.254.169.254/32
      fd00:ec2::/32
    特殊网络
      Loopback
      Link-Local
      Multicast
      Broadcast
    Docker
      Docker Networks
      K8s Service
    DNS
      Public DNS
```

## 完整数据流

```mermaid
flowchart TB
    A[IP 输入] --> B{输入格式判断}

    B -->|单 IP| C[parseIPRange]
    B -->|CIDR| D[parseIPRange]
    B -->|区间 a-b| E[parseIPRangeList]

    C -->|normalizeIPString| F[IPRange]
    D -->|normalizeIPString| IPNet[IPNet]
    E -->|rangeToCIDRs| R[多个 IPRange]

    F --> ACL[IPACL.ranges]
    IPNet --> ACL
    R --> ACL

    ACL --> Trie[插入前缀树]
    Trie -->|Contains| Check[Check 判定]
    Trie -->|Lookup| Lookup[最长前缀反查]
```