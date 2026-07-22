# 域名匹配维度的深入理解

## 五种匹配维度

DomainACL 支持五种不同的匹配维度，满足从简单到复杂的各种场景：

```mermaid
quadrantChart
    title 匹配维度对比
    x-axis 灵活度低 --> 灵活度高
    y-axis 性能高 --> 性能低
    quadrant-1 高灵活低性能
    quadrant-2 低灵活低性能
    quadrant-3 低灵活高性能
    quadrant-4 高灵活高性能
    "精确匹配": [0.15, 0.9]
    "通配子域": [0.35, 0.75]
    "前缀匹配": [0.50, 0.70]
    "宽松后缀": [0.65, 0.50]
    "正则匹配": [0.90, 0.20]
```

## 精确匹配

```mermaid
flowchart LR
    A[example.com] --> B{domain == example.com?}
    B -->|是| C[命中 ✅]
    B -->|否| D[未命中]
    E[sub.example.com] --> B
    F[notexample.com] --> B
```

最简单的匹配方式，`includeSubdomains=false` 时使用 `map[string]struct{}` O(1) 查找：

```go
acl.Add("example.com")
// 匹配: example.com
// 不匹配: sub.example.com, notexample.com
```

## 通配子域 `*.example.com`

```mermaid
flowchart LR
    A[*.example.com] --> B{HasSuffix .example.com?}
    B -->|是| C[命中 ✅]
    B -->|否| D[不匹配: 主域本身]
    E[sub.example.com] --> B
    F[example.com] --> B
    G[other.com] --> B
```

仅匹配子域名，**不包含主域本身**：

```go
acl.Add("*.example.com")
// 匹配: sub.example.com, deep.sub.example.com
// 不匹配: example.com（主域本身不匹配）
```

## 前缀匹配 `api.*`

```mermaid
flowchart LR
    A[api.*] --> B{HasPrefix api.?}
    B -->|是| C[命中 ✅]
    B -->|否| D[未命中]
    E[api.example.com] --> B
    F[api.other.org] --> B
    G[example.com] --> B
    H[apisomething.com] --> B
```

匹配以指定前缀开头的域名——适合 API 域名分组：

```go
acl.Add("api.*")
// 匹配: api.example.com, api.service.com
// 不匹配: example.com, apiservice.com
```

## 宽松后缀 `*example.com`

```mermaid
flowchart LR
    A[*example.com] --> B{domain == example.com 或 HasSuffix .example.com?}
    B -->|是| C[命中 ✅]
    B -->|否| D[未命中]
    E[example.com] --> B
    F[sub.example.com] --> B
    G[notexample.com] --> B
```

匹配主域本身及其任意子域名，**使用标签边界**防止误匹配：

```go
acl.Add("*example.com")
// 匹配: example.com, sub.example.com, deep.sub.example.com
// 不匹配: notexample.com（标签边界保护！）
```

## 正则匹配 `/pattern/`

```mermaid
flowchart LR
    A[/^api\\..*\\.com$/] --> B[regexp.Compile]
    B --> C{编译成功?}
    C -->|否| D[返回错误]
    C -->|是| E[编译后的 Regexp]
    E --> F[MatchString 小写化域名]
    F --> G[命中 ✅]
    H[api.service.com] --> F
    I[other.net] --> F
```

最灵活的方式，按声明顺序依次匹配（Go RE2 引擎，天然防 ReDoS）：

```go
acl.Add("/^api\\..*\\.com$/")
// 匹配: api.service.com
// 不匹配: api.service.net, plain.com
```

## 匹配优先级

```mermaid
flowchart TB
    A[输入域名] --> B[标准化: 小写/剥协议/剥端口/剥路径]
    B --> C{精确匹配?}
    C -->|是| D[命中 ✅]
    C -->|否| E{通配子域匹配?}
    E -->|是| D
    E -->|否| F{前缀匹配?}
    F -->|是| D
    F -->|否| G{宽松后缀匹配?}
    G -->|是| D
    G -->|否| H{正则匹配?}
    H -->|是| D
    H -->|否| I[未命中]
```

匹配顺序固定：精确 → 通配子域 → 前缀 → 宽松后缀 → 正则。一旦命中立即返回，不继续检查后续维度。正则匹配按声明顺序检查，多个正则中第一个命中的生效。

## 域名标准化

```mermaid
flowchart TB
    A["https://www.Sub.Example.NET:8080/path?q=1#frag"] --> B[移除协议]
    B --> C["www.Sub.Example.NET:8080/path?q=1#frag"]
    C --> D[移除 www]
    D --> E["Sub.Example.NET:8080/path?q=1#frag"]
    E --> F[移除端口]
    F --> G["Sub.Example.NET/path?q=1#frag"]
    G --> H[移除路径/参数/fragment]
    H --> I["Sub.Example.NET"]
    I --> J[小写化]
    J --> K["sub.example.net"]
    K --> L[移除末尾点]
    L --> M["sub.example.net"]
```

标准化包含：
1. 移除协议前缀（`http://`、`https://`）
2. 移除 `www` 前缀
3. 移除端口号
4. 移除路径、查询参数和 fragment
5. 转换为小写（DNS 大小写不敏感）
6. 移除末尾点（FQDN 根标签）

## 性能对比

| 维度 | 复杂度 | 规则数 1000 时 | 说明 |
|------|--------|---------------|------|
| 精确匹配 | O(1) | ~70 ns/op | map 查找，常数级 |
| 通配子域 | O(n) | ~80 µs/op | 线性扫描后缀列表 |
| 前缀匹配 | O(n) | ~80 µs/op | 线性扫描前缀列表 |
| 宽松后缀 | O(n) | ~80 µs/op | 线性扫描后缀列表 |
| 正则匹配 | O(n) | ~100-500 µs/op | 线性扫描，取决于正则复杂度 |