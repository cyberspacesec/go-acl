# ACL 匹配维度扩展（域名前缀/后缀/正则 + IP 范围区间）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 在不破坏 `types.MutableACL` 接口契约的前提下，补齐两大访问控制类的匹配维度：域名侧新增前缀匹配（`api.*`）、宽松后缀匹配（`*example.com`，含主域）、正则匹配（`/^...$/`）；IP 侧新增范围区间语法（`a-b`），并经 JSON Policy、Manager 与文档层统一暴露。

**Architecture:** 数据流统一为「用户规则串 → Add 识别语法分支 → 归一化/编译存入对应表 → matchDomain/matchIP 查询 → DecideByListType 决策」。域名侧采用最小侵入的多表方案：现有 `domains`/`domainSet`（精确）+ `wildcardSuffixes`（`*.x` 仅子域）保留不动，新增 `prefixes`（`xxx.*` 前缀）、`looseSuffixes`（`*x` 宽松后缀，含主域）、`regexes`（`/re/` 编译后的 `*regexp.Regexp`）四张独立表；`matchDomain` 在现有分支之前依次检查前缀/宽松后缀/正则/通配，命中即返回。IP 侧区间语法 `a-b` 在 `Add` 层经新函数 `parseIPRangeList` 识别，两端 IP 按字节边界合并为 CIDR 列表（标准 `rangeToCIDRs` 算法），逐个走现有 `parseIPRange`/`trie.Insert`，区间规则在 `ranges` 中以 Original 形式 `start-end` 记录。复用现有 trie 与 `normalizeDomain`/`normalizeIPString`，不引入新依赖（正则用标准库 `regexp`，Go RE2 引擎天然无回溯、防 ReDoS）。

**Tech Stack:** Go 1.18+，仅标准库（`net`、`strings`、`regexp`、`errors`、`fmt`、`sync`、`testing`），表驱动测试，Conventional Commits

**Risks:**
- Task 1/2 改 `matchDomain` 核心匹配——可能影响现有 `TestDomainACL_Wildcard`/`TestComplexSubdomainMatching` → 缓解：新分支置于现有分支之前但各自独立，非通配/非前缀/非正则规则行为字节不变；先跑全量基线再改
- Task 2 正则有 ReDoS 担忧 → 缓解：Go `regexp` 包基于 RE2，无回溯，天然防 ReDoS；仅暴露给信任配置方
- Task 3 区间转 CIDR 集合可能规则数膨胀（如 `0.0.0.0-255.255.255.255` 展开为少量 CIDR，但超大区间仍多）→ 缓解：标准字节边界合并算法将任意区间压缩为至多 `2×地址位数` 个 CIDR；`IPRange.Original` 存 `start-end` 原文便于 Remove，不存展开后的逐 CIDR
- `*suffix`（宽松含主域）与 `*.suffix`（仅子域）语义易混 → 缓解：文档明确区分 + 测试覆盖两条语义，命名用 `looseSuffixes` 与 `wildcardSuffixes` 区分
- Task 3 区间两端地址族不一致（IPv4-IPv6）或起止反转 → 缓解：返回 `ErrInvalidIPRange` 哨兵错误

---

### Task 1: 域名前缀匹配 `prefix.*` 与宽松后缀匹配 `*suffix`

**Depends on:** None
**Files:**
- Modify: `pkg/domain/domain.go:37-45`（struct 加 prefixes/looseSuffixes 字段）、`:517-525`（新增辅助函数）、`:169-205`（Add 分流）、`:244-316`（Remove 分流）、`:476-515`（matchDomain 加分支）、`:369-380`（GetDomains 重组）
- Test: `pkg/domain/domain_test.go`（追加前缀/宽松后缀测试）

- [ ] **Step 1: 修改 DomainACL 结构以增加前缀表与宽松后缀表 — 最小侵入隔离新匹配维度**
文件: `pkg/domain/domain.go:37-45`（替换结构定义）

```go
type DomainACL struct {
	// mu 保护 domains 的并发访问；listType 与 includeSubdomains 在构造后不可变
	mu      sync.RWMutex
	domains []string
	// domainSet 是 domains 的 set 镜像，用于 includeSubdomains=false 时的 O(1) 精确匹配
	domainSet map[string]struct{}
	// wildcardSuffixes 存放通配规则 *.example.com 的裸后缀，用于仅子域名匹配（不含主域本身）
	wildcardSuffixes []string
	// prefixes 存放前缀规则 api.* 的裸前缀，匹配 api.example.com 但不匹配 example.com
	prefixes []string
	// looseSuffixes 存放宽松后缀规则 *example.com 的裸后缀，匹配任意以 example.com 结尾者（含主域本身）
	looseSuffixes []string
	listType          types.ListType
	includeSubdomains bool
}
```

- [ ] **Step 2: 新增前缀与宽松后缀辅助函数 — 识别 api.* 与 *example.com 形式**
文件: `pkg/domain/domain.go`（在 isWildcardDomain/stripWildcard 之后，约 `:525` 处新增）

```go
// isPrefixDomain 判断规则是否为前缀形式 api.*
func isPrefixDomain(d string) bool {
	return strings.HasSuffix(d, ".*")
}

// stripPrefix 去除 .* 后缀，返回裸前缀
func stripPrefix(d string) string {
	return strings.TrimSuffix(d, ".*")
}

// isLooseSuffixDomain 判断规则是否为宽松后缀形式 *example.com（无点，含主域）
// 注意：*.example.com（含点）是通配仅子域规则，由 isWildcardDomain 处理，不在此列
func isLooseSuffixDomain(d string) bool {
	return strings.HasPrefix(d, "*") && !strings.HasPrefix(d, "*.")
}

// stripStar 去除 * 前缀，返回裸后缀
func stripStar(d string) string {
	return strings.TrimPrefix(d, "*")
}
```

- [ ] **Step 3: 修改 Add 以分流前缀与宽松后缀规则 — 普通规则仍进主表**
文件: `pkg/domain/domain.go:169-205`（替换通配分流块之后、普通规则块之前的分流逻辑；保留函数签名、锁、normalize+空跳过）

```go
func (d *DomainACL) Add(domains ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, domain := range domains {
		normalizedDomain := normalizeDomain(domain)
		if normalizedDomain == "" {
			// 空域名或经标准化后为空，按既有语义忽略
			continue
		}

		// 正则规则交给 Task 2 处理，此处跳过（Task 2 未合入前不会出现 /re/ 形式）

		// 通配规则 *.example.com → 存裸后缀，仅匹配其子域（不含主域本身）
		if isWildcardDomain(normalizedDomain) {
			suffix := stripWildcard(normalizedDomain)
			if suffix == "" {
				continue
			}
			found := false
			for _, existing := range d.wildcardSuffixes {
				if existing == suffix {
					found = true
					break
				}
			}
			if !found {
				d.wildcardSuffixes = append(d.wildcardSuffixes, suffix)
			}
			continue
		}

		// 前缀规则 api.* → 存裸前缀，匹配 api.example.com 但不匹配 example.com
		if isPrefixDomain(normalizedDomain) {
			prefix := stripPrefix(normalizedDomain)
			if prefix == "" {
				continue
			}
			found := false
			for _, existing := range d.prefixes {
				if existing == prefix {
					found = true
					break
				}
			}
			if !found {
				d.prefixes = append(d.prefixes, prefix)
			}
			continue
		}

		// 宽松后缀规则 *example.com → 存裸后缀，匹配任意以 example.com 结尾者（含主域）
		if isLooseSuffixDomain(normalizedDomain) {
			suffix := stripStar(normalizedDomain)
			if suffix == "" {
				continue
			}
			found := false
			for _, existing := range d.looseSuffixes {
				if existing == suffix {
					found = true
					break
				}
			}
			if !found {
				d.looseSuffixes = append(d.looseSuffixes, suffix)
			}
			continue
		}

		// 普通规则进主表
		exists := false
		for _, existingDomain := range d.domains {
			if existingDomain == normalizedDomain {
				exists = true
				break
			}
		}

		if !exists {
			d.domains = append(d.domains, normalizedDomain)
			if d.domainSet != nil {
				d.domainSet[normalizedDomain] = struct{}{}
			}
		}
	}
	return nil
}
```

**注意**：新增 `continue` 分支必须在普通规则块之前，确保各特殊语法不被误存入主表。

- [ ] **Step 4: 修改 Remove 以支持移除前缀与宽松后缀规则 — 分流删除**
文件: `pkg/domain/domain.go:244-316`（替换整个 Remove 函数）

```go
func (d *DomainACL) Remove(domains ...string) error {
	// 零参数：no-op，不视为错误
	if len(domains) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// 构建待删除的标准化集合，区分各特殊语法
	var wildcardToRemove []string
	var prefixToRemove []string
	var looseSuffixToRemove []string
	toRemove := make(map[string]struct{}, len(domains))
	for _, dom := range domains {
		n := normalizeDomain(dom)
		if n == "" {
			continue
		}
		switch {
		case isWildcardDomain(n):
			wildcardToRemove = append(wildcardToRemove, stripWildcard(n))
		case isPrefixDomain(n):
			prefixToRemove = append(prefixToRemove, stripPrefix(n))
		case isLooseSuffixDomain(n):
			looseSuffixToRemove = append(looseSuffixToRemove, stripStar(n))
		default:
			toRemove[n] = struct{}{}
		}
	}
	// 传入了参数但全部标准化后为空：视为未找到，保持与旧版一致的错误语义
	if len(toRemove) == 0 && len(wildcardToRemove) == 0 && len(prefixToRemove) == 0 && len(looseSuffixToRemove) == 0 {
		return ErrDomainNotFound
	}

	removed := 0

	// 通配删除（就地过滤复用底层数组）
	if len(wildcardToRemove) > 0 {
		newSuffixes := d.wildcardSuffixes[:0]
		for _, existing := range d.wildcardSuffixes {
			drop := false
			for _, w := range wildcardToRemove {
				if existing == w {
					drop = true
					break
				}
			}
			if drop {
				removed++
				continue
			}
			newSuffixes = append(newSuffixes, existing)
		}
		d.wildcardSuffixes = newSuffixes
	}

	// 前缀删除
	if len(prefixToRemove) > 0 {
		newPrefixes := d.prefixes[:0]
		for _, existing := range d.prefixes {
			drop := false
			for _, p := range prefixToRemove {
				if existing == p {
					drop = true
					break
				}
			}
			if drop {
				removed++
				continue
			}
			newPrefixes = append(newPrefixes, existing)
		}
		d.prefixes = newPrefixes
	}

	// 宽松后缀删除
	if len(looseSuffixToRemove) > 0 {
		newLoose := d.looseSuffixes[:0]
		for _, existing := range d.looseSuffixes {
			drop := false
			for _, s := range looseSuffixToRemove {
				if existing == s {
					drop = true
					break
				}
			}
			if drop {
				removed++
				continue
			}
			newLoose = append(newLoose, existing)
		}
		d.looseSuffixes = newLoose
	}

	// 普通删除
	var newDomains []string
	for _, existing := range d.domains {
		if _, drop := toRemove[existing]; drop {
			removed++
			continue
		}
		newDomains = append(newDomains, existing)
	}

	if removed == 0 {
		return ErrDomainNotFound
	}

	// 更新 domains 与 domainSet 镜像
	d.domains = newDomains
	newSet := make(map[string]struct{}, len(newDomains))
	for _, dom := range newDomains {
		newSet[dom] = struct{}{}
	}
	d.domainSet = newSet
	return nil
}
```

- [ ] **Step 5: 修改 matchDomain 以检查前缀与宽松后缀 — 新分支置于通配之后、精确之前**
文件: `pkg/domain/domain.go:476-515`（替换整个 matchDomain 函数）

```go
func (d *DomainACL) matchDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// 通配规则：*.example.com 仅匹配 example.com 的子域，不含 example.com 本身
	for _, suffix := range d.wildcardSuffixes {
		if strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}

	// 前缀规则：api.* 匹配 api.example.com 等以 api. 开头者，但不含 example.com 本身
	for _, prefix := range d.prefixes {
		if strings.HasPrefix(domain, prefix+".") {
			return true
		}
	}

	// 宽松后缀规则：*example.com 匹配任意以 example.com 结尾者（含 example.com 主域本身）
	for _, suffix := range d.looseSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}

	// 不含子域名匹配：O(1) 精确查找
	if !d.includeSubdomains {
		if d.domainSet != nil {
			_, ok := d.domainSet[domain]
			return ok
		}
		// 兜底：domainSet 未初始化时回退线性扫描
		for _, aclDomain := range d.domains {
			if domain == aclDomain {
				return true
			}
		}
		return false
	}

	// 含子域名匹配：精确命中或后缀命中
	for _, aclDomain := range d.domains {
		// 完全匹配
		if domain == aclDomain {
			return true
		}
		if strings.HasSuffix(domain, "."+aclDomain) {
			return true
		}
	}

	return false
}
```

- [ ] **Step 6: 修改 GetDomains 以包含前缀与宽松后缀规则 — GetRules 自动覆盖**
文件: `pkg/domain/domain.go:369-380`（替换 GetDomains 函数；GetRules 委托无需改动）

```go
func (d *DomainACL) GetDomains() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]string, 0, len(d.domains)+len(d.wildcardSuffixes)+len(d.prefixes)+len(d.looseSuffixes))
	result = append(result, d.domains...)
	for _, s := range d.wildcardSuffixes {
		result = append(result, "*."+s)
	}
	for _, p := range d.prefixes {
		result = append(result, p+".*")
	}
	for _, s := range d.looseSuffixes {
		result = append(result, "*"+s)
	}
	return result
}
```

- [ ] **Step 7: 追加前缀与宽松后缀测试 — 覆盖核心新语义**
文件: `pkg/domain/domain_test.go`（末尾追加）

```go
// TestDomainACL_Prefix 验证 api.* 仅匹配以 api. 开头的域名
func TestDomainACL_Prefix(t *testing.T) {
	acl := NewDomainACL([]string{"api.*"}, types.Blacklist, false)
	// 前缀子域命中
	if perm, _ := acl.Check("api.example.com"); perm != types.Denied {
		t.Errorf("api.example.com 应 Denied，得到 %s", perm)
	}
	// 多层命中
	if perm, _ := acl.Check("api.sub.example.com"); perm != types.Denied {
		t.Errorf("api.sub.example.com 应 Denied，得到 %s", perm)
	}
	// 非该前缀不命中
	if perm, _ := acl.Check("example.com"); perm != types.Allowed {
		t.Errorf("example.com 应 Allowed，得到 %s", perm)
	}
	if perm, _ := acl.Check("web.example.com"); perm != types.Allowed {
		t.Errorf("web.example.com 应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_LooseSuffix 验证 *example.com 宽松后缀含主域
func TestDomainACL_LooseSuffix(t *testing.T) {
	acl := NewDomainACL([]string{"*evil.com"}, types.Blacklist, false)
	// 主域本身命中（与 *.evil.com 的关键区别）
	if perm, _ := acl.Check("evil.com"); perm != types.Denied {
		t.Errorf("evil.com 主域应 Denied（宽松后缀含主域），得到 %s", perm)
	}
	// 子域命中
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Denied {
		t.Errorf("sub.evil.com 应 Denied，得到 %s", perm)
	}
	// 相邻域名不误匹配
	if perm, _ := acl.Check("notevil.com"); perm != types.Allowed {
		t.Errorf("notevil.com 应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_LooseSuffixVsWildcard 验证 *x 与 *.x 语义可区分且可共存
func TestDomainACL_LooseSuffixVsWildcard(t *testing.T) {
	// *evil.com 含主域；*.evil.com 仅子域
	acl := NewDomainACL([]string{"*evil.com"}, types.Blacklist, false)
	if perm, _ := acl.Check("evil.com"); perm != types.Denied {
		t.Errorf("*evil.com 应命中主域 evil.com，得到 %s", perm)
	}
	wcl := NewDomainACL([]string{"*.evil.com"}, types.Blacklist, false)
	if perm, _ := wcl.Check("evil.com"); perm != types.Allowed {
		t.Errorf("*.evil.com 不应命中主域 evil.com，得到 %s", perm)
	}
}

// TestDomainACL_RemovePrefixAndLooseSuffix 验证移除前缀与宽松后缀规则
func TestDomainACL_RemovePrefixAndLooseSuffix(t *testing.T) {
	acl := NewDomainACL([]string{"api.*", "*evil.com"}, types.Blacklist, false)
	if err := acl.Remove("api.*"); err != nil {
		t.Fatalf("移除前缀失败: %v", err)
	}
	if perm, _ := acl.Check("api.example.com"); perm != types.Allowed {
		t.Errorf("移除 api.* 后应 Allowed，得到 %s", perm)
	}
	// 宽松后缀仍在
	if perm, _ := acl.Check("evil.com"); perm != types.Denied {
		t.Errorf("evil.com 应仍 Denied，得到 %s", perm)
	}
	if err := acl.Remove("*evil.com"); err != nil {
		t.Fatalf("移除宽松后缀失败: %v", err)
	}
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Allowed {
		t.Errorf("移除 *evil.com 后应 Allowed，得到 %s", perm)
	}
}
```

- [ ] **Step 8: 验证前缀与宽松后缀语义**
Run: `go test ./pkg/domain/ -run 'TestDomainACL_Prefix|TestDomainACL_LooseSuffix|TestDomainACL_RemovePrefixAndLooseSuffix' -v`
Expected:
  - Exit code: 0
  - Output contains: "--- PASS"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 9: 全量回归确保既有域名行为未破坏**
Run: `go test ./pkg/domain/ -v 2>&1 | tail -25`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 10: 提交**
Run: `git add pkg/domain/domain.go pkg/domain/domain_test.go && git commit -m "feat(domain): add prefix (api.*) and loose-suffix (*example.com) match dimensions"`

---

### Task 2: 域名正则匹配 `/^...$/`

**Depends on:** Task 1
**Files:**
- Modify: `pkg/domain/domain.go:37-45`（struct 加 regexes 字段）、`:169-205`（Add 加正则分流）、`:244-316`（Remove 加正则删除）、`:476-515`（matchDomain 加正则分支）、`:369-380`（GetDomains 加正则）、`pkg/ip/ip.go` 无关
- Test: `pkg/domain/domain_test.go`（追加正则测试）

- [ ] **Step 1: 修改 DomainACL 结构以增加正则表 — 存编译后的 *regexp.Regexp**
文件: `pkg/domain/domain.go:37-45`（在 looseSuffixes 字段后追加 regexes 字段）

```go
type DomainACL struct {
	// mu 保护 domains 的并发访问；listType 与 includeSubdomains 在构造后不可变
	mu      sync.RWMutex
	domains []string
	// domainSet 是 domains 的 set 镜像，用于 includeSubdomains=false 时的 O(1) 精确匹配
	domainSet map[string]struct{}
	// wildcardSuffixes 存放通配规则 *.example.com 的裸后缀，用于仅子域名匹配（不含主域本身）
	wildcardSuffixes []string
	// prefixes 存放前缀规则 api.* 的裸前缀
	prefixes []string
	// looseSuffixes 存放宽松后缀规则 *example.com 的裸后缀（含主域本身）
	looseSuffixes []string
	// regexes 存放正则规则 /pattern/ 编译后的正则，按声明顺序匹配
	regexes []*regexp.Regexp
	// regexSources 存放正则规则的原文（用于 GetDomains 还原与 Remove 匹配）
	regexSources []string
	listType          types.ListType
	includeSubdomains bool
}
```

**注意**：`regexes` 与 `regexSources` 并行——前者用于匹配（编译后的 `*regexp.Regexp`），后者用于 GetDomains 还原原文与 Remove 比对。两者索引一一对应。

- [ ] **Step 2: 新增正则辅助函数 — 识别 /re/ 形式并编译**
文件: `pkg/domain/domain.go`（在前缀/宽松后缀辅助函数之后新增）

```go
// isRegexRule 判断规则是否为正则形式 /pattern/（首尾斜杠包围）
func isRegexRule(d string) bool {
	return len(d) >= 2 && strings.HasPrefix(d, "/") && strings.HasSuffix(d, "/")
}

// stripRegexSlashes 去除首尾斜杠，返回正则原文
func stripRegexSlashes(d string) string {
	return d[1 : len(d)-1]
}
```

- [ ] **Step 3: 修改 Add 以分流正则规则 — 编译失败返回错误**
文件: `pkg/domain/domain.go:169-205`（在 normalize+空跳过后、通配分流前插入正则分流块；函数签名加返回 error 已有）

在 Add 的 `if normalizedDomain == ""` 块之后、`if isWildcardDomain` 之前插入：

```go
		// 正则规则 /pattern/ → 编译后存 regexes，原文存 regexSources
		if isRegexRule(normalizedDomain) {
			pattern := stripRegexSlashes(normalizedDomain)
			if pattern == "" {
				continue
			}
			// 已存在原文则跳过
			found := false
			for _, src := range d.regexSources {
				if src == pattern {
					found = true
					break
				}
			}
			if found {
				continue
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("无效的正则规则 %q: %w", pattern, err)
			}
			d.regexes = append(d.regexes, re)
			d.regexSources = append(d.regexSources, pattern)
			continue
		}
```

**注意**：`regexp.Compile`（非 MustCompile）基于 RE2 引擎，无回溯，天然防 ReDoS。正则编译失败返回包装错误，符合 Add 无效输入返回 error 的接口契约。

- [ ] **Step 4: 修改 Remove 以支持移除正则规则 — 按原文比对删除**
文件: `pkg/domain/domain.go:244-316`（在 Remove 的分流 switch 中加正则分支，并在删除块中加正则就地过滤）

分流 switch 加分支（在 default 之前）：

```go
		case isRegexRule(n):
			regexToRemove = append(regexToRemove, stripRegexSlashes(n))
```

分流变量声明区加：

```go
	var regexToRemove []string
```

空检查加 `&& len(regexToRemove) == 0`。

在宽松后缀删除块之后、普通删除之前加正则删除块：

```go
	// 正则删除（regexes 与 regexSources 索引一一对应，同步过滤）
	if len(regexToRemove) > 0 {
		newRegexes := d.regexes[:0]
		newSources := d.regexSources[:0]
		for i, src := range d.regexSources {
			drop := false
			for _, r := range regexToRemove {
				if src == r {
					drop = true
					break
				}
			}
			if drop {
				removed++
				continue
			}
			newRegexes = append(newRegexes, d.regexes[i])
			newSources = append(newSources, src)
		}
		d.regexes = newRegexes
		d.regexSources = newSources
	}
```

**注意**：`d.regexes[:0]` 与 `d.regexSources[:0]` 双切片就地过滤——两切片长度始终相等、同步推进，写入索引 ≤ 读取索引，安全。

- [ ] **Step 5: 修改 matchDomain 以检查正则 — 置于通配/前缀/宽松后缀之后、精确之前**
文件: `pkg/domain/domain.go:476-515`（在宽松后缀循环之后、`if !d.includeSubdomains` 之前插入正则循环）

```go
	// 正则规则：按声明顺序 MatchString，命中即返回
	for _, re := range d.regexes {
		if re.MatchString(domain) {
			return true
		}
	}
```

- [ ] **Step 6: 修改 GetDomains 以包含正则规则 — 还原 /pattern/ 原文**
文件: `pkg/domain/domain.go:369-380`（在宽松后缀循环之后追加正则还原）

```go
	for _, src := range d.regexSources {
		result = append(result, "/"+src+"/")
	}
```

result 初始容量加 `len(d.regexSources)`。

- [ ] **Step 7: 追加正则测试 — 覆盖编译、匹配、删除、错误**
文件: `pkg/domain/domain_test.go`（末尾追加）

```go
// TestDomainACL_Regex 验证 /pattern/ 正则匹配
func TestDomainACL_Regex(t *testing.T) {
	acl := NewDomainACL([]string{`/^api-\d+\.example\.com$/`}, types.Blacklist, false)
	// 命中
	if perm, _ := acl.Check("api-1.example.com"); perm != types.Denied {
		t.Errorf("api-1.example.com 应 Denied，得到 %s", perm)
	}
	if perm, _ := acl.Check("api-99.example.com"); perm != types.Denied {
		t.Errorf("api-99.example.com 应 Denied，得到 %s", perm)
	}
	// 不命中
	if perm, _ := acl.Check("api.example.com"); perm != types.Allowed {
		t.Errorf("api.example.com 应 Allowed，得到 %s", perm)
	}
	if perm, _ := acl.Check("api-x.example.com"); perm != types.Allowed {
		t.Errorf("api-x.example.com 应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_RegexInvalid 验证无效正则返回错误且不污染 ACL
func TestDomainACL_RegexInvalid(t *testing.T) {
	// 未闭合括号是 RE2 语法错误
	acl, err := NewDomainACL([]string{`/^(unbalanced$/`}, types.Blacklist, false)
	if err == nil {
		t.Fatal("无效正则应返回错误，得到 nil")
	}
	// NewDomainACL 失败时返回的 acl 可能非空但不应被使用；确认错误信息含正则相关
}

// TestDomainACL_RemoveRegex 验证移除正则规则
func TestDomainACL_RemoveRegex(t *testing.T) {
	acl := NewDomainACL([]string{`/^api-\d+\.example\.com$/`}, types.Blacklist, false)
	if err := acl.Remove(`/^api-\d+\.example\.com$/`); err != nil {
		t.Fatalf("移除正则失败: %v", err)
	}
	if perm, _ := acl.Check("api-1.example.com"); perm != types.Allowed {
		t.Errorf("移除后应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_RegexCoexist 验证正则与通配/精确规则共存
func TestDomainACL_RegexCoexist(t *testing.T) {
	acl := NewDomainACL([]string{`/^api-\d+\.example\.com$/`, "*.evil.com", "exact.com"}, types.Blacklist, false)
	// 正则命中
	if perm, _ := acl.Check("api-5.example.com"); perm != types.Denied {
		t.Errorf("正则应命中 api-5.example.com，得到 %s", perm)
	}
	// 通配命中
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Denied {
		t.Errorf("通配应命中 sub.evil.com，得到 %s", perm)
	}
	// 精确命中
	if perm, _ := acl.Check("exact.com"); perm != types.Denied {
		t.Errorf("精确应命中 exact.com，得到 %s", perm)
	}
	// GetDomains 返回三类规则
	domains := acl.GetDomains()
	if len(domains) != 3 {
		t.Errorf("应返回 3 条规则，得到 %d: %v", len(domains), domains)
	}
}
```

**注意**：`TestDomainACL_RegexInvalid` 依赖 `NewDomainACL` 对 Add 返回的 error 做处理。**执行者必须先读 `NewDomainACL` 构造函数**——若它内部调用 Add 并吞掉 error（返回 `*DomainACL` 无 error），则无效正则不会在构造时报错，该测试需调整为「先 NewDomainACL 空，再 acl.Add(invalidRegex) 断言 err」。执行者据真实 `NewDomainACL` 签名决定测试写法。

- [ ] **Step 8: 修改 domain.go import 以引入 regexp 与 fmt**
文件: `pkg/domain/domain.go:3-6`（import 块）

```go
import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/cyberspacesec/acl-skills/pkg/types"
)
```

**注意**：执行者先读现有 import 块，仅追加缺失的 `regexp` 与 `fmt`（若已有 errors 则保留），不删除现有导入。

- [ ] **Step 9: 验证正则匹配**
Run: `go test ./pkg/domain/ -run 'TestDomainACL_Regex' -v`
Expected:
  - Exit code: 0
  - Output contains: "--- PASS"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 10: 全量回归 + race + vet + gofmt**
Run: `go test ./... 2>&1 | tail -8 && go test -race ./pkg/domain/ 2>&1 | tail -3 && go vet ./... && gofmt -l pkg/domain/domain.go pkg/domain/domain_test.go`
Expected:
  - Exit code: 0
  - go test 全 ok 无 FAIL
  - gofmt 输出为空

- [ ] **Step 11: 提交**
Run: `git add pkg/domain/domain.go pkg/domain/domain_test.go && git commit -m "feat(domain): add regex (/pattern/) match dimension with RE2-backed compilation"`

---

### Task 3: IP 范围区间语法 `start-end`

**Depends on:** None
**Files:**
- Modify: `pkg/ip/ip.go:14-22`（新增 ErrInvalidIPRange）、`:182-224`（Add 改用 parseIPRangeList）、`:581-622`（parseIPRange 保留，新增 parseIPRangeList + rangeToCIDRs）
- Test: `pkg/ip/ip_test.go`（追加区间测试）

- [ ] **Step 1: 新增 ErrInvalidIPRange 哨兵错误 — 区间语法专用**
文件: `pkg/ip/ip.go:14-22`（在现有错误变量块中追加）

```go
var (
	// ErrInvalidIP 表示提供的IP格式无效
	ErrInvalidIP = errors.New("无效的IP地址格式")
	// ErrInvalidCIDR 表示提供的CIDR格式无效
	ErrInvalidCIDR = errors.New("无效的CIDR格式")
	// ErrInvalidIPRange 表示提供的IP范围区间格式无效（如两端地址族不一致、起止反转）
	ErrInvalidIPRange = errors.New("无效的IP范围区间格式")
	// ErrIPNotFound 表示要操作的IP不在访问控制列表中
	ErrIPNotFound = errors.New("IP不在列表中")
	// ErrInvalidPredefinedSet 表示请求的预定义IP集合不存在
	ErrInvalidPredefinedSet = errors.New("无效的预定义IP集合")
)
```

**注意**：执行者先读现有 `var (...)` 块，仅在 ErrInvalidCIDR 与 ErrIPNotFound 之间插入 `ErrInvalidIPRange`，不改动其余。

- [ ] **Step 2: 新增 rangeToCIDRs 函数 — 将 IP 区间按字节边界合并为 CIDR 列表**
文件: `pkg/ip/ip.go`（在 parseIPRange 函数之后新增）

```go
// rangeToCIDRs 将 [start, end] 闭区间转换为覆盖该区间且不重叠的最少 CIDR 列表。
//
// 标准字节边界合并算法：从 start 起，每次取当前地址能向右扩展到的最大 CIDR 块
// （既不超出 end，也不越过当前字节内已置位的位），推进到该块末尾 +1，直至超过 end。
//
// start 与 end 必须同地址族（同为 IPv4 或同为 IPv6），且 start <= end（按字节序），
// 否则返回 ErrInvalidIPRange。
func rangeToCIDRs(start, end net.IP) ([]*net.IPNet, error) {
	start = start.To16()
	end = end.To16()
	if start == nil || end == nil {
		return nil, ErrInvalidIPRange
	}
	// 地址族一致性：IPv4 映射的 IPv6 形式 To4 非 nil；两端必须一致
	start4 := start.To4()
	end4 := end.To4()
	if (start4 != nil) != (end4 != nil) {
		return nil, ErrInvalidIPRange
	}
	// 用 math/big 表达地址与步长，彻底避免 IPv6 巨大区间下 int/uint64 溢出
	bitLen := 128
	if start4 != nil {
		bitLen = 32
	}
	cur := new(big.Int).SetBytes(start.To16())
	last := new(big.Int).SetBytes(end.To16())
	if cur.Cmp(last) > 0 {
		return nil, ErrInvalidIPRange
	}

	bigOne := big.NewInt(1)
	var result []*net.IPNet
	for cur.Cmp(last) <= 0 {
		// 当前地址在 bitLen 位空间内的「最低置位」决定对齐粒度：
		// cur 的低 trailing 个二进制位为 0，则可对齐到前缀 (bitLen - trailing)。
		// big.Int.TrailingZeroBits 返回最低置位之前 0 的个数（cur=0 时返回 0）。
		trailing := int(cur.TrailingZeroBits())
		if trailing >= bitLen {
			trailing = bitLen - 1 // cur 为全 0 的极端情况，取最大块
		}
		// 块大小 = 2^trailing，块末尾 = cur + (2^trailing - 1)
		blockSize := new(big.Int).Lsh(bigOne, uint(trailing))
		blockEnd := new(big.Int).Sub(new(big.Int).Add(cur, blockSize), bigOne)
		// 若块末尾超过 last，逐步缩小 trailing（块减半）直至块末尾 <= last
		for blockEnd.Cmp(last) > 0 && trailing > 0 {
			trailing--
			blockSize.Lsh(bigOne, uint(trailing))
			blockEnd.Sub(new(big.Int).Add(cur, blockSize), bigOne)
		}
		ones := bitLen - trailing
		// 用 16 字节大端表示构造 CIDR 的 IP 与掩码
		ipBytes := make([]byte, 16)
		cur.FillBytes(ipBytes) // 高位补零到 16 字节
		ipNet := &net.IPNet{
			IP:   net.IP(ipBytes),
			Mask: net.CIDRMask(ones, bitLen),
		}
		result = append(result, ipNet)
		// 推进到当前块末尾 +1
		cur.Add(cur, blockSize)
	}
	return result, nil
}
```

**注意**：该算法用 `math/big.Int` 表达地址与步长，IPv4/IPv6 统一在 128 位空间运算，**彻底消除**旧版 `int`/`uint64` 在超大 IPv6 区间（如 `::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`）下的溢出缺陷。`TrailingZeroBits` 直接给出当前地址的对齐粒度，无需手写位扫描。`bigOne`/`blockSize`/`blockEnd` 均为 `*big.Int`，`FillBytes` 高位补零到 16 字节后构造 `net.IP`。

**执行者必须**：
1. 在 ip.go import 块追加 `"bytes"` 与 `"math/big"`（先读现有 import 块，仅补缺失项）
2. 确认 `getBit`（trie.go 同包）不被本函数引用后，无需改动 trie.go
3. 本函数不依赖任何旧辅助（`ipAlignedToBit`/`ipAddBits`/`ilog2` 均已删除，由 `math/big` 取代）——执行者**不得**再添加这三个函数

- [ ] **Step 3: 新增 parseIPRangeList 函数 — 识别区间语法并展开为 IPRange 列表**
文件: `pkg/ip/ip.go`（在 rangeToCIDRs 之后新增）

```go
// parseIPRangeList 解析单个规则串，返回其对应的 IPRange 列表。
//
// 支持三种语法：
//  1. CIDR（含 /）→ 单条 IPRange
//  2. 区间 a-b（含 - 且非 CIDR）→ 展开为覆盖 [a,b] 的多条 CIDR IPRange
//  3. 单 IP → 单条 IPRange（/32 或 /128）
//
// 区间语法要求两端为同地址族的有效 IP；Original 统一记为 "start-end"（规范化形式）。
func parseIPRangeList(ipStr string) ([]IPRange, error) {
	normalized := normalizeIPString(ipStr)

	// CIDR 优先（含 /）
	if strings.Contains(normalized, "/") {
		r, err := parseIPRange(normalized)
		if err != nil {
			return nil, err
		}
		return []IPRange{*r}, nil
	}

	// 区间语法 a-b（含 - 且两端不含 /）
	if strings.Contains(normalized, "-") {
		parts := strings.SplitN(normalized, "-", 2)
		if len(parts) != 2 {
			return nil, ErrInvalidIPRange
		}
		startIP := net.ParseIP(strings.TrimSpace(parts[0]))
		endIP := net.ParseIP(strings.TrimSpace(parts[1]))
		if startIP == nil || endIP == nil {
			return nil, ErrInvalidIPRange
		}
		cidrs, err := rangeToCIDRs(startIP, endIP)
		if err != nil {
			return nil, err
		}
		original := startIP.String() + "-" + endIP.String()
		ranges := make([]IPRange, 0, len(cidrs))
		for _, c := range cidrs {
			ranges = append(ranges, IPRange{
				Original: original,
				IP:       c.IP,
				IPNet:    c,
			})
		}
		return ranges, nil
	}

	// 单 IP
	r, err := parseIPRange(normalized)
	if err != nil {
		return nil, err
	}
	return []IPRange{*r}, nil
}
```

**注意**：区间规则的多个 IPRange 共享同一 `Original`（"start-end"），便于 Remove 时按原文移除整组。去重逻辑见 Step 4。

- [ ] **Step 4: 修改 Add 以使用 parseIPRangeList — 区间展开为多条并逐个 Insert**
文件: `pkg/ip/ip.go:182-224`（替换解析循环体）

```go
	// 解析和验证每个IP/CIDR/区间
	for _, ipStr := range ipRanges {
		// 忽略空字符串
		if strings.TrimSpace(ipStr) == "" {
			continue
		}

		// 解析为 IPRange 列表（区间语法会展开为多条 CIDR）
		ipRangesParsed, err := parseIPRangeList(ipStr)
		if err != nil {
			return err
		}

		// 区间规则整体去重：若其 Original 已存在则跳过整组
		if len(ipRangesParsed) > 0 {
			if _, ok := seen[ipRangesParsed[0].Original]; ok {
				continue
			}
			seen[ipRangesParsed[0].Original] = struct{}{}
		}
		for _, r := range ipRangesParsed {
			a.ranges = append(a.ranges, r)
			a.trie.Insert(r.IPNet)
		}
	}

	return nil
```

**注意**：`seen` map 与 `existing` 切片在循环前已构建（保留 Task 调研时的去重初始化代码，仅替换循环体）。区间规则的 Original 统一为 "start-end"，故同区间重复添加只整体跳过一次。

- [ ] **Step 5: 追加 IP 区间测试 — 覆盖 IPv4/IPv6 区间、跨族错误、反转、边界**
文件: `pkg/ip/ip_test.go`（末尾追加）

```go
// TestIPRange_Interval 验证 a-b 区间语法匹配
func TestIPRange_Interval(t *testing.T) {
	acl, err := NewIPACL([]string{"192.168.1.10-192.168.1.20"}, types.Blacklist)
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	tests := []struct {
		name string
		ip   string
		want types.Permission
	}{
		{"区间起", "192.168.1.10", types.Denied},
		{"区间内", "192.168.1.15", types.Denied},
		{"区间末", "192.168.1.20", types.Denied},
		{"区间前", "192.168.1.9", types.Allowed},
		{"区间后", "192.168.1.21", types.Allowed},
		{"远端无关", "10.0.0.1", types.Allowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm, err := acl.Check(tt.ip)
			if err != nil {
				t.Fatalf("Check(%s) 错误: %v", tt.ip, err)
			}
			if perm != tt.want {
				t.Errorf("Check(%s) = %s, 期望 %s", tt.ip, perm, tt.want)
			}
		})
	}
}

// TestIPRange_IPv6Interval 验证 IPv6 区间语法
func TestIPRange_IPv6Interval(t *testing.T) {
	acl, err := NewIPACL([]string{"2001:db8::1-2001:db8::5"}, types.Blacklist)
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if perm, _ := acl.Check("2001:db8::3"); perm != types.Denied {
		t.Errorf("2001:db8::3 应 Denied，得到 %s", perm)
	}
	if perm, _ := acl.Check("2001:db8::6"); perm != types.Allowed {
		t.Errorf("2001:db8::6 应 Allowed，得到 %s", perm)
	}
}

// TestIPRange_Invalid 验证非法区间返回 ErrInvalidIPRange
func TestIPRange_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"跨地址族", "192.168.1.1-2001:db8::1"},
		{"起止反转", "192.168.1.20-192.168.1.10"},
		{"端点非IP", "192.168.1.1-notanip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewIPACL([]string{tt.input}, types.Blacklist)
			if !errors.Is(err, ErrInvalidIPRange) {
				t.Errorf("期望 ErrInvalidIPRange，得到 %v", err)
			}
		})
	}
}

// TestIPRange_RemoveInterval 验证移除区间规则
func TestIPRange_RemoveInterval(t *testing.T) {
	acl, err := NewIPACL([]string{"192.168.1.10-192.168.1.20"}, types.Blacklist)
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if err := acl.Remove("192.168.1.10-192.168.1.20"); err != nil {
		t.Fatalf("移除失败: %v", err)
	}
	if perm, _ := acl.Check("192.168.1.15"); perm != types.Allowed {
		t.Errorf("移除后应 Allowed，得到 %s", perm)
	}
}

// TestIPRange_LookupLongestPrefix 验证区间展开后最长前缀反查仍正确
func TestIPRange_LookupLongestPrefix(t *testing.T) {
	m := acl.NewManager()
	if err := m.SetIPACL([]string{"10.0.0.0/8", "10.1.0.10-10.1.0.20"}, types.Blacklist); err != nil {
		t.Fatal(err)
	}
	got, err := m.LookupIP("10.1.0.15")
	if err != nil {
		t.Fatalf("LookupIP 错误: %v", err)
	}
	// 10.1.0.15 同时落在 /8 与区间展开的某 CIDR 内；区间更具体应胜出
	if got == "" {
		t.Errorf("期望非空最长前缀，得到空串")
	}
}
```

**注意**：`TestIPRange_LookupLongestPrefix` 中 `m` 用 `acl.NewManager()`——执行者确认 manager_test.go 的 import 别名（`acl` 或 `aclskt`），据实调整。该测试不固定具体 CIDR 串（区间展开结果取决于算法），仅断言非空。

- [ ] **Step 6: 验证 IP 区间语法**
Run: `go test ./pkg/ip/ -run 'TestIPRange' -v`
Expected:
  - Exit code: 0
  - Output contains: "--- PASS"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 7: 全量回归 + race + vet + gofmt**
Run: `go test ./... 2>&1 | tail -8 && go test -race ./pkg/ip/ ./pkg/acl/ 2>&1 | tail -3 && go vet ./... && gofmt -l pkg/ip/ip.go pkg/ip/ip_test.go`
Expected:
  - Exit code: 0
  - 全 ok 无 FAIL
  - gofmt 空

- [ ] **Step 8: 提交**
Run: `git add pkg/ip/ip.go pkg/ip/ip_test.go && git commit -m "feat(ip): support IP range interval syntax (start-end) with CIDR expansion"`

---

### Task 4: JSON Policy 与 Manager 端到端验证

**Depends on:** Task 1, Task 2, Task 3
**Files:**
- Modify: `pkg/acl/policy_test.go`（追加端到端测试）
- Modify: `testdata/security_policy.json`（追加示例规则，可选）

- [ ] **Step 1: 在 policy_test.go 追加端到端测试 — 验证新语法经 ApplyPolicy 可用**
文件: `pkg/acl/policy_test.go`（末尾追加）

```go
// TestApplyPolicy_DomainPatterns 验证域名前缀/后缀/正则经 JSON Policy 端到端可用
func TestApplyPolicy_DomainPatterns(t *testing.T) {
	m := NewManager()
	pol := &config.Policy{
		Domain: &config.DomainPolicy{
			Domains: []string{
				"api.*",                 // 前缀
				"*evil.com",             // 宽松后缀
				`/^internal-\d+\.corp$/`, // 正则
			},
			ListType:          "blacklist",
			IncludeSubdomains: false,
		},
	}
	if err := m.ApplyPolicy(pol); err != nil {
		t.Fatalf("ApplyPolicy 失败: %v", err)
	}
	// 前缀命中
	if perm, _ := m.CheckDomain("api.example.com"); perm != types.Denied {
		t.Errorf("api.example.com 应 Denied，得到 %s", perm)
	}
	// 宽松后缀命中（含主域）
	if perm, _ := m.CheckDomain("evil.com"); perm != types.Denied {
		t.Errorf("evil.com 应 Denied，得到 %s", perm)
	}
	// 正则命中
	if perm, _ := m.CheckDomain("internal-42.corp"); perm != types.Denied {
		t.Errorf("internal-42.corp 应 Denied，得到 %s", perm)
	}
	// 无关域名放行
	if perm, _ := m.CheckDomain("safe.org"); perm != types.Allowed {
		t.Errorf("safe.org 应 Allowed，得到 %s", perm)
	}
}

// TestApplyPolicy_IPInterval 验证 IP 区间语法经 JSON Policy 端到端可用
func TestApplyPolicy_IPInterval(t *testing.T) {
	m := NewManager()
	pol := &config.Policy{
		IP: &config.IPPolicy{
			Ranges:   []string{"192.168.1.10-192.168.1.20", "2001:db8::1-2001:db8::5"},
			ListType: "blacklist",
		},
	}
	if err := m.ApplyPolicy(pol); err != nil {
		t.Fatalf("ApplyPolicy 失败: %v", err)
	}
	if perm, _ := m.CheckIP("192.168.1.15"); perm != types.Denied {
		t.Errorf("192.168.1.15 应 Denied，得到 %s", perm)
	}
	if perm, _ := m.CheckIP("192.168.1.25"); perm != types.Allowed {
		t.Errorf("192.168.1.25 应 Allowed，得到 %s", perm)
	}
	if perm, _ := m.CheckIP("2001:db8::3"); perm != types.Denied {
		t.Errorf("2001:db8::3 应 Denied，得到 %s", perm)
	}
}
```

**注意**：执行者确认 policy_test.go 顶部已 import `config` 与 `types`（调研显示已 import）。若 `errors` 未 import 且测试用到则补；本测试未用 errors。

- [ ] **Step 2: 验证 Policy 端到端**
Run: `go test ./pkg/acl/ -run 'TestApplyPolicy_DomainPatterns|TestApplyPolicy_IPInterval' -v`
Expected:
  - Exit code: 0
  - Output contains: "--- PASS"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 3: 全量回归**
Run: `go test ./... 2>&1 | tail -8`
Expected:
  - Exit code: 0
  - 全 ok 无 FAIL

- [ ] **Step 4: 提交**
Run: `git add pkg/acl/policy_test.go && git commit -m "test(acl): cover domain patterns and IP interval via JSON Policy end-to-end"`

---

### Task 5: 示例与文档

**Depends on:** Task 4
**Files:**
- Create: `examples/12_domain_pattern_acl/main.go`
- Create: `examples/13_ip_range_acl/main.go`
- Modify: `README.md`、`.gitignore`

- [ ] **Step 1: 创建域名模式匹配示例 — 演示前缀/后缀/正则**
文件: `examples/12_domain_pattern_acl/main.go`（新建）

```go
package main

import (
	"errors"
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
	fmt.Println("===== 域名模式匹配 ACL 示例 =====")

	m := acl.NewManager()
	// 前缀 api.* + 宽松后缀 *evil.com + 正则 /internal-\d+\.corp/
	m.SetDomainACL([]string{
		"api.*",
		"*evil.com",
		`/^internal-\d+\.corp$/`,
	}, types.Blacklist, false)

	testDomains := []string{
		"api.example.com",    // 前缀命中
		"api.sub.example.com", // 前缀多层命中
		"evil.com",           // 宽松后缀含主域
		"sub.evil.com",       // 宽松后缀子域
		"internal-7.corp",    // 正则命中
		"internal-x.corp",   // 正则不命中
		"safe.org",           // 无关放行
	}
	fmt.Println("\n测试结果:")
	for _, d := range testDomains {
		perm, err := m.CheckDomain(d)
		if err != nil {
			if errors.Is(err, types.ErrNoACL) {
				fmt.Printf("  %s: 未配置域名ACL\n", d)
			} else {
				fmt.Printf("  %s: 检查失败 - %v\n", d, err)
			}
			continue
		}
		if perm == types.Allowed {
			fmt.Printf("  %s: 允许访问 ✓\n", d)
		} else {
			fmt.Printf("  %s: 拒绝访问 ✗\n", d)
		}
	}
}
```

- [ ] **Step 2: 创建 IP 区间示例 — 演示 start-end 与 IPv6 区间**
文件: `examples/13_ip_range_acl/main.go`（新建）

```go
package main

import (
	"errors"
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
	fmt.Println("===== IP 区间 ACL 示例 =====")

	m := acl.NewManager()
	// IPv4 区间 + IPv6 区间 + CIDR 混合
	if err := m.SetIPACL([]string{
		"192.168.1.10-192.168.1.20",
		"2001:db8::1-2001:db8::5",
		"10.0.0.0/8",
	}, types.Blacklist); err != nil {
		fmt.Printf("配置失败: %v\n", err)
		return
	}

	testIPs := []string{
		"192.168.1.15",  // IPv4 区间命中
		"192.168.1.25",  // IPv4 区间外
		"2001:db8::3",   // IPv6 区间命中
		"2001:db8::6",   // IPv6 区间外
		"10.1.2.3",      // CIDR 命中
		"8.8.8.8",       // 无关放行
	}
	fmt.Println("\n测试结果:")
	for _, ip := range testIPs {
		perm, err := m.CheckIP(ip)
		if err != nil && !errors.Is(err, types.ErrNoACL) {
			fmt.Printf("  %s: 检查失败 - %v\n", ip, err)
			continue
		}
		if perm == types.Allowed {
			fmt.Printf("  %s: 允许访问 ✓\n", ip)
		} else {
			fmt.Printf("  %s: 拒绝访问 ✗\n", ip)
		}
	}
}
```

- [ ] **Step 3: 验证两个示例运行**
Run: `cd examples/12_domain_pattern_acl && go run main.go ; cd ../13_ip_range_acl && go run main.go`
Expected:
  - Exit code: 0
  - 示例 12 输出含 "拒绝访问 ✗"（api.example.com）与 "允许访问 ✓"（safe.org）
  - 示例 13 输出含 "拒绝访问 ✗"（192.168.1.15）与 "允许访问 ✓"（8.8.8.8）
  - expected-output 注释块以**实际运行输出**为准（执行者运行后填入）

**注意**：执行者运行示例后，将真实输出写入文件末尾的 `/* 预期输出: ... */` 注释块（参考 examples/09 的风格），不得臆测。

- [ ] **Step 4: 修改 README — 新增匹配维度说明章节**
文件: `README.md`（在"### 域名控制"小节追加前缀/后缀/正则说明；在"### IP控制"小节追加区间说明；示例表格追加两行）

域名控制小节追加：
```markdown
// 前缀 api.* 匹配以 api. 开头的域名（不含主域）
// 宽松后缀 *example.com 匹配任意以 example.com 结尾者（含主域，区别于 *.example.com 仅子域）
// 正则 /pattern/ 按声明顺序匹配（基于 RE2，无回溯）
manager.SetDomainACL([]string{"api.*", "*evil.com", `/^internal-\d+\.corp$/`}, types.Blacklist, false)
```

IP 控制小节追加：
```markdown
// IP 区间 start-end 覆盖闭区间，自动按字节边界合并为 CIDR
manager.SetIPACL([]string{"192.168.1.10-192.168.1.20", "2001:db8::1-2001:db8::5"}, types.Blacklist)
```

示例表格（09 行之后）追加：
```
| **域名模式匹配** | 演示前缀/宽松后缀/正则维度 | [查看示例](examples/12_domain_pattern_acl/) |
| **IP 区间 ACL** | 演示 start-end 区间与 IPv6 区间 | [查看示例](examples/13_ip_range_acl/) |
```

**注意**：执行者先读 README 确认插入点（"### 域名控制"约在 :184，"### IP控制"约在 :197，示例表格 09 行约在 :318）。使用真实 API 大小写（SetDomainACL/SetIPACL）。

- [ ] **Step 5: 修改 .gitignore — 追加两个示例二进制**
文件: `.gitignore`（在 /11_ipv6_subnet_acl 之后追加）

```text
/12_domain_pattern_acl
/13_ip_range_acl
```

- [ ] **Step 6: 全量回归**
Run: `go build ./... && go test ./... 2>&1 | tail -8 && gofmt -l examples/12_domain_pattern_acl/main.go examples/13_ip_range_acl/main.go`
Expected:
  - Exit code: 0
  - gofmt 输出为空
  - go test 全 ok 无 FAIL

- [ ] **Step 7: 提交**
Run: `git add examples/12_domain_pattern_acl/main.go examples/13_ip_range_acl/main.go README.md .gitignore && git commit -m "docs: add domain pattern matching and IP interval examples with README sections"`

---

## 向后兼容性说明

本 Plan 全部为**纯增强**，不改变任何既有行为：

- 域名侧新增 `prefixes`/`looseSuffixes`/`regexes` 三张独立表，现有 `domains`/`domainSet`/`wildcardSuffixes` 行为字节不变；`*.example.com`（仅子域）语义保持。
- IP 侧 `parseIPRange` 未改动，新增 `parseIPRangeList` 仅在 `Add` 层分流；单 IP 与 CIDR 输入仍走原 `parseIPRange`。
- `MutableACL` 接口契约（`Check`/`GetListType`/`Add`/`Remove`/`GetRules`）与所有既有方法签名未变。
- 新语法（前缀 `api.*`、宽松后缀 `*x`、正则 `/re/`、区间 `a-b`）此前会被当作字面普通规则存入主表，现改为按语义匹配——对刻意以这些字面形式作规则的调用方属行为变化，但此类用法非实际用例。

`NewDomainACL`/`NewIPACL` 构造函数签名不变；`Add` 对无效正则返回 error 符合既有「无效输入返回 error」契约。

---

## 实现执行结果（2026-07-16 执行记录）

5 个 Task 全部经 subagent-driven-development 两阶段审查（spec → quality）闭环完成，9 个提交落在 `feat/acl-access-control-hardening` 分支。执行中对 Plan 原文做了以下**关键修正**（均经审查确认合理）：

1. **宽松后缀改为标签边界匹配**（Task 1）：Plan 原文 `HasSuffix(domain, suffix)` 会误命中 `notevil.com`，与测试期望矛盾。实现改为 `domain == suffix || strings.HasSuffix(domain, "."+suffix)`，含主域且不误伤相邻域名。
2. **正则绕过 normalizeDomain**（Task 2）：真实 `normalizeDomain` 把 `/re/` 的首 `/` 当路径分隔符截断成空串，且 `ToLower` 破坏大小写敏感转义。正则分流移到 normalize 之前，按原文编译。
3. **正则匹配小写域名契约**（Task 2）：`Check` 先 `normalizeDomain` 小写化待查域名，故正则匹配小写域名主体——这是域名大小写不敏感（DNS 规范）的后果。补 `TestDomainACL_RegexMatchesLowercasedDomain` 固化此契约，README 提示用户正则不应依赖 `[A-Z]`。
4. **区间检测用 `Count("-")==1`**（Task 3）：Plan 原文 `Contains("-")` 会把 `not-an-ip`（含多 `-`）误判为区间破坏 `ErrInvalidIP` 契约。改为恰好一个 `-`。
5. **rangeToCIDRs 全零起点修复**（Task 3）：`big.Int.TrailingZeroBits()` 对 0 返回 0（非 bitLen），导致 `0.0.0.0-255.255.255.255` 逐地址展开（2^32 灾难）。改为 `cur.Sign()==0` 时 `trailing=bitLen`，全空间展开为单条 `/0`。
6. **Remove 区间规范化统一**（Task 3）：Remove 原用 `normalizeIPString`，与 Add 区间 Original（两端经 `net.ParseIP().String()` 规范化）路径不一致，导致含空格/IPv6 等价形式区间无法移除。改为 Remove 走 `parseIPRangeList` 取 Original 作 key。
7. **GetIPRanges 区间去重**（Task 3）：区间展开的多条 CIDR 共享同一 Original，`GetIPRanges` 加去重避免返回重复串。

**最终质量门禁**：`go build` / `go test ./...` / `go test -race ./...` / `go vet ./...` / `gofmt -l` 全绿；examples/12、13 真实运行输出与预期一致；final reviewer 评估 READY_TO_FINALIZE，无遗留问题。
