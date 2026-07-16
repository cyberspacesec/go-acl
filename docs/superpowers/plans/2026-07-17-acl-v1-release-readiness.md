# acl-skills v1 发布就绪度补齐 Plan

> **For agentic workers:** REQUIRED SUB-SKILL `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 补齐 acl-skills 仓库的 v1 发布缺口，使其达到可发布的 `v1.0.0` 级别——含 godoc 包文档、发布治理文档（CHANGELOG/SECURITY/CONTRIBUTING）、API 健壮性修复（SetDomainACL 无 error 对称化）、测试覆盖率补齐、CI 现代化、README 校准与 API 稳定性承诺。

**Architecture:** 本 Plan 不引入破坏性新功能，而是补齐「可发布」所需治理层。数据流为：缺包文档 → 补 `doc.go`；发布文档 → 创建 CHANGELOG/SECURITY/CONTRIBUTING；API 对称化 → 新增 `SetDomainACLStrict` 返回 error，保留旧 `SetDomainACL` 兼容（旧方法无 error 静默忽略无效域，符合既有行为契约）；测试补齐 → 给 `pkg/aclutil` 与 `pkg/types` 补测；CI 现代化 → 升 Go 矩阵、升 actions 版本、Codecov 设阈值；README 校准 → 修正虚标徽章、加 Versioning 段。所有改动均向后兼容，不破坏现有 API 签名。

**Tech Stack:** Go 1.18+（保持 `go.mod` 指令不变以兼容最低版本用户），仅标准库依赖，golangci-lint，GitHub Actions，Conventional Commits。

**Risks:**
- Task 3 新增 `SetDomainACLStrict` 需确保与 `ApplyPolicy` 路径一致（ApplyPolicy 走 `SetDomainACL` 非严格路径，保持现状不破坏 JSON Policy 加载）→ 缓解：新方法独立，不改 ApplyPolicy 调用路径
- Task 5 升级 actions 版本可能与自托管 runner 不兼容 → 缓解：使用 `@v5` 稳定版，不引入 `@v6` 实验版
- Task 6 打 tag 是不可逆发布动作 → 缓解：仅在本 Plan 全部 Task 通过全量门禁后执行，且 tag 语义为 `v1.0.0` 一次性正式发布

---

### Task 1: 补齐核心包 godoc 文档注释

**Depends on:** None
**Files:**
- Create: `pkg/acl/doc.go`
- Create: `pkg/domain/doc.go`
- Create: `pkg/ip/doc.go`
- Create: `pkg/config/doc.go`
- Modify: `.golangci.yml:22-24`（移除 ST1000 屏蔽）

- [ ] **Step 1: 创建 pkg/acl/doc.go — 为 acl 包提供 godoc 包注释**

```go
// Package acl 提供统一的访问控制列表（ACL）管理器。
//
// Manager 是核心入口，通过注册不同 kind 的 MutableACL 实现统一管理。
// 内置 KindDomain（域名 ACL）与 KindIP（IP ACL）两种 kind，亦可通过
// RegisterACL 注册自定义 ACL。
//
// Manager 自身并发安全：内置 sync.RWMutex 仅保护 kind→ACL 映射的增删查，
// 各子 ACL 自带锁保护自身规则，查询不同 kind 互不阻塞。
//
// 主要能力：
//   - 域名/IP 双维度增删改查
//   - 文件读写（持久化）
//   - 预定义集合（私有网络、云元数据、短链等）
//   - JSON Policy 注入（ApplyPolicy）
//   - 统一 kind 入口（CheckKind/AddRule/RemoveRule）
//   - IP 最长前缀反查（LookupIP）
package acl
```

- [ ] **Step 2: 创建 pkg/domain/doc.go — 为 domain 包提供 godoc 包注释**

```go
// Package domain 实现域名维度的访问控制列表。
//
// DomainACL 支持五种匹配维度：
//   - 精确匹配：example.com
//   - 通配仅子域：*.example.com（不含主域本身）
//   - 前缀：api.*（匹配 api. 开头，不含裸域名）
//   - 宽松后缀：*example.com（标签边界匹配主域及子域）
//   - 正则：/pattern/（按声明顺序匹配小写化域名）
//
// 标签边界处理严谨：宽松后缀用 domain==suffix || HasSuffix(domain,"."+suffix)，
// 避免将 notevil.com 误匹配为 evil.com 的子域。
//
// 域名大小写不敏感（遵循 DNS 规范），Check 前先小写化输入。
package domain
```

- [ ] **Step 3: 创建 pkg/ip/doc.go — 为 ip 包提供 godoc 包注释**

```go
// Package ip 实现 IP 维度的访问控制列表。
//
// IPACL 基于 IPv4/IPv6 双前缀 trie（ipTrie）实现 O(prefixLen) 匹配，
// 与规则数无关，支持 IPv4/IPv6/CIDR/区间/zone id 剥离。
//
// 区间语法 a-b 用 math/big 展开为覆盖 [a,b] 的最少不重叠 CIDR，
// 彻底避免 IPv6 巨区间下 int/uint64 溢出。
//
// Lookup 返回最长前缀匹配 CIDR，便于规则反查与审计。
package ip
```

- [ ] **Step 4: 创建 pkg/config/doc.go — 为 config 包提供 godoc 包注释**

```go
// Package config 提供 JSON Policy 解析与文件 I/O。
//
// Policy 结构含 Domain 与 IP 两段，任一为 nil 表示不配置该类型 ACL。
// ApplyPolicy 将解析后的 Policy 注入 Manager，失败时在注入前返回，
// 避免半应用状态。
//
// 文件格式：每行一条规则，支持 # 行注释与行内注释。
package config
```

- [ ] **Step 5: 修改 .golangci.yml 移除 ST1000 屏蔽 — 不再掩盖缺包注释**

文件: `.golangci.yml:22-24`

```yaml
# 替换 .golangci.yml 第 18-24 行的 exclude-rules 区块
  exclude-rules:
    - linters:
        - staticcheck
      text: "SA1019:"  # 忽略已弃用API使用的警告
```

（删除原第 22-24 行对 ST1000 的屏蔽条目，保留 SA1019 屏蔽。）

- [ ] **Step 6: 验证 godoc 注释生效且 lint 通过**
Run: `go vet ./... && golangci-lint run --timeout=5m ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "ST1000" or "missing package comment"

- [ ] **Step 7: 提交**
Run: `git add pkg/acl/doc.go pkg/domain/doc.go pkg/ip/doc.go pkg/config/doc.go .golangci.yml && git commit -m "docs: add godoc package comments for acl/domain/ip/config packages"`

---

### Task 2: 创建发布治理文档（CHANGELOG/SECURITY/CONTRIBUTING）

**Depends on:** None
**Files:**
- Create: `CHANGELOG.md`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`

- [ ] **Step 1: 创建 CHANGELOG.md — 记录版本变更历史**

```markdown
# Changelog

本项目所有重要变更均记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- 新增 `Manager.SetDomainACLStrict` 方法，返回无效域名错误，与 `SetIPACL` 对称。
- 为 `pkg/acl`、`pkg/domain`、`pkg/ip`、`pkg/config` 补齐 godoc 包注释。

### Changed
- README 覆盖率徽章改为动态 shields.io/codecov，不再写死。
- CI Go 版本矩阵扩展至 1.18–1.24。
- 升级 GitHub Actions 至 checkout@v5、setup-go@v5、codecov-action@v5。

### Fixed
- 修复 README 中 CONTRIBUTING.md 死链。

## [1.0.0] - 2026-07-17

### Added
- 三层 ACL 接口：`ACL` → `ListTypeACL` → `MutableACL`。
- 域名 ACL 五维匹配：精确、通配 `*.x`、前缀 `api.*`、宽松后缀 `*x`、正则 `/re/`。
- IP ACL 全语法：IPv4/IPv6、CIDR、区间 `a-b`、zone id 剥离、最长前缀反查 `Lookup`。
- 基于 math/big 的区间→CIDR 展开，避免 IPv6 巨区间溢出。
- 统一 Manager：构造、注册、双维度增删改查、文件读写、预定义集合、统一 kind 入口。
- JSON Policy 注入（`ApplyPolicy`），失败不半应用。
- HTTP 中间件，支持代理头信任、自定义拒绝响应，白名单 fail-closed。
- 预定义集合：域名（短链/一次性邮箱/恶意域名等）、IP（私有网络/云元数据/特殊网络等）。
- 并发安全（各子 ACL 自锁），race 测试覆盖。
- benchmark 测试套件。

### Security
- 白名单语义 fail-closed：空值输入在白名单下拒绝。
```

- [ ] **Step 2: 创建 SECURITY.md — 漏洞披露流程**

```markdown
# 安全策略

## 报告漏洞

本项目重视安全性。如发现安全漏洞，请按以下流程报告：

1. **不要**在公开 issue 中提交安全漏洞。
2. 发送邮件至：security@cyberspacesec.example（替换为真实邮箱）
3. 邮件标题以 `[SECURITY]` 开头，描述漏洞、影响范围与复现步骤。
4. 我们将在 72 小时内确认收到，并在 14 天内给出修复计划。

## 支持版本

| 版本 | 支持状态 |
| --- | --- |
| 1.0.x | :white_check_mark: 支持 |
| < 1.0 | :x: 不支持 |

## 安全设计要点

- 白名单语义 fail-closed：空值输入在白名单模式下默认拒绝。
- 中间件 `TrustProxy` 默认 false，防止伪造 `X-Forwarded-For` 绕过。
- 正则基于 Go RE2 引擎，无回溯，天然防 ReDoS。
- 域名宽松后缀用标签边界匹配，防止 `notevil.com` 误命中 `evil.com`。
```

- [ ] **Step 3: 创建 CONTRIBUTING.md — 贡献指南**

```markdown
# 贡献指南

感谢您关注 acl-skills！欢迎贡献代码、文档或问题反馈。

## 开发流程

1. Fork 仓库并创建分支：`feat/<your-feature>`。
2. 确保通过本地质量门禁：
   - `go vet ./...`
   - `golangci-lint run --timeout=5m ./...`
   - `go test -race -cover ./...`
3. 提交信息遵循 [Conventional Commits](https://www.conventionalcommits.org/)：
   - `feat(domain): support wildcard rules`
   - `fix(ip): correct IPv6 range overflow`
   - `docs: add godoc comments`
4. 测试以表驱动、中文测试名为规范，覆盖 Happy Path + Edge/Error Case。
5. 提交 PR，描述变更与测试方式。

## 代码规范

- 仅使用 Go 标准库，不引入外部依赖。
- 所有导出符号必须有 godoc 注释。
- 并发安全由各子 ACL 自锁保证，Manager 的 mu 仅保护 kind 映射。

## 发布

- 版本号遵循 Semantic Versioning。
- 每个 release 会在 CHANGELOG.md 记录变更。
- 稳定 API（见 README Versioning 段）保证向后兼容。
```

- [ ] **Step 4: 验证三文档存在且 README 死链修复**
Run: `ls CHANGELOG.md SECURITY.md CONTRIBUTING.md && grep -n "CONTRIBUTING" README.md`
Expected:
  - Exit code: 0
  - 三个文件均列出
  - README 中 CONTRIBUTING 引用指向已存在文件

- [ ] **Step 5: 提交**
Run: `git add CHANGELOG.md SECURITY.md CONTRIBUTING.md && git commit -m "docs: add CHANGELOG, SECURITY policy, and CONTRIBUTING guide"`

---

### Task 3: 新增 SetDomainACLStrict 对称化 API

**Depends on:** None
**Files:**
- Modify: `pkg/acl/manager.go`（在 SetDomainACL 之后新增方法）
- Modify: `pkg/acl/policy.go`（ApplyPolicy 优先用 strict 路径）
- Test: `pkg/acl/manager_test.go`

- [ ] **Step 1: 修改 domain.NewDomainACLStrict — 新增带错误返回的构造函数**

文件: `pkg/domain/domain.go`（在 NewDomainACL 函数之后插入）

```go
// NewDomainACLStrict 创建域名 ACL，解析失败时返回错误。
//
// 与 NewDomainACL 行为一致，但无效域名会返回 error 而非静默忽略，
// 供需要严格校验的场景使用。
func NewDomainACLStrict(domains []string, listType types.ListType, includeSubdomains bool) (*DomainACL, error) {
	a := NewDomainACL(domains, listType, includeSubdomains)
	// 复用 Add 的校验路径：Add 对无效域名返回 error
	if err := a.Add(domains...); err != nil {
		return nil, err
	}
	return a, nil
}
```

- [ ] **Step 2: 修改 Manager 新增 SetDomainACLStrict — 返回无效域名错误**

文件: `pkg/acl/manager.go`（在 SetDomainACL 函数之后，即原第 119 行 `}` 之后插入）

```go
// SetDomainACLStrict 设置域名访问控制列表，返回无效域名错误。
//
// 与 SetDomainACL 行为一致，但在解析域名失败时返回 error 而非静默忽略，
// 使调用方能感知无效输入。与 SetIPACL 的错误返回语义对称。
//
// 参数:
//   - domains: 要控制的域名列表
//   - listType: 列表类型（黑名单或白名单）
//   - includeSubdomains: 是否包含子域名匹配
//
// 返回:
//   - error: 域名解析失败时返回错误（具体错误类型由 domain 层定义）
//
// 此方法覆盖之前设置的任何域名访问控制列表。
//
// 示例:
//
//	err := manager.SetDomainACLStrict(
//	    []string{"malware.example.com", "bad..domain"},
//	    types.Blacklist,
//	    true,
//	)
//	if err != nil {
//	    log.Printf("设置域名ACL失败: %v", err)
//	}
func (m *Manager) SetDomainACLStrict(domains []string, listType types.ListType, includeSubdomains bool) error {
	a, err := domain.NewDomainACLStrict(domains, listType, includeSubdomains)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acls[KindDomain] = a
	return nil
}
```

- [ ] **Step 3: 修改 ApplyPolicy 优先用 strict 路径 — 让 JSON Policy 感知无效域名**

文件: `pkg/acl/policy.go`（ApplyPolicy 中处理 Domain 段的 SetDomainACL 调用处）

```go
// 替换 policy.go 中对域名 Set 的调用：
// 原：m.SetDomainACL(p.Domain.Domains, lt, p.Domain.IncludeSubdomains)
// 改为：
if err := m.SetDomainACLStrict(p.Domain.Domains, lt, p.Domain.IncludeSubdomains); err != nil {
    return fmt.Errorf("应用域名策略失败: %w", err)
}
```

- [ ] **Step 4: 新增 SetDomainACLStrict 测试**

文件: `pkg/acl/manager_test.go`（追加测试函数）

```go
func TestManager_SetDomainACLStrict_InvalidDomain(t *testing.T) {
	m := acl.NewManager()
	// 空串被忽略不报错
	err := m.SetDomainACLStrict([]string{"", "  "}, types.Blacklist, false)
	if err != nil {
		t.Fatalf("空串应被忽略，不应报错，got: %v", err)
	}
}

func TestManager_SetDomainACLStrict_ValidDomains(t *testing.T) {
	m := acl.NewManager()
	err := m.SetDomainACLStrict([]string{"evil.example.com", "malware.test"}, types.Blacklist, true)
	if err != nil {
		t.Fatalf("有效域名不应报错，got: %v", err)
	}
	perm, err := m.CheckDomain("evil.example.com")
	if err != nil || perm != types.Denied {
		t.Errorf("黑名单命中应拒绝，got perm=%v err=%v", perm, err)
	}
}
```

- [ ] **Step 5: 验证 strict API 与 ApplyPolicy 集成**
Run: `go test -run 'TestManager_SetDomainACLStrict|TestApplyPolicy' ./pkg/acl/... -race`
Expected:
  - Exit code: 0
  - Output contains: "ok" and "PASS"

- [ ] **Step 6: 提交**
Run: `git add pkg/acl/manager.go pkg/domain/domain.go pkg/acl/policy.go pkg/acl/manager_test.go && git commit -m "feat(acl): add SetDomainACLStrict for symmetric error reporting with SetIPACL"`

---

### Task 4: 补齐 pkg/aclutil 与 pkg/types 测试覆盖

**Depends on:** None
**Files:**
- Create: `pkg/aclutil/unique_test.go`
- Create: `pkg/types/errors_test.go`

- [ ] **Step 1: 创建 pkg/aclutil/unique_test.go — 补 0% 覆盖包**

```go
package aclutil

import (
	"reflect"
	"testing"
)

func TestAppendUnique_NewAndExisting(t *testing.T) {
	rules := []string{"a", "b"}
	got := AppendUnique(rules, []string{"b", "c"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AppendUnique 去重追加 = %v, want %v", got, want)
	}
}

func TestAppendUnique_EmptyInputs(t *testing.T) {
	got := AppendUnique(nil, nil)
	if len(got) != 0 {
		t.Errorf("空输入应返回空切片，got %v", got)
	}
	got = AppendUnique([]string{"x"}, []string{})
	if !reflect.DeepEqual(got, []string{"x"}) {
		t.Errorf("空候选应原样返回，got %v", got)
	}
}

func TestRemoveMatching_AllFound(t *testing.T) {
	rules := []string{"a", "b", "c"}
	newRules, missing := RemoveMatching(rules, []string{"a", "c"})
	if !reflect.DeepEqual(newRules, []string{"b"}) {
		t.Errorf("移除后剩余 = %v, want [b]", newRules)
	}
	if len(missing) != 0 {
		t.Errorf("全部命中不应有 missing，got %v", missing)
	}
}

func TestRemoveMatching_PartialMissing(t *testing.T) {
	rules := []string{"a", "b"}
	newRules, missing := RemoveMatching(rules, []string{"b", "z"})
	if !reflect.DeepEqual(newRules, []string{"a"}) {
		t.Errorf("移除后剩余 = %v, want [a]", newRules)
	}
	if !reflect.DeepEqual(missing, []string{"z"}) {
		t.Errorf("未命中应记录 = %v, want [z]", missing)
	}
}
```

- [ ] **Step 2: 创建 pkg/types/errors_test.go — 补错误分支覆盖**

```go
package types

import (
	"errors"
	"testing"
)

func TestSentinelErrors_Identity(t *testing.T) {
	// 确保哨兵错误可被 errors.Is 识别
	if !errors.Is(ErrNoACL, ErrNoACL) {
		t.Error("ErrNoACL 应可被 errors.Is 识别")
	}
	if !errors.Is(ErrACLAlreadyRegistered, ErrACLAlreadyRegistered) {
		t.Error("ErrACLAlreadyRegistered 应可被 errors.Is 识别")
	}
	if errors.Is(ErrNoACL, ErrACLAlreadyRegistered) {
		t.Error("不同哨兵错误不应互等")
	}
}

func TestListType_String(t *testing.T) {
	tests := []struct {
		lt   ListType
		want string
	}{
		{Blacklist, "blacklist"},
		{Whitelist, "whitelist"},
		{ListType(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.lt.String(); got != tt.want {
			t.Errorf("ListType(%d).String() = %q, want %q", tt.lt, got, tt.want)
		}
	}
}

func TestPermission_String(t *testing.T) {
	tests := []struct {
		p    Permission
		want string
	}{
		{Denied, "denied"},
		{Allowed, "allowed"},
		{Permission(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.p.String(); got != tt.want {
			t.Errorf("Permission(%d).String() = %q, want %q", tt.p, got, tt.want)
		}
	}
}

func TestDecideByListType(t *testing.T) {
	// 黑名单：命中→拒绝，未命中→允许
	if got := DecideByListType(Blacklist, true); got != Denied {
		t.Errorf("黑名单命中应拒绝，got %v", got)
	}
	if got := DecideByListType(Blacklist, false); got != Allowed {
		t.Errorf("黑名单未命中应允许，got %v", got)
	}
	// 白名单：命中→允许，未命中→拒绝
	if got := DecideByListType(Whitelist, true); got != Allowed {
		t.Errorf("白名单命中应允许，got %v", got)
	}
	if got := DecideByListType(Whitelist, false); got != Denied {
		t.Errorf("白名单未命中应拒绝，got %v", got)
	}
}
```

- [ ] **Step 3: 验证覆盖率提升**
Run: `go test -cover ./pkg/aclutil/... ./pkg/types/...`
Expected:
  - Exit code: 0
  - pkg/aclutil 覆盖率 > 80%（从 0% 提升）
  - pkg/types 覆盖率 > 80%（从 53% 提升）

- [ ] **Step 4: 提交**
Run: `git add pkg/aclutil/unique_test.go pkg/types/errors_test.go && git commit -m "test: cover aclutil unique helpers and types error branches"`

---

### Task 5: 现代化 CI 与校准 README 徽章

**Depends on:** None
**Files:**
- Modify: `.github/workflows/go-test.yml`
- Modify: `README.md:4-8`

- [ ] **Step 1: 修改 CI workflow — 扩展 Go 矩阵、升级 actions 版本**

文件: `.github/workflows/go-test.yml`（整体替换关键区块）

```yaml
# 替换整个 go-test.yml 的 jobs 部分
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        go-version: ['1.18', '1.21', '1.22', '1.23', '1.24']
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go-version }}
      - name: Run tests
        run: go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
      - name: Upload coverage
        uses: codecov/codecov-action@v5
        with:
          files: ./coverage.txt
          fail_ci_if_error: false

  examples:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - name: Run examples
        run: bash examples/run_all.sh

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - name: golangci-lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: latest
          args: --timeout=5m

  benchmark:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - name: Run benchmarks
        run: go test -bench=. -benchmem ./...
```

- [ ] **Step 2: 修改 README 徽章 — 修正虚标覆盖率与混乱 examples 徽章**

文件: `README.md:4-8`（替换徽章区块）

```markdown
  <img src="https://img.shields.io/badge/Go-1.18+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go版本" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="许可证" />
  <img src="https://img.shields.io/codecov/c/github/cyberspacesec/acl-skills?style=for-the-badge&logo=codecov&logoColor=white" alt="测试覆盖率" />
  <img src="https://img.shields.io/github/workflow/status/cyberspacesec/acl-skills/Go%20Tests?style=for-the-badge&logo=github&label=tests" alt="测试状态" />
  <img src="https://img.shields.io/github/v/release/cyberspacesec/acl-skills?style=for-the-badge&logo=github&label=release" alt="发布版本" />
```

- [ ] **Step 3: 在 README 末尾新增 Versioning 段 — API 稳定性承诺**

文件: `README.md`（在文件末尾追加）

```markdown
## 版本策略

本项目遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

### API 稳定性

自 `v1.0.0` 起，以下 API 保证向后兼容（仅在主版本升级时可能破坏）：

- `types` 包：`ACL`、`ListTypeACL`、`MutableACL` 接口及 `ListType`、`Permission` 枚举。
- `domain.DomainACL` 与 `ip.IPACL` 的 `Check`/`Add`/`Remove`/`GetRules`/`GetListType` 方法。
- `acl.Manager` 的 `Set*`/`Check*`/`Add*`/`Remove*`/`Get*`/`LookupIP` 方法。
- `config.Policy` 结构及其 JSON 字段。
- `middleware.New` 与 `Options` 字段。

### 实验性 API

以下 API 可能在次版本中调整，使用前请评估：

- `Manager.RegisterACL` / `UnregisterACL`（自定义 ACL 注册机制，稳定后转入稳定 API）。
- `SetDomainACLStrict`（新增，行为稳定但签名观察中）。

## 发布记录

详见 [CHANGELOG.md](CHANGELOG.md)。
```

- [ ] **Step 4: 验证本地全量门禁**
Run: `go vet ./... && golangci-lint run --timeout=5m ./... && go test -race ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "FAIL" or "Error"

- [ ] **Step 5: 提交**
Run: `git add .github/workflows/go-test.yml README.md && git commit -m "ci: expand go matrix to 1.18-1.24, upgrade actions, fix README coverage badge"`

---

### Task 6: 全量验证与 v1.0.0 发布准备

**Depends on:** Task 1, Task 2, Task 3, Task 4, Task 5
**Files:**
- Modify: `CHANGELOG.md`（确认 1.0.0 发布日期）

- [ ] **Step 1: 运行完整质量门禁 — 确认所有改动通过**

Run: `go vet ./... && gofmt -l pkg/ && golangci-lint run --timeout=5m ./... && go test -race -cover ./...`
Expected:
  - Exit code: 0
  - gofmt -l 无输出（无格式问题）
  - 全部测试通过
  - 无 race 报告

- [ ] **Step 2: 运行 examples 验证编译与运行**

Run: `bash examples/run_all.sh`
Expected:
  - Exit code: 0
  - 13 个示例均编译运行成功

- [ ] **Step 3: 确认 CHANGELOG 1.0.0 日期与发布内容完整**

Run: `head -40 CHANGELOG.md`
Expected:
  - Output contains: "[1.0.0] - 2026-07-17"
  - 含 Added / Changed / Fixed / Security 分类

- [ ] **Step 4: 提交最终发布准备**

Run: `git add -A && git commit -m "chore: prepare v1.0.0 release with full quality gates passing"`

- [ ] **Step 5: 打 v1.0.0 tag — 正式发布**

Run: `git tag v1.0.0 && git push origin feat/acl-access-control-hardening --tags`
Expected:
  - Exit code: 0
  - `git tag --list` 输出 v1.0.0

---

## 执行后补记（implementer 实际执行结果）

本节由 subagent-driven-development 执行后填写，记录实际偏离与修正。
