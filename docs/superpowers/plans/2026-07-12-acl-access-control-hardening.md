# 域名+IP 访问控制工程化补全 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 补全 ACL 库在"按 IP、域名做访问控制"工程化层面的短板：为域名 ACL 增加文件持久化能力（对齐 IP ACL）、提供一份 JSON 即可同时配置域名+IP 规则的统一配置加载、并提供开箱即用的 `net/http` 访问控制中间件，让用户"一份配置 + 一行中间件"即可完成按 IP/域名的访问控制。

**Architecture:** 数据流：JSON 配置文件 → `config.LoadPolicy` 解析为 `Policy` 结构 → 调用既有 `Manager.SetDomainACL`/`SetIPACL`/`SetIPACLWithDefaults` 注入规则 → HTTP 请求到达 `middleware.New` 包装的 handler → 中间件从 `http.Request` 提取客户端 IP（可选信任代理头）与目标 Host → 调用 `Manager.CheckIP`/`CheckDomain` → Denied 则返回 403，Allowed 则放行到下游 handler。域名文件 IO 复用既有 `config.ReadIPACL` 的解析风格（每行一条、`#` 注释）与 `SaveIPACLWithHeader` 的写入风格，保证 IP/域名两套文件 API 体验一致。

**Tech Stack:** Go 1.18+（标准库 `net/http`、`net`、`encoding/json`、`bufio`），无新增第三方依赖。模块路径 `github.com/cyberspacesec/acl-skills`。

**Risks:**
- Task 1 修改 `pkg/domain`：DomainACL 当前无 `SaveToFile`/`AddFromFile`，需新增方法而非改既有方法，避免破坏 `types.MutableACL` 接口契约 → 缓解：新增方法独立，不动 `Check`/`Add`/`Remove`/`GetRules`/`GetListType` 签名
- Task 3 在 `manager.go` 新增方法需与既有 `SetIPACLFromFile` 风格一致 → 缓解：复用既有 `domainACL()` 私有取值方法
- Task 4 HTTP 中间件从 `http.Request` 提取客户端真实 IP：误信 `X-Forwarded-For` 会绕过 IP 黑名单 → 缓解：提供 `TrustProxy bool` 开关，默认 `false` 保守地只取 `RemoteAddr`
- 统一 JSON 配置必须向后兼容现有命令式 API → 缓解：JSON 加载内部调用既有 `SetDomainACL`/`SetIPACL`，不替换任何既有方法

---

### Task 1: 域名 ACL 文件持久化

**Depends on:** None
**Files:**
- Create: `pkg/domain/file.go`
- Create: `pkg/domain/file_test.go`

- [ ] **Step 1: 创建 `pkg/domain/file.go` — 为 DomainACL 增加从文件加载、保存到文件、追加文件的能力**

```go
package domain

import (
	"github.com/cyberspacesec/acl-skills/pkg/config"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// NewDomainACLFromFile 从文件创建域名访问控制列表
//
// 参数:
//   - filePath: 包含域名列表的文件路径（每行一个域名，支持 # 注释与行内注释）
//   - listType: 列表类型（黑名单或白名单）
//   - includeSubdomains: 是否包含子域名匹配
//
// 返回:
//   - *DomainACL: 创建的域名访问控制列表
//   - error: config.ErrFileNotFound / config.ErrEmptyFile / 其他系统错误
//
// 文件格式与 config.ReadIPACL 相同（每行一条，# 开头注释，行内 # 后内容忽略，空行忽略）。
//
// 示例:
//
//	acl, err := domain.NewDomainACLFromFile("./domain_blacklist.txt", types.Blacklist, true)
func NewDomainACLFromFile(filePath string, listType types.ListType, includeSubdomains bool) (*DomainACL, error) {
	domains, err := config.ReadIPACL(filePath)
	if err != nil {
		return nil, err
	}
	return NewDomainACL(domains, listType, includeSubdomains), nil
}

// SaveToFile 将域名访问控制列表保存到文件
//
// 参数:
//   - filePath: 要保存的文件路径
//   - overwrite: 是否覆盖已存在的文件
//
// 返回:
//   - error: config.ErrFileExists / config.ErrFilePermission / 其他系统错误
//
// 生成的文件格式: 标题注释行 + 生成时间注释行 + 每行一个域名。
func (d *DomainACL) SaveToFile(filePath string, overwrite bool) error {
	var header string
	if d.listType == types.Blacklist {
		header = "Domain Blacklist - domains in this list will be denied access"
	} else {
		header = "Domain Whitelist - only domains in this list will be allowed access"
	}
	return config.SaveIPACLWithHeader(filePath, d.GetDomains(), header, overwrite)
}

// SaveToFileWithOverwrite 兼容旧版风格，默认覆盖已存在的文件
// 已废弃：请改用 SaveToFile
func (d *DomainACL) SaveToFileWithOverwrite(filePath string) error {
	return d.SaveToFile(filePath, true)
}

// AddFromFile 从文件添加域名到现有的访问控制列表
//
// 参数:
//   - filePath: 包含域名列表的文件路径
//
// 返回:
//   - error: config.ErrFileNotFound / config.ErrEmptyFile / 其他系统错误
//
// 与 NewDomainACLFromFile 不同，此方法将文件中的域名添加到现有列表，不替换原有内容。
func (d *DomainACL) AddFromFile(filePath string) error {
	domains, err := config.ReadIPACL(filePath)
	if err != nil {
		return err
	}
	return d.Add(domains...)
}
```

- [ ] **Step 2: 创建 `pkg/domain/file_test.go` — 覆盖文件加载、保存、追加、覆盖保护、注释解析**

```go
package domain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/config"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// writeTempFile 在临时目录写入内容并返回路径，测试结束自动清理
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	return p
}

func TestNewDomainACLFromFile(t *testing.T) {
	p := writeTempFile(t, "blacklist.txt", "# 域名黑名单\nbad.com\nphish.org # 钓鱼\n\nbad.com\n")
	acl, err := NewDomainACLFromFile(p, types.Blacklist, true)
	if err != nil {
		t.Fatalf("从文件创建域名 ACL 失败: %v", err)
	}
	got := acl.GetDomains()
	// 重复 bad.com 应被去重，注释与空行应被忽略
	if len(got) != 2 {
		t.Fatalf("期望 2 个域名，得到 %d: %v", len(got), got)
	}
	// 子域名应命中
	perm, err := acl.Check("sub.bad.com")
	if err != nil {
		t.Fatalf("Check 失败: %v", err)
	}
	if perm != types.Denied {
		t.Errorf("黑名单子域名应被 Denied，得到 %s", perm)
	}
}

func TestNewDomainACLFromFile_NotExist(t *testing.T) {
	_, err := NewDomainACLFromFile("/no/such/file.txt", types.Blacklist, false)
	if !errors.Is(err, config.ErrFileNotFound) {
		t.Errorf("期望 ErrFileNotFound，得到 %v", err)
	}
}

func TestNewDomainACLFromFile_Empty(t *testing.T) {
	p := writeTempFile(t, "empty.txt", "# 只有注释\n\n")
	_, err := NewDomainACLFromFile(p, types.Blacklist, false)
	if !errors.Is(err, config.ErrEmptyFile) {
		t.Errorf("期望 ErrEmptyFile，得到 %v", err)
	}
}

func TestDomainACL_SaveToFile(t *testing.T) {
	acl := NewDomainACL([]string{"save.com", "keep.org"}, types.Blacklist, true)
	p := filepath.Join(t.TempDir(), "out.txt")
	if err := acl.SaveToFile(p, true); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	// 重新加载应得到等价规则
	loaded, err := NewDomainACLFromFile(p, types.Blacklist, true)
	if err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if len(loaded.GetDomains()) != 2 {
		t.Errorf("回读后规则数期望 2，得到 %d", len(loaded.GetDomains()))
	}
	perm, _ := loaded.Check("x.save.com")
	if perm != types.Denied {
		t.Errorf("回读后子域名应 Denied，得到 %s", perm)
	}
}

func TestDomainACL_SaveToFile_NoOverwrite(t *testing.T) {
	acl := NewDomainACL([]string{"a.com"}, types.Blacklist, false)
	p := writeTempFile(t, "exists.txt", "existing\n")
	err := acl.SaveToFile(p, false) // 不覆盖
	if !errors.Is(err, config.ErrFileExists) {
		t.Errorf("期望 ErrFileExists，得到 %v", err)
	}
}

func TestDomainACL_AddFromFile(t *testing.T) {
	acl := NewDomainACL([]string{"base.com"}, types.Blacklist, false)
	p := writeTempFile(t, "more.txt", "more.com\n# 注释\n")
	if err := acl.AddFromFile(p); err != nil {
		t.Fatalf("AddFromFile 失败: %v", err)
	}
	got := acl.GetDomains()
	if len(got) != 2 {
		t.Fatalf("期望 2 个域名，得到 %d: %v", len(got), got)
	}
}
```

- [ ] **Step 3: 验证域名文件 IO**
Run: `go test ./pkg/domain/ -run 'File' -v`
Expected:
  - Exit code: 0
  - Output contains: "ok" 且各 Test* 子测试全部 PASS

- [ ] **Step 4: 提交**
Run: `git add pkg/domain/file.go pkg/domain/file_test.go && git commit -m "feat(domain): add file persistence (load/save/add-from-file) for DomainACL"`

---

### Task 2: 统一 JSON 策略配置加载

**Depends on:** None
**Files:**
- Create: `pkg/config/json.go`
- Create: `pkg/config/json_test.go`

- [ ] **Step 1: 创建 `pkg/config/json.go` — 定义 Policy 结构与 LoadPolicyFromBytes/LoadPolicyFromFile**

```go
package config

import (
	"encoding/json"
	"os"
)

// DomainPolicy 描述一份域名 ACL 配置
//
// ListType 取 "blacklist" 或 "whitelist"；IncludeSubdomains 控制子域名匹配。
type DomainPolicy struct {
	Domains            []string `json:"domains"`
	ListType           string   `json:"listType"`           // "blacklist" | "whitelist"
	IncludeSubdomains  bool     `json:"includeSubdomains"`
	// File 可选：从该文件加载域名规则，与 Domains 合并
	File string `json:"file,omitempty"`
}

// IPPolicy 描述一份 IP ACL 配置
//
// ListType 取 "blacklist" 或 "whitelist"；PredefinedSets 引用预定义集合名。
type IPPolicy struct {
	Ranges          []string `json:"ranges"`
	ListType        string   `json:"listType"` // "blacklist" | "whitelist"`
	PredefinedSets  []string `json:"predefinedSets,omitempty"`
	AllowPredefined bool     `json:"allowPredefined,omitempty"`
	// File 可选：从该文件加载 IP 规则，与 Ranges 合并
	File string `json:"file,omitempty"`
}

// Policy 是一份完整的访问控制策略，可同时包含域名与 IP 规则
//
// 任一字段为零值时表示不配置该类型 ACL，允许只配置域名或只配置 IP。
type Policy struct {
	Domain *DomainPolicy `json:"domain,omitempty"`
	IP     *IPPolicy     `json:"ip,omitempty"`
}

// LoadPolicyFromBytes 从 JSON 字节流解析 Policy
//
// 参数:
//   - data: JSON 字节流
//
// 返回:
//   - *Policy: 解析得到的策略
//   - error: JSON 解析错误
func LoadPolicyFromBytes(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadPolicyFromFile 从 JSON 文件加载 Policy
//
// 参数:
//   - filePath: JSON 配置文件路径
//
// 返回:
//   - *Policy: 解析得到的策略
//   - error: 文件不存在或 JSON 解析错误
//
// 示例文件见 testdata/security_policy.json。
func LoadPolicyFromFile(filePath string) (*Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrFileNotFound
		}
		return nil, err
	}
	return LoadPolicyFromBytes(data)
}
```

- [ ] **Step 2: 创建 `pkg/config/json_test.go` — 覆盖正常解析、字段缺失、文件不存在、非法 JSON**

```go
package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicyFromBytes_Both(t *testing.T) {
	data := []byte(`{
		"domain": {
			"domains": ["bad.com", "phish.org"],
			"listType": "blacklist",
			"includeSubdomains": true
		},
		"ip": {
			"ranges": ["10.0.0.0/8"],
			"listType": "blacklist",
			"predefinedSets": ["private_networks"],
			"allowPredefined": false
		}
	}`)
	p, err := LoadPolicyFromBytes(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.Domain == nil || len(p.Domain.Domains) != 2 {
		t.Fatalf("域名解析异常: %+v", p.Domain)
	}
	if p.Domain.ListType != "blacklist" || !p.Domain.IncludeSubdomains {
		t.Errorf("域名字段解析错误: %+v", p.Domain)
	}
	if p.IP == nil || len(p.IP.Ranges) != 1 || p.IP.ListType != "blacklist" {
		t.Fatalf("IP 解析异常: %+v", p.IP)
	}
	if len(p.IP.PredefinedSets) != 1 || p.IP.PredefinedSets[0] != "private_networks" {
		t.Errorf("预定义集合解析错误: %+v", p.IP)
	}
}

func TestLoadPolicyFromBytes_DomainOnly(t *testing.T) {
	data := []byte(`{"domain":{"domains":["a.com"],"listType":"whitelist"}}`)
	p, err := LoadPolicyFromBytes(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.Domain == nil || p.IP != nil {
		t.Errorf("应只配置域名，得到 domain=%v ip=%v", p.Domain, p.IP)
	}
}

func TestLoadPolicyFromBytes_InvalidJSON(t *testing.T) {
	_, err := LoadPolicyFromBytes([]byte(`{not json`))
	if err == nil {
		t.Fatal("非法 JSON 应返回错误")
	}
}

func TestLoadPolicyFromFile_NotExist(t *testing.T) {
	_, err := LoadPolicyFromFile("/no/such/policy.json")
	if !errors.Is(err, ErrFileNotFound) {
		t.Errorf("期望 ErrFileNotFound，得到 %v", err)
	}
}

func TestLoadPolicyFromFile_OK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.json")
	content := `{"ip":{"ranges":["8.8.8.8"],"listType":"whitelist"}}`
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	pol, err := LoadPolicyFromFile(p)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if pol.IP == nil || len(pol.IP.Ranges) != 1 || pol.IP.Ranges[0] != "8.8.8.8" {
		t.Errorf("IP 解析异常: %+v", pol.IP)
	}
}
```

- [ ] **Step 3: 验证 JSON 配置加载**
Run: `go test ./pkg/config/ -run 'Policy' -v`
Expected:
  - Exit code: 0
  - Output contains: "ok" 且各 TestLoadPolicy* 子测试全部 PASS

- [ ] **Step 4: 提交**
Run: `git add pkg/config/json.go pkg/config/json_test.go && git commit -m "feat(config): add JSON Policy loading for unified domain+IP ACL config"`

---

### Task 3: Manager 域名文件 IO 转发 + Policy 应用入口

**Depends on:** Task 1, Task 2
**Files:**
- Modify: `pkg/acl/manager.go`（在 `SaveIPACLToFile` 方法之后、`AddIPFromFile` 之前插入域名文件 IO 转发方法；在文件末尾 `Reset` 之前插入 `ApplyPolicy`）
- Create: `pkg/acl/policy.go`
- Create: `pkg/acl/policy_test.go`

- [ ] **Step 1: 在 `pkg/acl/manager.go` 中追加域名文件 IO 转发方法 — 让 Manager 域名能力与 IP 对齐**

文件: `pkg/acl/manager.go`（在 `SaveIPACLToFileWithOverwrite` 方法之后、`AddIPFromFile` 方法之前插入；即原文件第 261 行 `}` 之后）

```go
// SetDomainACLFromFile 从文件加载域名访问控制列表
//
// 参数:
//   - filePath: 包含域名列表的文件路径（每行一个域名，# 注释）
//   - listType: 列表类型（黑名单或白名单）
//   - includeSubdomains: 是否包含子域名匹配
//
// 返回:
//   - error: 文件读取或解析错误
//
// 此方法会覆盖之前设置的任何域名访问控制列表。文件格式与 SetIPACLFromFile 相同。
//
// 示例:
//
//	err := manager.SetDomainACLFromFile("./domain_blacklist.txt", types.Blacklist, true)
func (m *Manager) SetDomainACLFromFile(filePath string, listType types.ListType, includeSubdomains bool) error {
	newACL, err := domain.NewDomainACLFromFile(filePath, listType, includeSubdomains)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.acls[KindDomain] = newACL
	return nil
}

// SaveDomainACLToFile 将当前域名访问控制列表保存到文件
//
// 参数:
//   - filePath: 要保存的文件路径
//   - overwrite: 是否覆盖现有文件
//
// 返回:
//   - error: types.ErrNoACL / config.ErrFileExists / config.ErrFilePermission
func (m *Manager) SaveDomainACLToFile(filePath string, overwrite bool) error {
	domA := m.domainACL()
	if domA == nil {
		return types.ErrNoACL
	}
	return domA.SaveToFile(filePath, overwrite)
}

// AddDomainFromFile 从文件添加域名到现有域名访问控制列表
//
// 参数:
//   - filePath: 包含要添加域名的文件路径
//
// 返回:
//   - error: types.ErrNoACL / 文件读取或解析错误
//
// 与 SetDomainACLFromFile 不同，此方法不替换现有 ACL，而是向其追加内容。
func (m *Manager) AddDomainFromFile(filePath string) error {
	domA := m.domainACL()
	if domA == nil {
		return types.ErrNoACL
	}
	return domA.AddFromFile(filePath)
}
```

- [ ] **Step 2: 创建 `pkg/acl/policy.go` — 提供 ApplyPolicy 入口，把 JSON Policy 注入 Manager**

```go
package acl

import (
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/config"
	"github.com/cyberspacesec/acl-skills/pkg/ip"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// ApplyPolicy 将一份 JSON 配置解析得到的 Policy 应用到 Manager
//
// 根据 Policy 中的 Domain / IP 字段，调用 Manager 既有的 SetDomainACL / SetIPACL /
// SetIPACLWithDefaults 注入规则。零值字段（nil）表示跳过该类型 ACL，不覆盖已注册的同名 kind。
//
// 参数:
//   - p: 已解析的策略；若为 nil 直接返回 nil
//
// 返回:
//   - error: listType 取值非法、IP 格式错误、预定义集合名错误等
//
// 示例:
//
//	pol, err := config.LoadPolicyFromFile("./policy.json")
//	if err != nil { return err }
//	if err := manager.ApplyPolicy(pol); err != nil { return err }
func (m *Manager) ApplyPolicy(p *config.Policy) error {
	if p == nil {
		return nil
	}

	if p.Domain != nil {
		domains := p.Domain.Domains
		// 若配置了 File，从文件追加加载域名（与显式 Domains 合并）
		if p.Domain.File != "" {
			fileDomains, err := config.ReadIPACL(p.Domain.File)
			if err != nil {
				return fmt.Errorf("load domain file %q: %w", p.Domain.File, err)
			}
			domains = append(domains, fileDomains...)
		}
		listType, err := parseListType(p.Domain.ListType)
		if err != nil {
			return fmt.Errorf("domain listType: %w", err)
		}
		m.SetDomainACL(domains, listType, p.Domain.IncludeSubdomains)
	}

	if p.IP != nil {
		listType, err := parseListType(p.IP.ListType)
		if err != nil {
			return fmt.Errorf("ip listType: %w", err)
		}

		var predefinedSets []ip.PredefinedSet
		for _, name := range p.IP.PredefinedSets {
			predefinedSets = append(predefinedSets, ip.PredefinedSet(name))
		}

		// 优先用 SetIPACLWithDefaults（当有预定义集合时），否则用 SetIPACL
		if len(predefinedSets) > 0 {
			if err := m.SetIPACLWithDefaults(p.IP.Ranges, listType, predefinedSets, p.IP.AllowPredefined); err != nil {
				return fmt.Errorf("apply ip policy: %w", err)
			}
		} else {
			if err := m.SetIPACL(p.IP.Ranges, listType); err != nil {
				return fmt.Errorf("apply ip policy: %w", err)
			}
		}

		// 若配置了 File，从文件追加 IP 规则
		if p.IP.File != "" {
			if err := m.AddIPFromFile(p.IP.File); err != nil {
				return fmt.Errorf("load ip file %q: %w", p.IP.File, err)
			}
		}
	}

	return nil
}

// parseListType 将字符串 "blacklist"/"whitelist" 转为 types.ListType
//
// 空字符串默认按 blacklist 处理（与库默认行为一致）。
func parseListType(s string) (types.ListType, error) {
	switch s {
	case "", "blacklist":
		return types.Blacklist, nil
	case "whitelist":
		return types.Whitelist, nil
	default:
		return 0, fmt.Errorf("invalid listType %q (want blacklist|whitelist)", s)
	}
}
```

- [ ] **Step 3: 创建 `pkg/acl/policy_test.go` — 覆盖域名+IP 双配置、仅域名、非法 listType、文件不存在**

```go
package acl

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/config"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// TestApplyPolicy_Both 验证一份 JSON 同时配置域名黑名单 + IP 黑名单（含预定义集合）
func TestApplyPolicy_Both(t *testing.T) {
	manager := NewManager()
	pol := &config.Policy{
		Domain: &config.DomainPolicy{
			Domains:           []string{"bad.com"},
			ListType:          "blacklist",
			IncludeSubdomains: true,
		},
		IP: &config.IPPolicy{
			Ranges:          []string{"203.0.113.1"},
			ListType:        "blacklist",
			PredefinedSets:  []string{"private_networks"},
			AllowPredefined: false,
		},
	}
	if err := manager.ApplyPolicy(pol); err != nil {
		t.Fatalf("ApplyPolicy 失败: %v", err)
	}

	// 域名黑名单 + 子域名应 Denied
	perm, err := manager.CheckDomain("sub.bad.com")
	if err != nil || perm != types.Denied {
		t.Errorf("域名子域名应 Denied，得到 %s err=%v", perm, err)
	}
	// IP 黑名单：内网应 Denied
	perm, err = manager.CheckIP("10.0.0.1")
	if err != nil || perm != types.Denied {
		t.Errorf("内网 IP 应 Denied，得到 %s err=%v", perm, err)
	}
	// 公网 IP 应 Allowed
	perm, err = manager.CheckIP("8.8.4.4")
	if err != nil || perm != types.Allowed {
		t.Errorf("公网 IP 应 Allowed，得到 %s err=%v", perm, err)
	}
}

// TestApplyPolicy_DomainOnly 验证只配置域名时不影响 IP kind
func TestApplyPolicy_DomainOnly(t *testing.T) {
	manager := NewManager()
	pol := &config.Policy{
		Domain: &config.DomainPolicy{
			Domains:  []string{"only.com"},
			ListType: "whitelist",
		},
	}
	if err := manager.ApplyPolicy(pol); err != nil {
		t.Fatalf("ApplyPolicy 失败: %v", err)
	}
	// 白名单：未命中应 Denied
	perm, _ := manager.CheckDomain("other.com")
	if perm != types.Denied {
		t.Errorf("白名单未命中应 Denied，得到 %s", perm)
	}
	// IP kind 未配置
	_, err := manager.CheckIP("1.2.3.4")
	if !errors.Is(err, types.ErrNoACL) {
		t.Errorf("未配置 IP ACL 应返回 ErrNoACL，得到 %v", err)
	}
}

// TestApplyPolicy_InvalidListType 验证非法 listType 报错且不静默通过
func TestApplyPolicy_InvalidListType(t *testing.T) {
	manager := NewManager()
	pol := &config.Policy{
		Domain: &config.DomainPolicy{
			Domains:  []string{"x.com"},
			ListType: "graylist",
		},
	}
	err := manager.ApplyPolicy(pol)
	if err == nil {
		t.Fatal("非法 listType 应返回错误")
	}
}

// TestApplyPolicy_NilPolicy 验证 nil 策略为 no-op
func TestApplyPolicy_NilPolicy(t *testing.T) {
	manager := NewManager()
	if err := manager.ApplyPolicy(nil); err != nil {
		t.Fatalf("nil 策略应返回 nil，得到 %v", err)
	}
}

// TestApplyPolicy_WithFiles 验证 Domain.File 与 IP.File 追加加载
func TestApplyPolicy_WithFiles(t *testing.T) {
	dir := t.TempDir()
	domFile := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(domFile, []byte("filedom.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ipFile := filepath.Join(dir, "ips.txt")
	if err := os.WriteFile(ipFile, []byte("198.51.100.5\n"), 0644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager()
	pol := &config.Policy{
		Domain: &config.DomainPolicy{
			Domains:           []string{"inlinedomain.com"},
			ListType:          "blacklist",
			IncludeSubdomains: true,
			File:              domFile,
		},
		IP: &config.IPPolicy{
			Ranges:   []string{"203.0.113.1"},
			ListType: "blacklist",
			File:     ipFile,
		},
	}
	if err := manager.ApplyPolicy(pol); err != nil {
		t.Fatalf("ApplyPolicy 失败: %v", err)
	}
	// 文件中的域名与行内域名都应生效（IncludeSubdomains=true，子域也应 Denied）
	if perm, _ := manager.CheckDomain("sub.filedom.com"); perm != types.Denied {
		t.Errorf("文件域名子域应 Denied，得到 %s", perm)
	}
	if perm, _ := manager.CheckDomain("inlinedomain.com"); perm != types.Denied {
		t.Errorf("行内域名应 Denied，得到 %s", perm)
	}
	// 文件中的 IP 应生效
	if perm, _ := manager.CheckIP("198.51.100.5"); perm != types.Denied {
		t.Errorf("文件 IP 应 Denied，得到 %s", perm)
	}
}
```

- [ ] **Step 4: 验证 Manager 域名文件 IO 与 Policy 应用**
Run: `go test ./pkg/acl/ -run 'Policy|Domain' -v`
Expected:
  - Exit code: 0
  - Output contains: "ok" 且 TestApplyPolicy* 全部 PASS

- [ ] **Step 5: 提交**
Run: `git add pkg/acl/manager.go pkg/acl/policy.go pkg/acl/policy_test.go && git commit -m "feat(acl): add domain file IO forwarding and ApplyPolicy entrypoint on Manager"`

---

### Task 4: HTTP 访问控制中间件

**Depends::** Task 3
**Files:**
- Create: `pkg/middleware/doc.go`
- Create: `pkg/middleware/middleware.go`
- Create: `pkg/middleware/middleware_test.go`

- [ ] **Step 1: 创建 `pkg/middleware/doc.go` — 包文档与使用说明**

```go
// Package middleware 提供基于 net/http 的访问控制中间件。
//
// 它把 acl.Manager 的 CheckIP / CheckDomain 能力封装为可组合的 HTTP 中间件，
// 使 Web 服务能以一行代码完成"按客户端 IP + 目标域名做访问控制"。
//
// 默认行为（保守模式，TrustProxy=false）：
//   - 客户端 IP 取自 http.Request.RemoteAddr（TCP 连接对端地址）
//   - 目标域名取自 Host 头（去除端口）
//   - 任一检查 Denied → 返回 403 Forbidden
//   - 未配置对应 ACL kind → 该项检查视为通过（不强制阻断）
//
// 当部署在受信任的反向代理后端时，可设置 TrustProxy=true 以解析
// X-Forwarded-For / X-Real-IP 头获取真实客户端 IP。
package middleware
```

- [ ] **Step 2: 创建 `pkg/middleware/middleware.go` — 实现 ACL 中间件**

```go
package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// Options 控制中间件的行为
type Options struct {
	// TrustProxy 为 true 时，从 X-Forwarded-For（取首个）或 X-Real-IP 提取客户端 IP。
	// 默认 false：仅使用 Request.RemoteAddr，保守不信任代理头，避免被伪造头绕过黑名单。
	TrustProxy bool

	// CheckClientIP 为 true 时对客户端 IP 执行 CheckIP（需 Manager 注册了 IP ACL）。
	// 默认 true。
	CheckClientIP bool

	// CheckHost 为 true 时对请求 Host 执行 CheckDomain（需 Manager 注册了 Domain ACL）。
	// 默认 true。
	CheckHost bool

	// Denied 处理器：默认返回 403 + "Access Denied"。可自定义返回 JSON 或重定向。
	Denied http.HandlerFunc
}

// New 返回一个 HTTP 中间件，基于给定 Manager 与 Options 做访问控制。
//
// 用法:
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/api", apiHandler)
//	handler := middleware.New(manager, middleware.Options{CheckClientIP: true})(mux)
//	http.ListenAndServe(":8080", handler)
func New(manager *acl.Manager, opts Options) func(http.Handler) http.Handler {
	if opts.Denied == nil {
		opts.Denied = defaultDenied
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !opts.CheckClientIP && !opts.CheckHost {
				next.ServeHTTP(w, r)
				return
			}

			if opts.CheckHost {
				host := extractHost(r.Host)
				if host != "" {
					perm, err := manager.CheckDomain(host)
					// err==ErrNoACL 视为该项未配置 → 放行该项
					if err == nil && perm == types.Denied {
						opts.Denied(w, r)
						return
					}
				}
			}

			if opts.CheckClientIP {
				clientIP := extractClientIP(r, opts.TrustProxy)
				if clientIP != "" {
					perm, err := manager.CheckIP(clientIP)
					if err == nil && perm == types.Denied {
						opts.Denied(w, r)
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// defaultDenied 默认拒绝处理器：返回 403 与简短正文
func defaultDenied(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("Access Denied\n"))
}

// extractHost 从请求 Host 头提取域名（去除端口，IPv6 兼容）
func extractHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// IPv6 带端口：[2001:db8::1]:8080
	if strings.HasPrefix(host, "[") {
		if idx := strings.Index(host, "]"); idx != -1 {
			return host[:idx+1]
		}
	}
	// 普通 host:port
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

// extractClientIP 提取客户端 IP
//
// TrustProxy=false: 取 RemoteAddr 的 host 部分。
// TrustProxy=true: 优先 X-Real-IP，其次 X-Forwarded-For 首个，兜底 RemoteAddr。
func extractClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			if ip := net.ParseIP(strings.TrimSpace(xrip)); ip != nil {
				return ip.String()
			}
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For: client, proxy1, proxy2
			first := strings.Split(xff, ",")[0]
			if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
```

- [ ] **Step 3: 创建 `pkg/middleware/middleware_test.go` — 覆盖放行、域名拒绝、IP 拒绝、代理头、自定义 Denied**

```go
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func newManager(t *testing.T) *acl.Manager {
	t.Helper()
	m := acl.NewManager()
	m.SetDomainACL([]string{"bad.com"}, types.Blacklist, true)
	if err := m.SetIPACL([]string{"10.0.0.0/8"}, types.Blacklist); err != nil {
		t.Fatalf("SetIPACL 失败: %v", err)
	}
	return m
}

// TestMiddleware_Allowed 验证正常请求放行
func TestMiddleware_Allowed(t *testing.T) {
	m := newManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckClientIP: true, CheckHost: true})(next)

	req := httptest.NewRequest("GET", "https://good.com/x", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Host = "good.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("正常请求应放行 200，得到 %d", rec.Code)
	}
}

// TestMiddleware_DomainDenied 验证黑名单域名返回 403
func TestMiddleware_DomainDenied(t *testing.T) {
	m := newManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckHost: true, CheckClientIP: false})(next)

	req := httptest.NewRequest("GET", "https://sub.bad.com/x", nil)
	req.Host = "sub.bad.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("黑名单域名应 403，得到 %d", rec.Code)
	}
}

// TestMiddleware_IPDenied 验证黑名单 IP 返回 403
func TestMiddleware_IPDenied(t *testing.T) {
	m := newManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckHost: false, CheckClientIP: true})(next)

	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("黑名单 IP 应 403，得到 %d", rec.Code)
	}
}

// TestMiddleware_TrustProxy 验证信任代理头时从 X-Forwarded-For 取 IP
func TestMiddleware_TrustProxy(t *testing.T) {
	m := newManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckHost: false, CheckClientIP: true, TrustProxy: true})(next)

	// RemoteAddr 是白名单 IP，但 X-Forwarded-For 是黑名单 IP
	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("X-Forwarded-For", "10.5.5.5, 192.168.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("信任代理头时应取首个 XFF 10.5.5.5 → 403，得到 %d", rec.Code)
	}
}

// TestMiddleware_NoProxyByDefault 验证默认不信任代理头，黑名单 IP 伪造 XFF 无效
func TestMiddleware_NoProxyByDefault(t *testing.T) {
	m := newManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckHost: false, CheckClientIP: true})(next) // TrustProxy 默认 false

	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("X-Forwarded-For", "10.5.5.5")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("默认不信代理头，伪造 XFF 应放行 200，得到 %d", rec.Code)
	}
}

// TestMiddleware_CustomDenied 验证自定义 Denied 处理器
func TestMiddleware_CustomDenied(t *testing.T) {
	m := newManager(t)
	called := false
	custom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})
	handler := New(m, Options{CheckHost: false, CheckClientIP: true, Denied: custom})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "10.0.0.1:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("自定义 Denied 处理器未被调用")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("应返回自定义状态 418，得到 %d", rec.Code)
	}
}

// TestMiddleware_NoACLKindPasses 验证未配置某 kind 时该项视为放行
func TestMiddleware_NoACLKindPasses(t *testing.T) {
	m := acl.NewManager() // 空 Manager，无任何 ACL
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckHost: true, CheckClientIP: true})(next)

	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "1.2.3.4:1"
	req.Host = "whatever.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("未配置 ACL 应放行 200，得到 %d", rec.Code)
	}
}
```

- [ ] **Step 4: 验证 HTTP 中间件**
Run: `go test ./pkg/middleware/ -v`
Expected:
  - Exit code: 0
  - Output contains: "ok" 且 TestMiddleware_* 全部 PASS

- [ ] **Step 5: 提交**
Run: `git add pkg/middleware/ && git commit -m "feat(middleware): add net/http access-control middleware with proxy-trust option"`

---

### Task 5: 统一示例 + 文档

**Depends on:** Task 3, Task 4
**Files:**
- Create: `testdata/security_policy.json`
- Create: `examples/08_http_middleware/main.go`
- Modify: `README.md`（在"🔧 快速开始"之后插入"📦 统一配置"与"🌐 HTTP 中间件"两小节；在示例表格末尾追加 08 行）

- [ ] **Step 1: 创建 `testdata/security_policy.json` — 一份同时配置域名+IP 的示例策略**

```json
{
  "domain": {
    "domains": [
      "malware-site.com",
      "phishing-example.org"
    ],
    "listType": "blacklist",
    "includeSubdomains": true
  },
  "ip": {
    "ranges": [
      "203.0.113.0/24"
    ],
    "listType": "blacklist",
    "predefinedSets": [
      "private_networks",
      "loopback_networks",
      "cloud_metadata",
      "docker_networks"
    ],
    "allowPredefined": false
  }
}
```

- [ ] **Step 2: 创建 `examples/08_http_middleware/main.go` — 演示一份配置 + 一行中间件**

```go
// Package main 演示如何用统一 JSON 配置 + HTTP 中间件完成按 IP/域名的访问控制
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/config"
	"github.com/cyberspacesec/acl-skills/pkg/middleware"
)

func main() {
	// 1. 从一份 JSON 策略加载域名 + IP 规则
	policyPath := "../../testdata/security_policy.json"
	pol, err := config.LoadPolicyFromFile(policyPath)
	if err != nil {
		fmt.Printf("加载策略失败: %v\n", err)
		os.Exit(1)
	}

	manager := acl.NewManager()
	if err := manager.ApplyPolicy(pol); err != nil {
		fmt.Printf("应用策略失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("已从 JSON 加载域名 + IP 访问控制策略")

	// 2. 用一行中间件包装业务 handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %s!\n", r.Host)
	})

	// TrustProxy=false：默认不信任 X-Forwarded-For，防止伪造头绕过 IP 黑名单
	handler := middleware.New(manager, middleware.Options{
		CheckClientIP: true,
		CheckHost:     true,
	})(mux)

	fmt.Println("中间件已挂载，监听 :8080")
	fmt.Println("  - 域名黑名单 + 子域名 → 403")
	fmt.Println("  - IP 黑名单（内网/云元数据/Docker/203.0.113.0/24）→ 403")

	if err := http.ListenAndServe(":8080", handler); err != nil {
		fmt.Printf("服务退出: %v\n", err)
	}
}
```

- [ ] **Step 3: 修改 `README.md` — 在"🔧 快速开始"章节之后插入统一配置与中间件两小节**

文件: `README.md`（在"## 🎯 主要组件"标题之前插入，即原文件第 132 行 `## 🎯 主要组件` 之前）

```markdown
## 📦 统一配置（JSON Policy）

除命令式 API 外，可用一份 JSON 同时配置域名 + IP 规则：

```go
pol, err := config.LoadPolicyFromFile("./security_policy.json")
if err != nil { return err }
manager := acl.NewManager()
if err := manager.ApplyPolicy(pol); err != nil { return err }
```

策略字段：`domain.{domains,listType,includeSubdomains,file}` 与 `ip.{ranges,listType,predefinedSets,allowPredefined,file}`。任一顶层字段省略即跳过该类型 ACL。详见 [`testdata/security_policy.json`](testdata/security_policy.json)。

## 🌐 HTTP 中间件

把 `Manager` 的 IP/域名检查封装为 `net/http` 中间件，一行接入：

```go
handler := middleware.New(manager, middleware.Options{
    CheckClientIP: true, // 检查客户端 IP
    CheckHost:     true, // 检查目标域名
})(mux)
http.ListenAndServe(":8080", handler)
```

- 默认 **不信任** `X-Forwarded-For`/`X-Real-IP`（`TrustProxy=false`），防止伪造头绕过 IP 黑名单；部署在可信反代后端时再开启。
- 任一检查 `Denied` → 返回 403；未配置对应 ACL kind → 该项放行。
- 可通过 `Options.Denied` 自定义拒绝响应（返回 JSON、重定向等）。
```

- [ ] **Step 4: 修改 `README.md` 示例表格 — 追加 08 行**

文件: `README.md`（在示例表格 `**自定义ACL扩展**` 行之后、`查看[示例目录]` 之前追加）

```markdown
| **HTTP 中间件** | 演示一份 JSON 配置 + 一行中间件完成访问控制 | [查看示例](examples/08_http_middleware/) |
```

- [ ] **Step 5: 验证全量构建与测试**
Run: `go build ./... && go test ./...`
Expected:
  - Exit code: 0
  - Output contains: "ok" for all packages (pkg/acl, pkg/config, pkg/domain, pkg/ip, pkg/middleware, pkg/types)
  - Output does NOT contain: "FAIL" or "cannot" or "undefined"

- [ ] **Step 6: 提交**
Run: `git add testdata/security_policy.json examples/08_http_middleware/main.go README.md && git commit -m "docs: add unified JSON policy + HTTP middleware example and README sections"`
