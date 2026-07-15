# 域名 ACL 预定义集合与策略集成 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 为域名 ACL 补齐预定义域名集合能力（对标 IP 侧已有的 14 个预定义集合），并打通 Manager 转发层与 JSON Policy 配置链路，使整个访问控制库的域名侧能力与 IP 侧对齐。

**Architecture:** 数据流：`predefined.go` 定义域名集合常量与 map → `DomainACL.AddPredefinedSet` 复用既有 `Add`（自动走 `normalizeDomain` 标准化）注入规则 → `Manager.AddPredefinedDomainSet`/`SetDomainACLWithDefaults` 委托给 `DomainACL` → `config.DomainPolicy` 增 `PredefinedSets`/`AllowPredefined` 字段 → `Manager.ApplyPolicy` 域名块仿 IP 块分支处理预定义集合。关键组件：`pkg/domain/predefined.go`（新增，对标 `pkg/ip/predefined.go`）、`pkg/domain/domain.go`（新增方法）、`pkg/acl/manager.go`（新增转发）、`pkg/config/json.go`+`pkg/acl/policy.go`（打通配置）。设计理由：完全复刻 IP 侧已验证的预定义集合架构，保证两侧行为对称、调用方心智模型统一。

**Tech Stack:** Go 1.18+，仅标准库依赖（`net`、`sync`、`errors`、`encoding/json`、`os`），测试用 `testing` 标准库表驱动风格

**Risks:**
- Task 2 新增 `DomainACL` 方法不改既有方法体，仅追加 → 缓解：所有现有 `domain_test.go`/`manager_test.go` 测试必须保持通过作为安全网
- Task 4 扩展 `DomainPolicy` 增字段是向后兼容的（新字段加 `omitempty`）→ 缓解：旧 JSON 文件无该字段时走零值，行为不变
- 域名预定义集合内容需经 `normalizeDomain` 标准化 → 缓解：`AddPredefinedSet` 内部复用 `Add`，自动标准化，无需额外处理
- `predefined.go` 的 `init()` 合成 `AllMaliciousDomains` 时 map 遍历顺序不确定 → 缓解：`init` 中对合并结果排序，保证幂等且测试可断言

---

### Task 1: 创建域名预定义集合定义

**Depends on:** None
**Files:**
- Create: `pkg/domain/predefined.go`
- Create: `pkg/domain/predefined_test.go`

- [ ] **Step 1: 创建 predefined.go — 定义 PredefinedSet 类型与预定义域名集合常量**

```go
package domain

// PredefinedSet 表示预定义域名集合的类型
//
// 预定义集合是一组相关的域名，用于简化常见安全场景的访问控制。
// 例如可一键阻止短链/网盘/代码托管等高风险域名类别，或放行可信公共服务域名。
type PredefinedSet string

// 预定义域名集合常量，用于参数传递
const (
	// Shorteners 包含常见的 URL 短链服务域名
	// 这些域名常被用于隐藏真实跳转目标，在反钓鱼/反恶意场景中常被整体阻止
	Shorteners PredefinedSet = "shorteners"

	// PublicFileSharing 包含常见公共网盘/文件分享服务域名
	// 数据外泄场景中常需阻止上传到这些服务
	PublicFileSharing PredefinedSet = "public_file_sharing"

	// CodeHosting 包含常见代码托管平台域名
	// 防止源码外泄或阻止从不受信源拉取代码时使用
	CodeHosting PredefinedSet = "code_hosting"

	// SocialMedia 包含主流社交媒体域名
	// 用于限制企业环境对外访问或防止社工攻击载荷投递
	SocialMedia PredefinedSet = "social_media"

	// WebmailProviders 包含常见网页邮箱服务域名
	// 数据外泄/钓鱼场景中常需控制
	WebmailProviders PredefinedSet = "webmail_providers"

	// TorExitNodes 包含 Tor 出口节点常用域名标识
	// 用于阻断匿名网络流量到已知 Tor 相关域名
	TorExitNodes PredefinedSet = "tor_exit_nodes"

	// DisposableEmail 包含一次性邮箱服务域名
	// 注册场景中常需阻止一次性邮箱绕过验证
	DisposableEmail PredefinedSet = "disposable_email"

	// TrustedCDN 包含可信公共 CDN 域名
	// 白名单场景下放行这些 CDN 加速域名
	TrustedCDN PredefinedSet = "trusted_cdn"

	// AllMaliciousDomains 包含上述所有高风险域名类别的合集
	// 这是一个便捷集合，适用于需要最全面外联管控的场景
	AllMaliciousDomains PredefinedSet = "all_malicious_domains"
)

// PredefinedSets 存储所有可用的预定义域名集合
//
// 每个集合的域名均为规范化后的小写裸域名（无协议/端口/路径），
// 在 AddPredefinedSet 注入时会再经 normalizeDomain 处理一次，保持幂等。
var PredefinedSets = map[PredefinedSet][]string{
	Shorteners: {
		"bit.ly",
		"tinyurl.com",
		"t.co",
		"goo.gl",
		"ow.ly",
		"is.gd",
		"buff.ly",
		"rebrand.ly",
		"cutt.ly",
	},

	PublicFileSharing: {
		"dropbox.com",
		"drive.google.com",
		"onedrive.live.com",
		"mega.nz",
		"wetransfer.com",
		"mediafire.com",
		"sendspace.com",
		"uploadfiles.io",
	},

	CodeHosting: {
		"github.com",
		"gitlab.com",
		"bitbucket.org",
		"gitee.com",
		"codeberg.org",
		"sourceforge.net",
	},

	SocialMedia: {
		"facebook.com",
		"twitter.com",
		"instagram.com",
		"linkedin.com",
		"tiktok.com",
		"weibo.com",
		"reddit.com",
	},

	WebmailProviders: {
		"gmail.com",
		"outlook.com",
		"yahoo.com",
		"hotmail.com",
		"mail.com",
		"protonmail.com",
		"icloud.com",
	},

	TorExitNodes: {
		"torproject.org",
		"check.torproject.org",
		"exit-relay.org",
	},

	DisposableEmail: {
		"mailinator.com",
		"guerrillamail.com",
		"tempmail.com",
		"10minutemail.com",
		"throwawaymail.com",
		"yopmail.com",
		"getnada.com",
	},

	TrustedCDN: {
		"cdn.cloudflare.net",
		"jsdelivr.net",
		"unpkg.com",
		"cdnjs.cloudflare.com",
		"ajax.googleapis.com",
	},
}

// init 合成 AllMaliciousDomains：合并除自身外所有集合，去重并排序保证幂等
func init() {
	seen := make(map[string]struct{})
	var all []string
	for set, domains := range PredefinedSets {
		if set == AllMaliciousDomains {
			continue
		}
		for _, d := range domains {
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			all = append(all, d)
		}
	}
	// 排序保证 init 幂等（map 遍历顺序不确定，排序后结果稳定）
	sortStrings(all)
	PredefinedSets[AllMaliciousDomains] = all
}

// sortStrings 对字符串切片做原地升序排序（仅标准库 sort，避免引入额外依赖感知）
func sortStrings(s []string) {
	// 使用插入排序：集合规模小（百级以内），且保持文件无额外 import 的简洁性
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j] < s[j-1] {
			s[j], s[j-1] = s[j-1], s[j]
			j--
		}
	}
}

// GetPredefinedDomains 获取指定预定义集合中的域名列表
//
// 参数:
//   - setName: 预定义集合名称
//     例如: domain.Shorteners, domain.DisposableEmail 等
//
// 返回:
//   - []string: 预定义集合中的域名列表
//     如果指定的集合不存在，返回 nil
//
// 示例:
//
//	shorteners := domain.GetPredefinedDomains(domain.Shorteners)
//	fmt.Printf("短链服务集合包含 %d 个域名\n", len(shorteners))
func GetPredefinedDomains(setName PredefinedSet) []string {
	if domains, ok := PredefinedSets[setName]; ok {
		return domains
	}
	return nil
}

// getPredefinedSet 内部辅助：返回集合与不存在的错误
func getPredefinedSet(setName PredefinedSet) ([]string, error) {
	if domains, ok := PredefinedSets[setName]; ok {
		return domains, nil
	}
	return nil, ErrInvalidPredefinedSet
}
```

- [ ] **Step 2: 创建 predefined_test.go — 验证集合定义与 AllMaliciousDomains 合成**

```go
package domain

import (
	"testing"
)

// TestGetPredefinedDomains 测试获取预定义域名集合
func TestGetPredefinedDomains(t *testing.T) {
	tests := []struct {
		name      string
		set       PredefinedSet
		wantEmpty bool
		wantSample string // 期望包含的样本域名
	}{
		{name: "短链服务集合非空", set: Shorteners, wantEmpty: false, wantSample: "bit.ly"},
		{name: "一次性邮箱集合非空", set: DisposableEmail, wantEmpty: false, wantSample: "mailinator.com"},
		{name: "代码托管集合非空", set: CodeHosting, wantEmpty: false, wantSample: "github.com"},
		{name: "可信CDN集合非空", set: TrustedCDN, wantEmpty: false, wantSample: "jsdelivr.net"},
		{name: "不存在的集合返回nil", set: PredefinedSet("nonexistent_set"), wantEmpty: true, wantSample: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPredefinedDomains(tt.set)
			if tt.wantEmpty {
				if got != nil {
					t.Fatalf("期望 nil，得到 %v", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("集合 %s 不应为空", tt.set)
			}
			found := false
			for _, d := range got {
				if d == tt.wantSample {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("集合 %s 应包含样本 %s，实际 %v", tt.set, tt.wantSample, got)
			}
		})
	}
}

// TestAllMaliciousDomainsAggregation 测试 AllMaliciousDomains 是所有子集的去重并集
func TestAllMaliciousDomainsAggregation(t *testing.T) {
	all := GetPredefinedDomains(AllMaliciousDomains)
	if len(all) == 0 {
		t.Fatal("AllMaliciousDomains 不应为空")
	}
	// 去重性：无重复元素
	seen := make(map[string]struct{}, len(all))
	for _, d := range all {
		if _, ok := seen[d]; ok {
			t.Fatalf("AllMaliciousDomains 存在重复域名: %s", d)
		}
		seen[d] = struct{}{}
	}
	// 完备性：每个子集的每个域名都应出现在 all 中
	for set, domains := range PredefinedSets {
		if set == AllMaliciousDomains {
			continue
		}
		for _, d := range domains {
			if _, ok := seen[d]; !ok {
				t.Fatalf("域名 %s（来自 %s）未出现在 AllMaliciousDomains 中", d, set)
			}
		}
	}
}

// TestPredefinedSetsInitIdempotent 测试 init 合成结果稳定（多次调用等价，已排序）
func TestPredefinedSetsInitIdempotent(t *testing.T) {
	all := GetPredefinedDomains(AllMaliciousDomains)
	// 已排序：逐对比较
	for i := 1; i < len(all); i++ {
		if all[i-1] > all[i] {
			t.Fatalf("AllMaliciousDomains 未按升序排序: %s > %s", all[i-1], all[i])
		}
	}
}
```

- [ ] **Step 3: 验证预定义集合定义**
Run: `go test ./pkg/domain/ -run 'TestGetPredefinedDomains|TestAllMaliciousDomainsAggregation|TestPredefinedSetsInitIdempotent' -v`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "FAIL" or "--- FAIL"

- [ ] **Step 4: 提交**
Run: `git add pkg/domain/predefined.go pkg/domain/predefined_test.go && git commit -m "feat(domain): add predefined domain sets (shorteners/disposable email/code hosting etc.)"`

---

### Task 2: DomainACL 增加 AddPredefinedSet 与 NewDomainACLWithDefaults 方法

**Depends on:** Task 1
**Files:**
- Modify: `pkg/domain/domain.go`（新增 `ErrInvalidPredefinedSet` 错误、`AddPredefinedSet` 方法、`NewDomainACLWithDefaults` 构造函数）
- Modify: `pkg/domain/domain_test.go`（追加预定义集合相关测试）

- [ ] **Step 1: 在 domain.go 错误定义块追加 ErrInvalidPredefinedSet**

文件: `pkg/domain/domain.go:12-17`（`var ( ... )` 错误定义块，在 `ErrInvalidDomain` 之后追加）

```go
// 错误定义
var (
	// ErrDomainNotFound 表示请求的域名不在访问控制列表中
	ErrDomainNotFound = errors.New("域名不在列表中")
	// ErrInvalidDomain 表示提供的域名格式无效
	ErrInvalidDomain = errors.New("无效的域名格式")
	// ErrInvalidPredefinedSet 表示请求的预定义域名集合不存在
	ErrInvalidPredefinedSet = errors.New("无效的预定义域名集合")
)
```

- [ ] **Step 2: 在 domain.go NewDomainACL 之后追加 NewDomainACLWithDefaults 构造函数**

文件: `pkg/domain/domain.go`（在 `NewDomainACL` 函数结束 `}` 之后、`Add` 函数之前插入）

```go
// NewDomainACLWithDefaults 创建一个新的域名访问控制列表，同时加入预定义的域名集合
//
// 参数:
//   - domains: 基础域名列表
//   - listType: 列表类型（黑名单或白名单）
//   - includeSubdomains: 是否包含子域名匹配
//   - predefinedSets: 要包含的预定义域名集合列表
//     例如: []PredefinedSet{Shorteners, DisposableEmail}
//   - allowDefaultSets: 预定义集合的处理方式
//   - 对于黑名单，false 表示阻止这些域名（添加到黑名单）
//   - 对于白名单，true 表示允许这些域名（添加到白名单）
//
// 返回:
//   - *DomainACL: 创建的域名访问控制列表
//   - error: ErrInvalidPredefinedSet 指定的预定义集合不存在
//
// 此函数是创建具有安全防护功能 ACL 的便捷方法，特别适用于一键阻止高风险域名类别。
//
// 示例:
//
//	// 创建黑名单，阻止短链与一次性邮箱域名
//	blacklist, err := domain.NewDomainACLWithDefaults(
//	    []string{"malware.example.com"},
//	    types.Blacklist,
//	    true,
//	    []domain.PredefinedSet{
//	        domain.Shorteners,
//	        domain.DisposableEmail,
//	    },
//	    false, // 添加到黑名单阻止这些域名
//	)
//	if err != nil {
//	    log.Printf("创建域名黑名单失败: %v", err)
//	    return
//	}
func NewDomainACLWithDefaults(domains []string, listType types.ListType, includeSubdomains bool, predefinedSets []PredefinedSet, allowDefaultSets bool) (*DomainACL, error) {
	acl := NewDomainACL(domains, listType, includeSubdomains)
	for _, setName := range predefinedSets {
		if err := acl.AddPredefinedSet(setName, allowDefaultSets); err != nil {
			return nil, err
		}
	}
	return acl, nil
}
```

- [ ] **Step 3: 在 domain.go 追加 AddPredefinedSet 方法**

文件: `pkg/domain/domain.go`（在 `Remove` 函数之后、`GetDomains` 函数之前插入；签名与 IP 侧 `AddPredefinedSet` 完全对齐）

```go
// AddPredefinedSet 向域名访问控制列表添加一个预定义域名集合
//
// 参数:
//   - setName: 预定义集合名称
//     可用值: domain.Shorteners, domain.DisposableEmail, domain.AllMaliciousDomains 等
//   - allowSet: 预定义集合的处理方式
//   - 对于黑名单，false 表示阻止这些域名（添加到黑名单）
//   - 对于白名单，true 表示允许这些域名（添加到白名单）
//
// 返回:
//   - error: 可能的错误:
//   - ErrInvalidPredefinedSet: 如果提供了无效的预定义集合名称
//
// 域名在添加前会经 normalizeDomain 自动标准化，与 Add 行为一致。
// 当 listType 与 allowSet 的组合表示"不实际添加"时，本方法为 no-op 并返回 nil。
//
// 示例:
//
//	// 向黑名单添加短链域名（阻止访问）
//	err := acl.AddPredefinedSet(domain.Shorteners, false)
//	// 向白名单添加可信 CDN 域名（允许访问）
//	err := acl.AddPredefinedSet(domain.TrustedCDN, true)
func (d *DomainACL) AddPredefinedSet(setName PredefinedSet, allowSet bool) error {
	domains, err := getPredefinedSet(setName)
	if err != nil {
		return err
	}
	// 与 IP 侧语义一致：黑名单+!allowSet 添加为阻止项；白名单+allowSet 添加为允许项
	if (d.listType == types.Blacklist && !allowSet) || (d.listType == types.Whitelist && allowSet) {
		return d.Add(domains...)
	}
	return nil
}
```

- [ ] **Step 4: 在 domain_test.go 追加预定义集合方法测试**

文件: `pkg/domain/domain_test.go`（在文件末尾追加；复用表驱动风格）

```go
// TestAddPredefinedSet 测试向 DomainACL 添加预定义域名集合
func TestAddPredefinedSet(t *testing.T) {
	tests := []struct {
		name            string
		setName         PredefinedSet
		allowSet        bool
		listType        types.ListType
		wantErr         bool
		wantErrIs       error
		wantSampleMatch bool // 添加后是否应命中集合中的样本域名
		sampleDomain    string
		includeSubs     bool
	}{
		{
			name:            "黑名单添加短链集合（阻止）",
			setName:         Shorteners,
			allowSet:        false,
			listType:        types.Blacklist,
			wantErr:         false,
			wantSampleMatch: true,
			sampleDomain:    "bit.ly",
			includeSubs:     true,
		},
		{
			name:            "白名单添加可信CDN集合（允许）",
			setName:         TrustedCDN,
			allowSet:        true,
			listType:        types.Whitelist,
			wantErr:         false,
			wantSampleMatch: true,
			sampleDomain:    "jsdelivr.net",
			includeSubs:     false,
		},
		{
			name:            "黑名单+allowSet=true 不实际添加（no-op）",
			setName:         Shorteners,
			allowSet:        true,
			listType:        types.Blacklist,
			wantErr:         false,
			wantSampleMatch: false,
			sampleDomain:    "bit.ly",
			includeSubs:     true,
		},
		{
			name:      "无效集合名返回错误",
			setName:   PredefinedSet("nonexistent_set"),
			allowSet:  false,
			listType:  types.Blacklist,
			wantErr:   true,
			wantErrIs: ErrInvalidPredefinedSet,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := NewDomainACL([]string{}, tt.listType, tt.includeSubs)
			err := acl.AddPredefinedSet(tt.setName, tt.allowSet)
			if tt.wantErr {
				if err == nil {
					t.Fatal("期望错误，得到 nil")
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("期望错误 %v，得到 %v", tt.wantErrIs, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("非期望错误: %v", err)
			}
			perm, _ := acl.Check(tt.sampleDomain)
			if tt.wantSampleMatch {
				// 命中应被拒（黑名单）/ 被允许（白名单）
				wantPerm := types.Allowed
				if tt.listType == types.Blacklist {
					wantPerm = types.Denied
				}
				if perm != wantPerm {
					t.Fatalf("期望 %s，得到 %s", wantPerm, perm)
				}
			} else {
				// no-op：未添加，黑名单默认 Allowed
				if tt.listType == types.Blacklist && perm != types.Allowed {
					t.Fatalf("no-op 后黑名单应 Allowed，得到 %s", perm)
				}
			}
		})
	}
}

// TestNewDomainACLWithDefaults 测试带预定义集合的构造函数
func TestNewDomainACLWithDefaults(t *testing.T) {
	t.Run("黑名单阻止短链与一次性邮箱", func(t *testing.T) {
		acl, err := NewDomainACLWithDefaults(
			[]string{"malware.example.com"},
			types.Blacklist,
			true,
			[]PredefinedSet{Shorteners, DisposableEmail},
			false,
		)
		if err != nil {
			t.Fatalf("非期望错误: %v", err)
		}
		for _, d := range []string{"bit.ly", "mailinator.com", "malware.example.com"} {
			if perm, _ := acl.Check(d); perm != types.Denied {
				t.Fatalf("期望 %s 被 Denied，得到 %s", d, perm)
			}
		}
		// 不在列表中的域名应 Allowed
		if perm, _ := acl.Check("innocent.example.org"); perm != types.Allowed {
			t.Fatalf("期望 innocent 域 Allowed，得到 %s", perm)
		}
	})
	t.Run("无效预定义集合名返回错误", func(t *testing.T) {
		_, err := NewDomainACLWithDefaults(
			[]string{},
			types.Blacklist,
			false,
			[]PredefinedSet{PredefinedSet("nonexistent_set")},
			false,
		)
		if err == nil || !errors.Is(err, ErrInvalidPredefinedSet) {
			t.Fatalf("期望 ErrInvalidPredefinedSet，得到 %v", err)
		}
	})
}
```

- [ ] **Step 5: 验证 DomainACL 预定义方法**
Run: `go test ./pkg/domain/ -run 'TestAddPredefinedSet|TestNewDomainACLWithDefaults' -v`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 6: 回归验证域名包全量测试**
Run: `go test ./pkg/domain/ -v`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "FAIL"

- [ ] **Step 7: 提交**
Run: `git add pkg/domain/domain.go pkg/domain/domain_test.go && git commit -m "feat(domain): add AddPredefinedSet and NewDomainACLWithDefaults on DomainACL"`

---

### Task 3: Manager 增加域名预定义集合转发方法

**Depends on:** Task 2
**Files:**
- Modify: `pkg/acl/manager.go`（新增 `SetDomainACLWithDefaults` 与 `AddPredefinedDomainSet`）
- Modify: `pkg/acl/manager_test.go`（追加对应测试）

- [ ] **Step 1: 在 manager.go 新增 SetDomainACLWithDefaults 方法**

文件: `pkg/acl/manager.go`（在 `SetDomainACL` 方法之后、`SetIPACL` 方法之前插入；对齐 `SetIPACLWithDefaults` 的签名与文档风格）

```go
// SetDomainACLWithDefaults 设置域名访问控制列表，并包含预定义的域名集合
//
// 参数:
//   - domains: 自定义的域名列表
//   - listType: 列表类型（黑名单或白名单）
//   - includeSubdomains: 是否包含子域名匹配
//   - predefinedSets: 要包含的预定义域名集合
//     例如: []domain.PredefinedSet{domain.Shorteners, domain.DisposableEmail}
//   - allowDefaultSets: 预定义集合的处理方式
//   - 对于黑名单，false 表示阻止这些域名（添加到黑名单）
//   - 对于白名单，true 表示允许这些域名（添加到白名单）
//
// 返回:
//   - error: ErrInvalidPredefinedSet 指定的预定义集合不存在
//
// 此方法会覆盖之前设置的任何域名访问控制列表，适合用于快速创建具有安全防护的域名 ACL。
//
// 示例:
//
//	// 创建黑名单，阻止短链与一次性邮箱域名
//	err := manager.SetDomainACLWithDefaults(
//	    []string{"malware.example.com"},
//	    types.Blacklist,
//	    true,
//	    []domain.PredefinedSet{
//	        domain.Shorteners,
//	        domain.DisposableEmail,
//	    },
//	    false,
//	)
func (m *Manager) SetDomainACLWithDefaults(domains []string, listType types.ListType, includeSubdomains bool, predefinedSets []domain.PredefinedSet, allowDefaultSets bool) error {
	newACL, err := domain.NewDomainACLWithDefaults(domains, listType, includeSubdomains, predefinedSets, allowDefaultSets)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acls[KindDomain] = newACL
	return nil
}
```

- [ ] **Step 2: 在 manager.go 新增 AddPredefinedDomainSet 方法**

文件: `pkg/acl/manager.go`（在 `AddPredefinedIPSet` 方法之后插入；对齐 `AddPredefinedIPSet` 的签名）

```go
// AddPredefinedDomainSet 向现有的域名访问控制列表添加一个预定义域名集合
// 如果当前没有设置域名访问控制列表，则会返回错误
//
// 参数:
//   - setName: 预定义集合名称
//     可用值: domain.Shorteners, domain.DisposableEmail, domain.AllMaliciousDomains 等
//   - allowSet: 预定义集合的处理方式
//   - 对于黑名单，false 表示阻止这些域名（添加到黑名单）
//   - 对于白名单，true 表示允许这些域名（添加到白名单）
//
// 返回:
//   - error: 可能的错误:
//   - types.ErrNoACL: 如果未设置域名 ACL
//   - domain.ErrInvalidPredefinedSet: 如果提供了无效的预定义集合名称
//
// 示例:
//
//	// 向黑名单添加短链域名（阻止访问）
//	err := manager.AddPredefinedDomainSet(domain.Shorteners, false)
//	// 向白名单添加可信 CDN 域名（允许访问）
//	err := manager.AddPredefinedDomainSet(domain.TrustedCDN, true)
func (m *Manager) AddPredefinedDomainSet(setName domain.PredefinedSet, allowSet bool) error {
	domA := m.domainACL()
	if domA == nil {
		return types.ErrNoACL
	}
	return domA.AddPredefinedSet(setName, allowSet)
}
```

- [ ] **Step 3: 在 manager_test.go 追加转发方法测试**

文件: `pkg/acl/manager_test.go`（在文件末尾追加）

```go
// TestManager_SetDomainACLWithDefaults 测试 Manager 带预定义集合的域名 ACL 设置
func TestManager_SetDomainACLWithDefaults(t *testing.T) {
	t.Run("黑名单阻止短链域名", func(t *testing.T) {
		m := NewManager()
		err := m.SetDomainACLWithDefaults(
			[]string{"malware.example.com"},
			types.Blacklist,
			true,
			[]domain.PredefinedSet{domain.Shorteners},
			false,
		)
		if err != nil {
			t.Fatalf("非期望错误: %v", err)
		}
		// 短链域名应被拒
		if perm, _ := m.CheckDomain("bit.ly"); perm != types.Denied {
			t.Fatalf("期望 bit.ly Denied，得到 %s", perm)
		}
		// 自定义恶意域名应被拒
		if perm, _ := m.CheckDomain("malware.example.com"); perm != types.Denied {
			t.Fatalf("期望 malware.example.com Denied，得到 %s", perm)
		}
		// 无关域名应允许
		if perm, _ := m.CheckDomain("innocent.example.org"); perm != types.Allowed {
			t.Fatalf("期望 innocent Allowed，得到 %s", perm)
		}
	})
	t.Run("无效预定义集合名返回错误", func(t *testing.T) {
		m := NewManager()
		err := m.SetDomainACLWithDefaults(
			[]string{}, types.Blacklist, true,
			[]domain.PredefinedSet{domain.PredefinedSet("nonexistent_set")}, false,
		)
		if err == nil || !errors.Is(err, domain.ErrInvalidPredefinedSet) {
			t.Fatalf("期望 ErrInvalidPredefinedSet，得到 %v", err)
		}
	})
}

// TestManager_AddPredefinedDomainSet 测试向已存在域名 ACL 追加预定义集合
func TestManager_AddPredefinedDomainSet(t *testing.T) {
	t.Run("追加短链集合到现有黑名单", func(t *testing.T) {
		m := NewManager()
		m.SetDomainACL([]string{"malware.example.com"}, types.Blacklist, true)
		err := m.AddPredefinedDomainSet(domain.Shorteners, false)
		if err != nil {
			t.Fatalf("非期望错误: %v", err)
		}
		if perm, _ := m.CheckDomain("bit.ly"); perm != types.Denied {
			t.Fatalf("追加后期望 bit.ly Denied，得到 %s", perm)
		}
	})
	t.Run("未设置域名ACL时返回ErrNoACL", func(t *testing.T) {
		m := NewManager()
		err := m.AddPredefinedDomainSet(domain.Shorteners, false)
		if !errors.Is(err, types.ErrNoACL) {
			t.Fatalf("期望 ErrNoACL，得到 %v", err)
		}
	})
	t.Run("无效集合名返回ErrInvalidPredefinedSet", func(t *testing.T) {
		m := NewManager()
		m.SetDomainACL([]string{}, types.Blacklist, true)
		err := m.AddPredefinedDomainSet(domain.PredefinedSet("nonexistent_set"), false)
		if !errors.Is(err, domain.ErrInvalidPredefinedSet) {
			t.Fatalf("期望 ErrInvalidPredefinedSet，得到 %v", err)
		}
	})
}
```

- [ ] **Step 4: 验证 Manager 域名预定义方法**
Run: `go test ./pkg/acl/ -run 'TestManager_SetDomainACLWithDefaults|TestManager_AddPredefinedDomainSet' -v`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 5: 回归验证 acl 包全量测试**
Run: `go test ./pkg/acl/ -v`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "FAIL"

- [ ] **Step 6: 提交**
Run: `git add pkg/acl/manager.go pkg/acl/manager_test.go && git commit -m "feat(acl): add SetDomainACLWithDefaults and AddPredefinedDomainSet on Manager"`

---

### Task 4: JSON Policy 域名侧支持预定义集合

**Depends on:** Task 3
**Files:**
- Modify: `pkg/config/json.go:11-17`（`DomainPolicy` 增 `PredefinedSets`/`AllowPredefined` 字段）
- Modify: `pkg/acl/policy.go:35-50`（`ApplyPolicy` 域名块仿 IP 块分支）
- Modify: `pkg/acl/policy_test.go`（追加 WithPredefined 测试）

- [ ] **Step 1: 扩展 DomainPolicy 增加预定义集合字段**

文件: `pkg/config/json.go:8-17`（替换整个 `DomainPolicy` 结构体定义，新增字段带 omitempty 保持向后兼容）

```go
// DomainPolicy 描述一份域名 ACL 配置
//
// ListType 取 "blacklist" 或 "whitelist"；IncludeSubdomains 控制子域名匹配。
// PredefinedSets 引用预定义域名集合名（如 "shorteners"、"disposable_email"），
// 与 Domains 合并注入；AllowPredefined 控制黑/白名单语义（与 IP 侧一致）。
type DomainPolicy struct {
	Domains           []string `json:"domains"`
	ListType          string   `json:"listType"`
	IncludeSubdomains bool     `json:"includeSubdomains"`
	// PredefinedSets 引用预定义域名集合名，可选；为空时不注入预定义集合
	PredefinedSets []string `json:"predefinedSets,omitempty"`
	// AllowPredefined 预定义集合的处理方式：黑名单 false=阻止，白名单 true=允许
	AllowPredefined bool `json:"allowPredefined,omitempty"`
	// File 可选：从该文件加载域名规则，与 Domains 合并
	File string `json:"file,omitempty"`
}
```

- [ ] **Step 2: 重写 ApplyPolicy 域名块以支持预定义集合**

文件: `pkg/acl/policy.go:35-50`（替换 `if p.Domain != nil { ... }` 整个块；仿 IP 块的"有预定义集合用 WithDefaults，否则用普通 Set"分支）

```go
	if p.Domain != nil {
		listType, err := parseListType(p.Domain.ListType)
		if err != nil {
			return fmt.Errorf("domain listType: %w", err)
		}
		domains := p.Domain.Domains
		// 若配置了 File，从文件追加加载域名（与显式 Domains 合并）；在读文件阶段失败则不注入
		if p.Domain.File != "" {
			fileDomains, err := config.ReadIPACL(p.Domain.File)
			if err != nil {
				return fmt.Errorf("load domain file %q: %w", p.Domain.File, err)
			}
			domains = append(domains, fileDomains...)
		}
		var predefinedSets []domain.PredefinedSet
		for _, name := range p.Domain.PredefinedSets {
			predefinedSets = append(predefinedSets, domain.PredefinedSet(name))
		}
		// 有预定义集合用 SetDomainACLWithDefaults，否则用 SetDomainACL；一次性注入合并后的 domains
		if len(predefinedSets) > 0 {
			if err := m.SetDomainACLWithDefaults(domains, listType, p.Domain.IncludeSubdomains, predefinedSets, p.Domain.AllowPredefined); err != nil {
				return fmt.Errorf("apply domain policy: %w", err)
			}
		} else {
			m.SetDomainACL(domains, listType, p.Domain.IncludeSubdomains)
		}
	}
```

- [ ] **Step 3: 在 policy_test.go 追加域名预定义集合测试**

文件: `pkg/acl/policy_test.go`（在文件末尾追加）

```go
// TestApplyPolicy_DomainWithPredefined 测试从 Policy 注入带预定义集合的域名 ACL
func TestApplyPolicy_DomainWithPredefined(t *testing.T) {
	t.Run("黑名单带短链预定义集合", func(t *testing.T) {
		m := NewManager()
		pol := &config.Policy{
			Domain: &config.DomainPolicy{
				Domains:           []string{"malware.example.com"},
				ListType:          "blacklist",
				IncludeSubdomains: true,
				PredefinedSets:    []string{"shorteners", "disposable_email"},
				AllowPredefined:   false,
			},
		}
		if err := m.ApplyPolicy(pol); err != nil {
			t.Fatalf("非期望错误: %v", err)
		}
		// 短链域名应被拒
		if perm, _ := m.CheckDomain("bit.ly"); perm != types.Denied {
			t.Fatalf("期望 bit.ly Denied，得到 %s", perm)
		}
		// 一次性邮箱域名应被拒
		if perm, _ := m.CheckDomain("mailinator.com"); perm != types.Denied {
			t.Fatalf("期望 mailinator.com Denied，得到 %s", perm)
		}
		// 自定义恶意域名应被拒
		if perm, _ := m.CheckDomain("malware.example.com"); perm != types.Denied {
			t.Fatalf("期望 malware.example.com Denied，得到 %s", perm)
		}
		// 无关域名应允许
		if perm, _ := m.CheckDomain("innocent.example.org"); perm != types.Allowed {
			t.Fatalf("期望 innocent Allowed，得到 %s", perm)
		}
	})
	t.Run("无效预定义集合名返回错误", func(t *testing.T) {
		m := NewManager()
		pol := &config.Policy{
			Domain: &config.DomainPolicy{
				Domains:        []string{},
				ListType:       "blacklist",
				PredefinedSets: []string{"nonexistent_set"},
			},
		}
		err := m.ApplyPolicy(pol)
		if err == nil {
			t.Fatal("期望错误，得到 nil")
		}
		// 错误信息应来自 apply domain policy 包装
		if !strings.Contains(err.Error(), "apply domain policy") {
			t.Fatalf("错误应包装 apply domain policy，得到 %v", err)
		}
	})
}
```

- [ ] **Step 4: 验证 Policy 域名预定义集成**
Run: `go test ./pkg/acl/ -run 'TestApplyPolicy_DomainWithPredefined' -v`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 5: 回归验证 config 与 acl 包全量测试**
Run: `go test ./pkg/config/ ./pkg/acl/ -v`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "FAIL"

- [ ] **Step 6: 提交**
Run: `git add pkg/config/json.go pkg/acl/policy.go pkg/acl/policy_test.go && git commit -m "feat(config): support predefined domain sets in JSON Policy and ApplyPolicy"`

---

### Task 5: 示例与文档

**Depends on:** Task 4
**Files:**
- Create: `examples/09_domain_predefined_sets/main.go`
- Modify: `README.md`（追加域名预定义集合章节）
- Modify: `.gitignore`（追加 `/09_domain_predefined_sets`）

- [ ] **Step 1: 创建示例 main.go — 演示域名预定义集合端到端用法**

```go
package main

import (
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/domain"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
	manager := acl.NewManager()

	// 创建黑名单：阻止短链、一次性邮箱域名，并阻止自定义恶意域名
	// allowDefaultSets=false 表示将这些预定义集合加入黑名单（阻止访问）
	err := manager.SetDomainACLWithDefaults(
		[]string{"malware.example.com", "phishing.example.net"},
		types.Blacklist,
		true, // 含子域名：bit.ly 的子域名也阻止
		[]domain.PredefinedSet{
			domain.Shorteners,
			domain.DisposableEmail,
		},
		false,
	)
	if err != nil {
		fmt.Printf("设置域名 ACL 失败: %v\n", err)
		return
	}

	// 运行时追加一个预定义集合（无需重建整个 ACL）
	if err := manager.AddPredefinedDomainSet(domain.AllMaliciousDomains, false); err != nil {
		fmt.Printf("追加预定义集合失败: %v\n", err)
		return
	}

	// 检查若干域名
	samples := []string{
		"bit.ly",            // 短链 → Denied
		"mailinator.com",    // 一次性邮箱 → Denied
		"malware.example.com",
		"github.com",         // 代码托管（AllMaliciousDomains 含 CodeHosting）→ Denied
		"innocent.example.org",
	}
	for _, d := range samples {
		perm, _ := manager.CheckDomain(d)
		fmt.Printf("CheckDomain(%-25s) => %s\n", d, perm)
	}

	// 同时可结合 JSON Policy 一次性配置（见 testdata 与 example 08）
	fmt.Println("域名预定义集合能力演示完成")
}
```

- [ ] **Step 2: 验证示例可构建运行**
Run: `go build ./examples/09_domain_predefined_sets/ && go vet ./examples/09_domain_predefined_sets/`
Expected:
  - Exit code: 0
  - Output does NOT contain: "error" or "FAIL"

- [ ] **Step 3: 在 .gitignore 追加示例二进制忽略规则**

文件: `.gitignore`（在 `# Build output` 区域、`/08_http_middleware` 规则之后追加）

```text
/09_domain_predefined_sets
```

- [ ] **Step 4: 在 README.md 追加域名预定义集合章节**

文件: `README.md`（在"## 🌐 HTTP 中间件"章节之后、文件末尾之前插入）

```markdown
## 🏷️ 域名预定义集合

域名 ACL 提供与 IP 侧对称的预定义域名集合，一键阻止/放行常见高风险或可信域名类别：

| 集合常量 | 含义 |
|---------|------|
| `domain.Shorteners` | URL 短链服务（bit.ly、tinyurl.com 等） |
| `domain.PublicFileSharing` | 公共网盘/文件分享（dropbox.com、mega.nz 等） |
| `domain.CodeHosting` | 代码托管平台（github.com、gitlab.com 等） |
| `domain.SocialMedia` | 主流社交媒体 |
| `domain.WebmailProviders` | 网页邮箱服务 |
| `domain.TorExitNodes` | Tor 相关域名 |
| `domain.DisposableEmail` | 一次性邮箱 |
| `domain.TrustedCDN` | 可信公共 CDN |
| `domain.AllMaliciousDomains` | 上述高风险类别的去重合集 |

### 编程式用法

```go
manager := acl.NewManager()
err := manager.SetDomainACLWithDefaults(
    []string{"malware.example.com"},
    types.Blacklist, true,
    []domain.PredefinedSet{domain.Shorteners, domain.DisposableEmail},
    false, // 加入黑名单阻止
)
// 运行时追加
manager.AddPredefinedDomainSet(domain.AllMaliciousDomains, false)
```

### JSON Policy 用法

```json
{
  "domain": {
    "domains": ["malware.example.com"],
    "listType": "blacklist",
    "includeSubdomains": true,
    "predefinedSets": ["shorteners", "disposable_email"],
    "allowPredefined": false
  }
}
```

完整示例见 `examples/09_domain_predefined_sets/`。
```

- [ ] **Step 5: 全量回归验证**
Run: `go build ./... && go test ./... && go test -race ./... && golangci-lint run ./...`
Expected:
  - Exit code: 0
  - Output contains: "ok" for all packages
  - Output does NOT contain: "FAIL" or "error" or lint warnings

- [ ] **Step 6: 提交**
Run: `git add examples/09_domain_predefined_sets/main.go README.md .gitignore && git commit -m "docs: add domain predefined sets example and README section"`

---

## 完成标准

- [ ] 所有 5 个 Task 完成，每个 Task 有独立 commit
- [ ] `go build ./...` 通过
- [ ] `go test ./...` 全绿
- [ ] `go test -race ./...` 全绿
- [ ] `golangci-lint run ./...` 零告警
- [ ] 域名 ACL 能力与 IP 侧对称：预定义集合定义、`AddPredefinedSet`、`NewWithDefaults`、Manager 转发、JSON Policy 集成
- [ ] 所有现有测试保持通过（无回归）
