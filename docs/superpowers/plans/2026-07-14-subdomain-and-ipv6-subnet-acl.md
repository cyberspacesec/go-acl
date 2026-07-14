# 子域名 ACL 增强 + IPv4/IPv6 子网访问控制完善 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 在不破坏 `types.MutableACL` 接口契约的前提下，补齐子域名 ACL 的通配符/仅子域/末尾点归一化能力，并完善 IPv4/IPv6 子网访问控制——修复 `ErrInvalidCIDR` 不可达 bug、补齐 IPv6 规范化与 zone id 处理、新增 trie 反查（Lookup）、并大幅加固 IPv6 与子网边界的测试覆盖。

**Architecture:** 域名侧：`normalizeDomain` 增末尾点剥离 + 通配符 `*.example.com` 规则识别；`matchDomain` 增通配分支与"仅子域不含主域"语义——采用最小侵入方案（在规则串层面识别 `*.` 前缀，存入独立 `wildcardSuffixes` 切片，不改 `domains`/`domainSet` 双轨主结构），保持 `Add/Remove/GetRules` 接口签名不变。IP 侧：`parseIPRange` 修含 `/` 串优先返回 `ErrInvalidCIDR`；新增 `normalizeIPString` 用于去重/Remove 的规范化（解决 `2001:db8::1` vs `2001:0db8::0001` 不一致）；`normalizeForParse` 剥离 zone id（`fe80::1%eth0`）；`trieNode.terminal bool` 升级为 `payload *net.IPNet`，新增 `Lookup` 返回最长匹配前缀。数据流：用户输入 → `normalizeDomain`/`parseIPRange` 归一化 → `Add` 存入结构 + 同步 trie/通配表 → `Check`/`Lookup` 查询 → `DecideByListType` 统一决策。复用现有 trie 前缀语义，不引入新依赖（zone 剥离用标准库 `strings`，不引 `netip`）。

**Tech Stack:** Go 1.18+，仅标准库（`net`、`strings`、`errors`、`fmt`、`sync`、`testing`、`math/rand`），表驱动测试，Conventional Commits

**Risks:**
- Task 2（通配符语义）需改 `matchDomain` 核心匹配——可能影响现有 `TestComplexSubdomainMatching`/`TestDomainACL_Check` → 缓解：通配规则走独立分支，非通配规则行为字节不变；先跑全量基线测试再改
- Task 4（trie payload 升级）改 `terminal bool`→`payload *net.IPNet`，影响 `insertPath`/`containsPath` → 缓解：`Contains` 仍返回 bool 语义不变，仅新增 `Lookup`；O(prefixLen) 不变
- Task 3 修 `ErrInvalidCIDR` 会改变 `parseIPRange` 对含 `/` 无效串的返回错误类型 → 缓解：同步修正 `ip_test.go` 死字段 `errType` 断言（当前从未被断言），补真实 `errors.Is` 断言
- IPv4-mapped IPv6（`::ffff:x.x.x.x`）经 `To4()` 走 v4 子树是既有隐式行为，本 Plan 不改变其语义，仅补测试固化

---

### Task 1: 域名末尾点归一化与 IDN 透传测试加固

**Depends on:** None
**Files:**
- Modify: `pkg/domain/domain.go:527-530`（normalizeDomain 末尾）
- Modify: `pkg/domain/domain_test.go`（追加末尾点测试到 TestNormalizeDomain 与 TestDomainACL_Check）

- [ ] **Step 1: 修改 normalizeDomain 以剥除末尾点 — FQDN root label 归一化**
文件: `pkg/domain/domain.go:527-530`（移除 www 前缀之后、return 之前）

```go
	// 移除www前缀
	domain = strings.TrimPrefix(domain, "www.")

	// 剥除末尾点（FQDN 根标签），使 example.com. 与 example.com 等价
	domain = strings.TrimSuffix(domain, ".")

	return domain
```

- [ ] **Step 2: 在 TestNormalizeDomain 追加末尾点用例 — 覆盖 FQDN 归一化**
文件: `pkg/domain/domain_test.go`（TestNormalizeDomain 的 tests 切片末尾追加两条）

```go
		{name: "末尾点-FQDN", input: "example.com.", want: "example.com"},
		{name: "末尾点-多重点", input: "sub.example.com.", want: "sub.example.com"},
```

- [ ] **Step 3: 在 TestDomainACL_Check 追加末尾点匹配用例 — 验证查询与规则双向归一**
文件: `pkg/domain/domain_test.go`（TestDomainACL_Check 表驱动用例末尾追加）

```go
		{
			name:           "末尾点查询匹配普通规则",
			domains:        []string{"blocked.com"},
			listType:       types.Blacklist,
			includeSub:     false,
			queryDomains:   []string{"blocked.com."},
			wantPerms:      []types.Permission{types.Denied},
		},
```

- [ ] **Step 4: 验证域名归一化**
Run: `go test ./pkg/domain/ -run 'TestNormalizeDomain|TestDomainACL_Check' -v`
Expected:
  - Exit code: 0
  - Output contains: "--- PASS" 且 "ok"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 5: 提交**
Run: `git add pkg/domain/domain.go pkg/domain/domain_test.go && git commit -m "fix(domain): normalize trailing dot in FQDN to unify root label matching"`

---

### Task 2: 修复 ErrInvalidCIDR 不可达 bug 并修正测试死字段断言

**Depends on:** None
**Files:**
- Modify: `pkg/ip/ip.go:521-559`（parseIPRange）
- Modify: `pkg/ip/ip_test.go:181-195, 198-206`（修正 errType 死字段 + 补 errors.Is 断言）

- [ ] **Step 1: 修改 parseIPRange 以优先返回 ErrInvalidCIDR — 含斜杠串不再误报 ErrInvalidIP**
文件: `pkg/ip/ip.go:521-559`（替换整个 parseIPRange 函数）

```go
func parseIPRange(ipStr string) (*IPRange, error) {
	ipStr = strings.TrimSpace(ipStr)

	// 含 "/" 视为 CIDR：解析失败一律返回 ErrInvalidCIDR，不回退到单 IP 解析
	if strings.Contains(ipStr, "/") {
		ip, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return nil, ErrInvalidCIDR
		}
		return &IPRange{
			Original: ipStr,
			IP:       ip,
			IPNet:    ipNet,
		}, nil
	}

	// 否则作为单个 IP 解析
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, ErrInvalidIP
	}

	// 创建一个只包含该IP的IPNet
	var mask net.IPMask
	if ip.To4() != nil {
		// IPv4使用/32掩码
		mask = net.CIDRMask(32, 32)
	} else {
		// IPv6使用/128掩码
		mask = net.CIDRMask(128, 128)
	}
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	return &IPRange{
		Original: ipStr,
		IP:       ip,
		IPNet:    ipNet,
	}, nil
}
```

- [ ] **Step 2: 修正 TestIPACL_Add 断言逻辑 — 把死字段 errType 改为真实 errors.Is 检查**
文件: `pkg/ip/ip_test.go:198-206`（替换 errType 检查逻辑块）

```go
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.acl.Add(tt.ipToAdd...)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("Add() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errType != nil {
				// 精确断言错误类型（修复此前 errType 从未被检查的死字段）
				if !errors.Is(err, tt.errType) {
					t.Errorf("Add() error = %v, 期望错误类型 %v", err, tt.errType)
					return
				}
			}

			if !tt.wantErr {
```

- [ ] **Step 3: 补 CIDR 错误边界用例 — 掩码越界 / 非法 CIDR 区分**
文件: `pkg/ip/ip_test.go:181-195`（在"添加无效的CIDR"用例后追加）

```go
		{
			name:         "添加IPv4掩码越界",
			acl:          initialACL,
			ipToAdd:      []string{"192.168.1.0/33"},
			wantErr:      true,
			errType:      ErrInvalidCIDR,
			expectedSize: 7,
		},
		{
			name:         "添加IPv6掩码越界",
			acl:          initialACL,
			ipToAdd:      []string{"2001:db8::/129"},
			wantErr:      true,
			errType:      ErrInvalidCIDR,
			expectedSize: 7,
		},
```

- [ ] **Step 4: 验证 CIDR 错误修正**
Run: `go test ./pkg/ip/ -run 'TestIPACL_Add|TestNewIPACL' -v`
Expected:
  - Exit code: 0
  - Output contains: "--- PASS" 且 "ok"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 5: 提交**
Run: `git add pkg/ip/ip.go pkg/ip/ip_test.go && git commit -m "fix(ip): return ErrInvalidCIDR for malformed CIDR and assert error type in tests"`

---

### Task 3: IPv6 规范化与 zone id 处理 + IPv6 子网边界测试加固

**Depends on:** None
**Files:**
- Modify: `pkg/ip/ip.go:199, 271, 521-559`（去重/Remove 用规范化 Original；parseIPRange 剥 zone）
- Modify: `pkg/ip/ip_test.go`（追加 IPv6 子网边界 + zone + 等价形式用例）

- [ ] **Step 1: 新增 normalizeIPString 辅助函数 — 统一 IPv6 表示用于去重与移除**
文件: `pkg/ip/ip.go`（在 parseIPRange 函数之后新增）

```go
// normalizeIPString 将 IP/CIDR 字符串规范化为稳定形式，
// 用于 Add 去重与 Remove 匹配，避免 2001:db8::1 与 2001:0db8::0001 被视为不同条目。
//
// 规则：剥除 zone id（如 %eth0），单 IP 用 net.IP.String() 规范化，
// CIDR 用 "网络地址/掩码" 形式。解析失败时原样返回（交由调用方报错）。
func normalizeIPString(s string) string {
	s = strings.TrimSpace(s)
	// 剥离 zone id：net.ParseIP 不支持 zone，fe80::1%eth0 → fe80::1
	if idx := strings.Index(s, "%"); idx != -1 {
		s = s[:idx]
	}
	if strings.Contains(s, "/") {
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return s
		}
		return ipNet.String()
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	return ip.String()
}
```

- [ ] **Step 2: 修改 parseIPRange 使用规范化 Original — 解决等价形式去重/移除不一致**
文件: `pkg/ip/ip.go:521-559`（在 Task 2 已重写的 parseIPRange 基础上，把两处 Original 赋值改为规范化值）

```go
func parseIPRange(ipStr string) (*IPRange, error) {
	normalized := normalizeIPString(ipStr)

	// 含 "/" 视为 CIDR：解析失败一律返回 ErrInvalidCIDR，不回退到单 IP 解析
	if strings.Contains(normalized, "/") {
		ip, ipNet, err := net.ParseCIDR(normalized)
		if err != nil {
			return nil, ErrInvalidCIDR
		}
		return &IPRange{
			Original: ipNet.String(),
			IP:       ip,
			IPNet:    ipNet,
		}, nil
	}

	// 否则作为单个 IP 解析
	ip := net.ParseIP(normalized)
	if ip == nil {
		return nil, ErrInvalidIP
	}

	// 创建一个只包含该IP的IPNet
	var mask net.IPMask
	if ip.To4() != nil {
		mask = net.CIDRMask(32, 32)
	} else {
		mask = net.CIDRMask(128, 128)
	}
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	return &IPRange{
		Original: ip.String(),
		IP:       ip,
		IPNet:    ipNet,
	}, nil
}
```

- [ ] **Step 3: 确认 Add 去重逻辑与规范化 Original 一致 — 等价形式现在能正确去重**
文件: `pkg/ip/ip.go:198-205`（去重块逻辑不变，但因 Step 2 已使 `ipRange.Original` 为规范化值，等价形式现在能正确去重，无需改动）

- [ ] **Step 4: 修改 Remove 以规范化形式匹配 — 等价形式可正确移除**
文件: `pkg/ip/ip.go:248-296`（替换整个 Remove 函数，`found` map 用规范化 key，比较两侧均规范化）

```go
func (a *IPACL) Remove(ipRanges ...string) error {
	if len(ipRanges) == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.ranges) == 0 {
		return ErrIPNotFound
	}

	// 跟踪是否找到所有要移除的IP（用规范化形式作 key，等价形式视为同一条）
	found := make(map[string]bool, len(ipRanges))
	for _, ipStr := range ipRanges {
		n := normalizeIPString(ipStr)
		if strings.TrimSpace(ipStr) == "" {
			continue
		}
		found[n] = false
	}

	// 创建新的IP范围列表，排除要移除的
	var newRanges []IPRange
	for _, existingRange := range a.ranges {
		keep := true
		for normKey := range found {
			if existingRange.Original == normKey {
				found[normKey] = true
				keep = false
				break
			}
		}
		if keep {
			newRanges = append(newRanges, existingRange)
		}
	}

	// 检查是否所有IP都找到了
	for normKey, wasFound := range found {
		if !wasFound && strings.TrimSpace(normKey) != "" {
			// 虽然有未找到的IP，但仍更新列表
			a.ranges = newRanges
			a.rebuildTrie()
			return ErrIPNotFound
		}
	}

	// 更新IPACL使用新的范围
	a.ranges = newRanges
	a.rebuildTrie()
	return nil
}
```

**注意**：`existingRange.Original` 在 Step 2 后已是规范化值，与 `normalizeIPString(ipStr)` 产出的规范化 key 直接可比。

- [ ] **Step 5: 追加 IPv6 子网边界与 zone id 测试 — 加固 IPv6 覆盖**
文件: `pkg/ip/ip_test.go`（文件末尾追加新测试函数）

```go
// TestIPv6SubnetBoundary 验证 IPv6 子网边界匹配
func TestIPv6SubnetBoundary(t *testing.T) {
	acl, err := NewIPACL([]string{"2001:db8::/32"}, types.Blacklist)
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	tests := []struct {
		name    string
		ip      string
		want    types.Permission
	}{
		{"网络地址", "2001:db8::", types.Denied},
		{"范围内首地址", "2001:db8::1", types.Denied},
		{"范围内末地址", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", types.Denied},
		{"范围外下一地址", "2001:db9::", types.Allowed},
		{"unspecified", "::", types.Allowed},
		{"link-local 单点未在规则中", "fe80::1", types.Allowed},
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

// TestIPv6ZoneID 验证 zone id 剥离后仍可匹配
func TestIPv6ZoneID(t *testing.T) {
	acl, err := NewIPACL([]string{"fe80::1"}, types.Blacklist)
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	// 带 zone id 的查询应剥除后匹配
	perm, err := acl.Check("fe80::1%eth0")
	if err != nil {
		t.Fatalf("Check(fe80::1%%eth0) 错误: %v", err)
	}
	if perm != types.Denied {
		t.Errorf("期望 fe80::1%%eth0 Denied，得到 %s", perm)
	}
}

// TestIPv6EquivalentForms 验证等价表示形式去重一致
func TestIPv6EquivalentForms(t *testing.T) {
	// 全写与压缩形式应被识别为同一条，去重后仅 1 条
	acl, err := NewIPACL([]string{"2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"}, types.Blacklist)
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if got := len(acl.GetIPRanges()); got != 1 {
		t.Errorf("等价 IPv6 应去重为 1 条，得到 %d 条: %v", got, acl.GetIPRanges())
	}
}
```

- [ ] **Step 6: 验证 IPv6 加固**
Run: `go test ./pkg/ip/ -run 'TestIPv6' -v`
Expected:
  - Exit code: 0
  - Output contains: "--- PASS"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 7: 提交**
Run: `git add pkg/ip/ip.go pkg/ip/ip_test.go && git commit -m "feat(ip): normalize IPv6 forms and strip zone id for dedup/match with boundary tests"`

---

### Task 4: trie 反查能力（Lookup 最长前缀匹配）

**Depends on:** Task 3
**Files:**
- Modify: `pkg/ip/trie.go:21-25, 32-55, 76-106`（节点 payload + Insert + Lookup）
- Modify: `pkg/ip/ip.go`（新增 IPACL.Lookup + Manager.LookupIP 透传）
- Modify: `pkg/acl/manager.go`（LookupIP 方法）
- Test: `pkg/ip/trie_test.go`（新建）, `pkg/acl/manager_test.go`（追加）

- [ ] **Step 1: 修改 trieNode 以存储 payload — 支持 CIDR 反查**
文件: `pkg/ip/trie.go:21-25`（替换 trieNode 定义）

```go
type trieNode struct {
	left     *trieNode // bit 0
	right    *trieNode // bit 1
	terminal bool      // 某 CIDR 前缀在此节点结束
	payload  *net.IPNet // 命中时对应的 CIDR（仅 terminal 为 true 时有效）
}
```

- [ ] **Step 2: 修改 insertPath 以写入 payload — 插入时记录 CIDR**
文件: `pkg/ip/trie.go:57-73`（替换 insertPath 函数，签名加 ipNet 参数）

```go
// insertPath 从 root 沿 bits 的前 ones 位下沉，末节点置 terminal 并存 payload
func insertPath(root *trieNode, bits []byte, ones int, ipNet *net.IPNet) {
	node := root
	for i := 0; i < ones; i++ {
		if getBit(bits, i) {
			if node.right == nil {
				node.right = &trieNode{}
			}
			node = node.right
		} else {
			if node.left == nil {
				node.left = &trieNode{}
			}
			node = node.left
		}
	}
	node.terminal = true
	node.payload = ipNet
}
```

- [ ] **Step 3: 修改 Insert 调用以传递 ipNet — v4/v6 两条路径同步**
文件: `pkg/ip/trie.go:32-55`（替换 Insert 函数）

```go
// Insert 将一个 CIDR 插入 trie
func (t *ipTrie) Insert(ipNet *net.IPNet) {
	if ipNet == nil {
		return
	}
	ones, _ := ipNet.Mask.Size()
	if ip4 := ipNet.IP.To4(); ip4 != nil {
		bits := ip4
		if ones < 0 || ones > 32 {
			ones = 32
		}
		insertPath(t.v4Root, bits, ones, ipNet)
	} else {
		bits := ipNet.IP.To16()
		if ones < 0 || ones > 128 {
			ones = 128
		}
		insertPath(t.v6Root, bits, ones, ipNet)
	}
}
```

- [ ] **Step 4: 新增 Lookup 方法 — 返回最长匹配前缀的 CIDR**
文件: `pkg/ip/trie.go`（在 Contains 函数之后新增）

```go
// Lookup 返回包含该 IP 的最长前缀匹配 CIDR；无匹配返回 nil
func (t *ipTrie) Lookup(ip net.IP) *net.IPNet {
	if ip4 := ip.To4(); ip4 != nil {
		return lookupPath(t.v4Root, ip4, 32)
	}
	return lookupPath(t.v6Root, ip.To16(), 128)
}

// lookupPath 沿 IP 位下沉，记录最后一个 terminal 节点的 payload 作为最长匹配
func lookupPath(root *trieNode, bits []byte, maxBits int) *net.IPNet {
	node := root
	var match *net.IPNet
	for i := 0; i < maxBits && node != nil; i++ {
		if node.terminal {
			match = node.payload
		}
		if getBit(bits, i) {
			node = node.right
		} else {
			node = node.left
		}
	}
	// 检查末节点本身（/32 或 /128 精确命中）
	if node != nil && node.terminal {
		match = node.payload
	}
	return match
}
```

- [ ] **Step 5: 新增 IPACL.Lookup 与 Manager.LookupIP — 暴露反查能力**
文件: `pkg/ip/ip.go`（在 Check 方法之后新增）

```go
// Lookup 返回包含该 IP 的最长前缀匹配 CIDR 规则串；无匹配返回 ""
func (a *IPACL) Lookup(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", ErrInvalidIP
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if ipNet := a.trie.Lookup(parsed); ipNet != nil {
		return ipNet.String(), nil
	}
	return "", nil
}
```

文件: `pkg/acl/manager.go`（在 CheckIP 方法之后新增）

```go
// LookupIP 返回包含该 IP 的最长前缀匹配 CIDR；未配置 IP ACL 或无匹配返回空串
func (m *Manager) LookupIP(ip string) (string, error) {
	ipAcl := m.ipACL()
	if ipAcl == nil {
		return "", types.ErrNoACL
	}
	return ipAcl.Lookup(ip)
}
```

- [ ] **Step 6: 创建 trie_test.go — 验证 Lookup 与最长前缀语义**
文件: `pkg/ip/trie_test.go`（新建）

```go
package ip

import (
	"net"
	"testing"
)

func TestTrieLookup_LongestPrefix(t *testing.T) {
	tr := newIPTrie()
	// 插入 10.0.0.0/8 与 10.1.0.0/16，10.1.2.3 应匹配更具体的 /16
	tr.Insert(parseCIDR(t, "10.0.0.0/8"))
	tr.Insert(parseCIDR(t, "10.1.0.0/16"))

	got := tr.Lookup(net.ParseIP("10.1.2.3"))
	if got == nil || got.String() != "10.1.0.0/16" {
		t.Fatalf("期望 10.1.0.0/16，得到 %v", got)
	}
	// 10.2.0.1 仅匹配 /8
	got = tr.Lookup(net.ParseIP("10.2.0.1"))
	if got == nil || got.String() != "10.0.0.0/8" {
		t.Fatalf("期望 10.0.0.0/8，得到 %v", got)
	}
	// 192.168.0.1 无匹配
	got = tr.Lookup(net.ParseIP("192.168.0.1"))
	if got != nil {
		t.Fatalf("期望 nil，得到 %v", got)
	}
}

func TestTrieLookup_IPv6(t *testing.T) {
	tr := newIPTrie()
	tr.Insert(parseCIDR(t, "2001:db8::/32"))
	got := tr.Lookup(net.ParseIP("2001:db8::1"))
	if got == nil || got.String() != "2001:db8::/32" {
		t.Fatalf("期望 2001:db8::/32，得到 %v", got)
	}
}

func parseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%s): %v", s, err)
	}
	return n
}
```

- [ ] **Step 7: 在 manager_test.go 追加 LookupIP 测试**
文件: `pkg/acl/manager_test.go`（末尾追加）

```go
func TestManager_LookupIP(t *testing.T) {
	m := NewManager()
	// 未配置时返回 ErrNoACL
	_, err := m.LookupIP("10.0.0.1")
	if !errors.Is(err, types.ErrNoACL) {
		t.Fatalf("期望 ErrNoACL，得到 %v", err)
	}
	// 配置后返回最长前缀
	if err := m.SetIPACL([]string{"10.0.0.0/8", "10.1.0.0/16"}, types.Blacklist); err != nil {
		t.Fatal(err)
	}
	got, err := m.LookupIP("10.1.2.3")
	if err != nil || got != "10.1.0.0/16" {
		t.Fatalf("期望 10.1.0.0/16 无错，得到 %q err=%v", got, err)
	}
}
```

- [ ] **Step 8: 验证 trie 反查**
Run: `go test ./pkg/ip/ -run 'TestTrieLookup' -v && go test ./pkg/acl/ -run 'TestManager_LookupIP' -v`
Expected:
  - Exit code: 0
  - Output contains: "--- PASS"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 9: 全量回归确保 Contains 语义未破坏**
Run: `go test ./... 2>&1 | tail -10`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "FAIL"

- [ ] **Step 10: 提交**
Run: `git add pkg/ip/trie.go pkg/ip/ip.go pkg/acl/manager.go pkg/ip/trie_test.go pkg/acl/manager_test.go && git commit -m "feat(ip): add trie longest-prefix Lookup and IPACL/Manager.LookupIP for CIDR reverse-lookup"`

---

### Task 5: 域名通配符与仅子域名语义

**Depends on:** Task 1
**Files:**
- Modify: `pkg/domain/domain.go:37-45, 167-220, 248-290, 424-456`（结构加 wildcardSuffixes；Add/Remove/matchDomain 增通配分支）
- Modify: `pkg/domain/domain_test.go`（追加通配符与仅子域测试）

- [ ] **Step 1: 修改 DomainACL 结构以增加通配后缀表 — 最小侵入隔离通配规则**
文件: `pkg/domain/domain.go:37-45`（替换结构定义）

```go
type DomainACL struct {
	mu                sync.RWMutex
	domains           []string            // 有序普通规则切片
	domainSet         map[string]struct{} // 普通规则 set 镜像，精确匹配 O(1)
	wildcardSuffixes  []string            // 通配规则（*.example.com）的裸后缀表，后缀匹配用
	listType          types.ListType
	includeSubdomains bool
}
```

- [ ] **Step 2: 新增 isWildcardDomain 辅助函数 — 识别 *.example.com 形式**
文件: `pkg/domain/domain.go`（在 normalizeDomain 之前新增）

```go
// isWildcardDomain 判断规则是否为通配形式 *.example.com
func isWildcardDomain(d string) bool {
	return strings.HasPrefix(d, "*.")
}

// stripWildcard 去除 *. 前缀，返回裸后缀
func stripWildcard(d string) string {
	return strings.TrimPrefix(d, "*.")
}
```

- [ ] **Step 3: 修改 Add 以分流通配规则 — 普通规则进主表，通配规则进后缀表**
文件: `pkg/domain/domain.go:167-220`（替换 Add 函数中遍历 ipRanges 的循环体核心；保留函数签名与并发锁）

```go
func (d *DomainACL) Add(domains ...string) error {
	if len(domains) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, domain := range domains {
		normalized := normalizeDomain(domain)
		if normalized == "" {
			continue
		}

		if isWildcardDomain(normalized) {
			// 通配规则 *.example.com → 存裸后缀 example.com，仅匹配其子域
			suffix := stripWildcard(normalized)
			if suffix == "" {
				continue
			}
			// 去重
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

		// 普通规则进主表
		if _, ok := d.domainSet[normalized]; ok {
			continue
		}
		d.domainSet[normalized] = struct{}{}
		d.domains = append(d.domains, normalized)
	}

	return nil
}
```

- [ ] **Step 4: 修改 Remove 以支持移除通配规则 — 分流通配与普通删除**
文件: `pkg/domain/domain.go:222-267`（替换整个 Remove 函数）

```go
func (d *DomainACL) Remove(domains ...string) error {
	// 零参数：no-op，不视为错误
	if len(domains) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// 构建待删除的标准化集合，区分通配与普通
	var wildcardToRemove []string
	toRemove := make(map[string]struct{}, len(domains))
	for _, dom := range domains {
		n := normalizeDomain(dom)
		if n == "" {
			continue
		}
		if isWildcardDomain(n) {
			wildcardToRemove = append(wildcardToRemove, stripWildcard(n))
		} else {
			toRemove[n] = struct{}{}
		}
	}
	// 传入了参数但全部标准化后为空：视为未找到
	if len(toRemove) == 0 && len(wildcardToRemove) == 0 {
		return ErrDomainNotFound
	}

	removed := 0

	// 先处理通配删除
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

	// 再处理普通删除
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

**注意**：`d.wildcardSuffixes[:0]` 复用底层数组就地过滤——与既有 Remove 的"重建切片"风格一致；当 `wildcardToRemove` 与 `toRemove` 都为空时仍返回 `ErrDomainNotFound`，保持旧语义。

- [ ] **Step 5: 修改 matchDomain 以处理通配后缀 — 仅子域不含主域语义**
文件: `pkg/domain/domain.go:424-456`（在 matchDomain 返回前增加通配检查；保留既有精确/后缀逻辑）

```go
func (d *DomainACL) matchDomain(domain string) bool {
	// 通配规则：*.example.com 仅匹配 example.com 的子域，不含 example.com 本身
	for _, suffix := range d.wildcardSuffixes {
		if strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}

	if !d.includeSubdomains {
		// 精确匹配
		_, ok := d.domainSet[domain]
		return ok
	}

	// 后缀匹配（含主域本身）
	for _, aclDomain := range d.domains {
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

- [ ] **Step 6: 修改 GetDomains 以包含通配规则 — GetRules 委托 GetDomains 自动覆盖**
文件: `pkg/domain/domain.go:320-332`（替换 GetDomains 函数；GetRules 直接 `return d.GetDomains()` 故无需改动）

```go
func (d *DomainACL) GetDomains() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]string, 0, len(d.domains)+len(d.wildcardSuffixes))
	result = append(result, d.domains...)
	for _, s := range d.wildcardSuffixes {
		result = append(result, "*."+s)
	}
	return result
}
```

**注意**：`GetRules`（`pkg/domain/domain.go:334`）实现为 `return d.GetDomains()`，故通配规则自动包含在 GetRules 返回中，无需单独修改。

- [ ] **Step 7: 追加通配符与仅子域测试 — 覆盖核心新语义**
文件: `pkg/domain/domain_test.go`（末尾追加）

```go
// TestDomainACL_Wildcard 验证 *.example.com 仅匹配子域不含主域
func TestDomainACL_Wildcard(t *testing.T) {
	acl := NewDomainACL([]string{"*.evil.com"}, types.Blacklist, false)
	// 子域命中
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Denied {
		t.Errorf("sub.evil.com 应 Denied，得到 %s", perm)
	}
	// 多层子域命中
	if perm, _ := acl.Check("a.b.evil.com"); perm != types.Denied {
		t.Errorf("a.b.evil.com 应 Denied，得到 %s", perm)
	}
	// 主域本身不命中（仅子域语义）
	if perm, _ := acl.Check("evil.com"); perm != types.Allowed {
		t.Errorf("evil.com 主域应 Allowed（仅子域），得到 %s", perm)
	}
	// 相邻域名不误匹配
	if perm, _ := acl.Check("notevil.com"); perm != types.Allowed {
		t.Errorf("notevil.com 应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_WildcardAndExactCoexist 验证通配与精确规则共存
func TestDomainACL_WildcardAndExactCoexist(t *testing.T) {
	acl := NewDomainACL([]string{"*.evil.com", "evil.com"}, types.Blacklist, false)
	// 主域被精确规则阻止
	if perm, _ := acl.Check("evil.com"); perm != types.Denied {
		t.Errorf("evil.com 精确规则应 Denied，得到 %s", perm)
	}
	// 子域被通配规则阻止
	if perm, _ := acl.Check("x.evil.com"); perm != types.Denied {
		t.Errorf("x.evil.com 通配应 Denied，得到 %s", perm)
	}
	// GetDomains 返回两类规则
	domains := acl.GetDomains()
	if len(domains) != 2 {
		t.Errorf("应返回 2 条规则，得到 %d: %v", len(domains), domains)
	}
}

// TestDomainACL_RemoveWildcard 验证移除通配规则
func TestDomainACL_RemoveWildcard(t *testing.T) {
	acl := NewDomainACL([]string{"*.evil.com"}, types.Blacklist, false)
	if err := acl.Remove("*.evil.com"); err != nil {
		t.Fatalf("移除失败: %v", err)
	}
	// 移除后子域不再命中
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Allowed {
		t.Errorf("移除后 sub.evil.com 应 Allowed，得到 %s", perm)
	}
}
```

- [ ] **Step 8: 验证通配符语义**
Run: `go test ./pkg/domain/ -run 'TestDomainACL_Wildcard|TestDomainACL_RemoveWildcard' -v`
Expected:
  - Exit code: 0
  - Output contains: "--- PASS"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 9: 全量回归确保既有域名行为未破坏**
Run: `go test ./pkg/domain/ -v 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "--- FAIL"

- [ ] **Step 10: 提交**
Run: `git add pkg/domain/domain.go pkg/domain/domain_test.go && git commit -m "feat(domain): support wildcard *.domain rules for subdomain-only matching"`

---

### Task 6: 示例与文档

**Depends on:** Task 4, Task 5
**Files:**
- Create: `examples/10_subdomain_acl/main.go`
- Create: `examples/11_ipv6_subnet_acl/main.go`
- Modify: `README.md`, `.gitignore`

- [ ] **Step 1: 创建子域名通配示例 — 演示 *.domain 仅子域控制**
文件: `examples/10_subdomain_acl/main.go`（新建）

```go
package main

import (
	"errors"
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
	fmt.Println("===== 子域名通配 ACL 示例 =====")

	m := acl.NewManager()
	// 阻止 *.evil.com 的所有子域，但放行 evil.com 主域本身
	m.SetDomainACL([]string{"*.evil.com"}, types.Blacklist, false)

	testDomains := []string{
		"evil.com",        // 主域：放行
		"phishing.evil.com", // 子域：阻止
		"a.b.evil.com",    // 多层子域：阻止
		"notevil.com",     // 相邻：放行
		"safe.org",        // 无关：放行
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

- [ ] **Step 2: 创建 IPv6/子网反查示例 — 演示 LookupIP 与 IPv6 子网**
文件: `examples/11_ipv6_subnet_acl/main.go`（新建）

```go
package main

import (
	"errors"
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
	fmt.Println("===== IPv6 子网 ACL 与反查示例 =====")

	m := acl.NewManager()
	// IPv4 + IPv6 子网混合黑名单
	if err := m.SetIPACL([]string{"10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32"}, types.Blacklist); err != nil {
		fmt.Printf("配置失败: %v\n", err)
		return
	}

	testIPs := []string{
		"10.1.2.3",         // 命中 /16（更具体）
		"10.2.0.1",         // 命中 /8
		"192.168.0.1",      // 无匹配
		"2001:db8::1",      // IPv6 子网命中
		"2001:db9::1",      // IPv6 无匹配
		"fe80::1%eth0",     // zone id 剥离后无匹配
	}
	fmt.Println("\n检查 + 反查最长前缀:")
	for _, ip := range testIPs {
		perm, err := m.CheckIP(ip)
		if err != nil && !errors.Is(err, types.ErrNoACL) {
			fmt.Printf("  %s: 检查失败 - %v\n", ip, err)
			continue
		}
		cidr, _ := m.LookupIP(ip)
		if perm == types.Denied {
			fmt.Printf("  %s: 拒绝 ✗ (匹配 %s)\n", ip, cidr)
		} else {
			fmt.Printf("  %s: 允许 ✓ (匹配 %q)\n", ip, cidr)
		}
	}
}
```

- [ ] **Step 3: 验证两个示例运行**
Run: `cd examples/10_subdomain_acl && go run main.go && cd ../11_ipv6_subnet_acl && go run main.go`
Expected:
  - Exit code: 0
  - 10 示例输出含 "拒绝访问 ✗"（phishing.evil.com）与 "允许访问 ✓"（evil.com）
  - 11 示例输出含 "10.1.0.0/16"

- [ ] **Step 4: 修改 README — 新增子域名通配与 IPv6 子网说明**
文件: `README.md`（在"### 域名控制"小节末尾追加通配说明；在"### IP控制"小节末尾追加 IPv6 子网与 LookupIP 说明）

域名控制小节追加：
```markdown
// 通配符规则 *.example.com 仅匹配子域，不含主域本身（适合"放行主站、阻止子域"场景）
manager.SetDomainACL([]string{"*.evil.com"}, types.Blacklist, false)
// evil.com 放行，phishing.evil.com 阻止
```

IP 控制小节追加：
```markdown
// IPv6 子网与 IPv4 混合；zone id 自动剥离
manager.SetIPACL([]string{"10.0.0.0/8", "2001:db8::/32"}, types.Blacklist)
// 反查 IP 所属最长前缀 CIDR
cidr, _ := manager.LookupIP("10.1.2.3") // "10.1.0.0/16"
```

示例表格追加两行（在 09 行之后）：
`| **子域名通配 ACL** | 演示 *.domain 仅子域访问控制 | [查看示例](examples/10_subdomain_acl/) |`
`| **IPv6 子网与反查** | 演示 IPv6 子网匹配与最长前缀反查 | [查看示例](examples/11_ipv6_subnet_acl/) |`

- [ ] **Step 5: 修改 .gitignore — 追加两个示例二进制**
文件: `.gitignore`（在 /09_domain_predefined_sets 之后追加）

```text
/10_subdomain_acl
/11_ipv6_subnet_acl
```

- [ ] **Step 6: 全量回归**
Run: `go build ./... && go test ./... 2>&1 | tail -10 && gofmt -l examples/10_subdomain_acl/ examples/11_ipv6_subnet_acl/`
Expected:
  - Exit code: 0
  - gofmt 输出为空
  - go test 全 ok，无 FAIL

- [ ] **Step 7: 提交**
Run: `git add examples/10_subdomain_acl/main.go examples/11_ipv6_subnet_acl/main.go README.md .gitignore && git commit -m "docs: add subdomain wildcard and IPv6 subnet lookup examples with README sections"`

---

## 向后兼容性与发行说明（semver 相关变更）

以下变更在提升错误准确性与语义的同时，对依赖既有（部分为错误）行为的下游用户构成可见的行为变化，发布时应在变更日志中标注：

1. **`parseIPRange` 对格式错误的 CIDR 现返回 `ErrInvalidCIDR`（此前因不可达 bug 返回 `ErrInvalidIP`）**
   - 影响范围：对含 `/` 的无效串（如 `192.168.1.0/33`）做 `errors.Is(err, ip.ErrInvalidIP)` 的调用方将不再命中；需改判 `ErrInvalidCIDR`。
   - 性质：修正与文档契约不符的既有 bug。内部调用方（`pkg/ip/file.go`）已同时检查两者，不受影响。

2. **Domain `Add` 将 `*.example.com` 识别为通配规则（仅匹配子域，不含主域）**
   - 影响范围：若调用方此前将 `"*.evil.com"` 作为字面域名添加（仅匹配字面串 `"*.evil.com"`），现改为匹配其所有子域。
   - 性质：字面星号域名非实际用例，实际影响极小；属语义增强。

3. **`normalizeDomain` 剥除末尾点（FQDN 根标签）**
   - `example.com.` 与 `example.com` 现等价。向后兼容的归一化增强，无负面影响。

4. **IPv6 等价形式归一与 zone id 剥离**
   - `2001:db8::1` 与 `2001:0db8:0000:...:0001` 视为同一条（去重/移除互通）；`fe80::1%eth0` 剥离 zone 后匹配。向后兼容增强。

以上 1、2 为 semver 相关（minor breaking），3、4 为纯增强。`MutableACL` 接口契约（`Check`/`GetListType`/`Add`/`Remove`/`GetRules`）与所有既有方法签名未变；新增的 `IPACL.Lookup` / `Manager.LookupIP` 为附加能力，不属于接口。

