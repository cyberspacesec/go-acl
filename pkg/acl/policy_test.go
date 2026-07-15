package acl

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// TestApplyPolicy_InvalidListType 验证非法 listType 报错且不污染 Manager
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
	// listType 非法时应早失败，不注入 Manager
	_, checkErr := manager.CheckDomain("x.com")
	if !errors.Is(checkErr, types.ErrNoACL) {
		t.Errorf("非法 listType 时 Manager 不应被污染，期望 ErrNoACL，得到 %v", checkErr)
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
	// 文件中的域名与行内域名都应生效
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

// TestApplyPolicy_DomainWildcard 验证从 JSON Policy 注入通配规则 *.domain 的端到端语义
func TestApplyPolicy_DomainWildcard(t *testing.T) {
	m := NewManager()
	pol := &config.Policy{
		Domain: &config.DomainPolicy{
			Domains:           []string{"*.evil.com"},
			ListType:          "blacklist",
			IncludeSubdomains: false,
		},
	}
	if err := m.ApplyPolicy(pol); err != nil {
		t.Fatalf("ApplyPolicy 失败: %v", err)
	}
	// 通配 *.evil.com 仅匹配子域，不含主域
	if perm, _ := m.CheckDomain("phishing.evil.com"); perm != types.Denied {
		t.Errorf("phishing.evil.com 应 Denied，得到 %s", perm)
	}
	if perm, _ := m.CheckDomain("evil.com"); perm != types.Allowed {
		t.Errorf("evil.com 主域应 Allowed（仅子域），得到 %s", perm)
	}
	if perm, _ := m.CheckDomain("notevil.com"); perm != types.Allowed {
		t.Errorf("notevil.com 应 Allowed，得到 %s", perm)
	}
}

// TestApplyPolicy_DomainPatterns 验证域名前缀/后缀/正则经 JSON Policy 端到端可用
func TestApplyPolicy_DomainPatterns(t *testing.T) {
	m := NewManager()
	pol := &config.Policy{
		Domain: &config.DomainPolicy{
			Domains: []string{
				"api.*",                  // 前缀
				"*evil.com",              // 宽松后缀（标签边界，含主域）
				`/^internal-\d+\.corp$/`, // 正则（匹配小写域名）
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
	if perm, _ := m.CheckDomain("sub.evil.com"); perm != types.Denied {
		t.Errorf("sub.evil.com 应 Denied，得到 %s", perm)
	}
	// 宽松后缀不误伤相邻域名
	if perm, _ := m.CheckDomain("notevil.com"); perm != types.Allowed {
		t.Errorf("notevil.com 应 Allowed，得到 %s", perm)
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
	if perm, _ := m.CheckIP("2001:db8::6"); perm != types.Allowed {
		t.Errorf("2001:db8::6 应 Allowed，得到 %s", perm)
	}
}
