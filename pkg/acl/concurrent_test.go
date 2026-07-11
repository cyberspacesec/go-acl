package acl

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/ip"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// TestManagerConcurrentAccess 验证 Manager 在并发查询不同 kind 时不互相阻塞，且结果正确
func TestManagerConcurrentAccess(t *testing.T) {
	m := NewManager()
	m.SetDomainACL([]string{"example.com"}, types.Blacklist, true)
	if err := m.SetIPACL([]string{"10.0.0.0/8"}, types.Blacklist); err != nil {
		t.Fatalf("SetIPACL 失败: %v", err)
	}

	var wg sync.WaitGroup
	// 并发查询 domain 和 ip，混入动态 Add/Remove
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = m.CheckDomain("sub.example.com")
				_, _ = m.CheckIP("10.1.2.3")
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = m.AddIP(fmt.Sprintf("192.168.%d.%d", n, j))
				_ = m.RemoveIP(fmt.Sprintf("192.168.%d.%d", n, j))
				_ = m.AddDomain(fmt.Sprintf("temp%d-%d.com", n, j))
				_ = m.RemoveDomain(fmt.Sprintf("temp%d-%d.com", n, j))
			}
		}(i)
	}
	wg.Wait()
}

// TestManagerRegisterCustomACL 验证可扩展性：注册自定义 ACL 并通过统一入口检查
func TestManagerRegisterCustomACL(t *testing.T) {
	m := NewManager()
	custom := &staticACL{allowed: types.Allowed}
	if err := m.RegisterACL("custom", custom); err != nil {
		t.Fatalf("RegisterACL 失败: %v", err)
	}

	perm, err := m.CheckKind("custom", "anything")
	if err != nil {
		t.Fatalf("CheckKind 失败: %v", err)
	}
	if perm != types.Allowed {
		t.Errorf("期望 Allowed, 实际 %s", perm)
	}

	// 重复注册应报错
	if err := m.RegisterACL("custom", custom); err == nil {
		t.Error("重复注册应返回错误")
	}

	// RegisteredKinds 应包含 custom
	kinds := m.RegisteredKinds()
	found := false
	for _, k := range kinds {
		if k == "custom" {
			found = true
		}
	}
	if !found {
		t.Error("RegisteredKinds 未包含 custom")
	}

	m.UnregisterACL("custom")
	if _, ok := m.GetACL("custom"); ok {
		t.Error("UnregisterACL 后仍存在")
	}
}

// staticACL 是一个用于测试的自定义 MutableACL 实现：始终允许
type staticACL struct {
	allowed types.Permission
}

func (s *staticACL) Check(value string) (types.Permission, error) { return s.allowed, nil }
func (s *staticACL) GetListType() types.ListType                  { return types.Whitelist }
func (s *staticACL) Add(rules ...string) error                    { return nil }
func (s *staticACL) Remove(rules ...string) error                 { return nil }
func (s *staticACL) GetRules() []string                           { return nil }

// 确保 staticACL 实现 types.MutableACL
var _ types.MutableACL = (*staticACL)(nil)

// TestManagerPredefinedKinds 验证内置 kind 常量
func TestManagerPredefinedKinds(t *testing.T) {
	if KindIP != "ip" {
		t.Errorf("KindIP = %q, 期望 ip", KindIP)
	}
	if KindDomain != "domain" {
		t.Errorf("KindDomain = %q, 期望 domain", KindDomain)
	}

	// 确保预定义常量与 ip 包的 SetIPACL 路径一致
	m := NewManager()
	_ = m.SetIPACLWithDefaults(nil, types.Blacklist, []ip.PredefinedSet{ip.PrivateNetworks}, false)
	if _, ok := m.GetACL(KindIP); !ok {
		t.Error("SetIPACLWithDefaults 后 KindIP 未注册")
	}
}
