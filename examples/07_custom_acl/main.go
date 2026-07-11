// Package main 演示如何注册一个自定义的 ACL 实现到 Manager
//
// go-acl 通过 types.MutableACL 接口提供扩展点：任何实现该接口的类型
// 都可以经由 Manager.RegisterACL 注册，从而获得 Manager 统一的访问入口。
package main

import (
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// TokenACL 是一个示例自定义 ACL：基于一个允许令牌集合做白名单匹配
//
// 它实现了 types.MutableACL 接口（Check / GetListType / Add / Remove / GetRules）。
type TokenACL struct {
	allowed map[string]struct{}
}

func NewTokenACL(tokens ...string) *TokenACL {
	t := &TokenACL{allowed: make(map[string]struct{})}
	_ = t.Add(tokens...)
	return t
}

func (t *TokenACL) Check(value string) (types.Permission, error) {
	if _, ok := t.allowed[value]; ok {
		return types.Allowed, nil
	}
	return types.Denied, nil
}

func (t *TokenACL) GetListType() types.ListType { return types.Whitelist }

func (t *TokenACL) Add(rules ...string) error {
	for _, r := range rules {
		if r == "" {
			continue
		}
		t.allowed[r] = struct{}{}
	}
	return nil
}

func (t *TokenACL) Remove(rules ...string) error {
	for _, r := range rules {
		delete(t.allowed, r)
	}
	return nil
}

func (t *TokenACL) GetRules() []string {
	rules := make([]string, 0, len(t.allowed))
	for r := range t.allowed {
		rules = append(rules, r)
	}
	return rules
}

// 编译期确保 TokenACL 实现 types.MutableACL
var _ types.MutableACL = (*TokenACL)(nil)

func main() {
	fmt.Println("===== 自定义 ACL 扩展示例 =====")

	manager := acl.NewManager()

	// 注册自定义令牌白名单
	tokenACL := NewTokenACL("secret-token-123", "service-key-abc")
	if err := manager.RegisterACL("token", tokenACL); err != nil {
		fmt.Printf("注册失败: %v\n", err)
		return
	}

	// 通过统一的 CheckKind 入口检查任意 kind 的 ACL
	perm, err := manager.CheckKind("token", "secret-token-123")
	fmt.Printf("检查 secret-token-123: %s (err=%v)\n", perm, err)

	perm, err = manager.CheckKind("token", "invalid-token")
	fmt.Printf("检查 invalid-token: %s (err=%v)\n", perm, err)

	// 通过统一入口动态增删规则
	_ = manager.AddRule("token", "new-token-xyz")
	rules := manager.GetRules("token")
	fmt.Printf("当前令牌规则: %v\n", rules)

	// 查看已注册的所有 kind
	fmt.Printf("已注册的 ACL kinds: %v\n", manager.RegisteredKinds())
}
