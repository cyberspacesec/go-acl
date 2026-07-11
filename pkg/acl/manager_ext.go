package acl

import (
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// withACL 在写锁下取出指定 kind 的 ACL，再以该 ACL 自带的锁执行操作
//
// map 锁只用于安全地取出子 ACL 指针，取出后立即释放，
// 随后调用 fn 时由子 ACL 自身的锁保护，避免 Manager 锁与子 ACL 锁嵌套。
//
// 若 kind 未注册，返回 ErrNoACL。
func (m *Manager) withACL(kind string, fn func(types.MutableACL) error) error {
	m.mu.RLock()
	a, ok := m.acls[kind]
	m.mu.RUnlock()

	if !ok {
		return types.ErrNoACL
	}
	return fn(a)
}

// withACLRead 同 withACL，语义上用于只读操作（仍依赖子 ACL 内部的读写锁区分）。
func (m *Manager) withACLRead(kind string, fn func(types.MutableACL) (types.Permission, error)) (types.Permission, error) {
	m.mu.RLock()
	a, ok := m.acls[kind]
	m.mu.RUnlock()

	if !ok {
		return types.Denied, types.ErrNoACL
	}
	return fn(a)
}

// RegisterACL 注册一个自定义 ACL 到 Manager
//
// 参数:
//   - kind: ACL 的注册键，需在 Manager 内唯一；可使用预定义的 KindDomain/KindIP，或自定义字符串
//   - acl:  实现 types.MutableACL 接口的 ACL 实例
//
// 若 kind 已被注册，返回 ErrACLAlreadyRegistered。
// 同一 ACL 实例可注册到不同 kind。
//
// 示例:
//
//	err := manager.RegisterACL(acl.KindIP, myCustomIPACL)
func (m *Manager) RegisterACL(kind string, a types.MutableACL) error {
	if a == nil {
		return types.ErrNoACL
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.acls[kind]; exists {
		return types.ErrACLAlreadyRegistered
	}
	m.acls[kind] = a
	return nil
}

// UnregisterACL 注销指定 kind 的 ACL
//
// 若 kind 未注册，本方法为 no-op。
func (m *Manager) UnregisterACL(kind string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.acls, kind)
}

// GetACL 返回指定 kind 的 ACL 实例
//
// 返回:
//   - types.MutableACL: 注册的 ACL（若存在）
//   - bool: 是否存在
func (m *Manager) GetACL(kind string) (types.MutableACL, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.acls[kind]
	return a, ok
}

// CheckKind 检查指定 kind 的 ACL 是否允许某个值访问
//
// 这是统一的访问检查入口，可对任意已注册的 ACL 类型进行检查。
//
// 示例:
//
//	perm, err := manager.CheckKind(acl.KindIP, "8.8.8.8")
//	perm, err := manager.CheckKind("my_custom", "some-value")
func (m *Manager) CheckKind(kind, value string) (types.Permission, error) {
	return m.withACLRead(kind, func(a types.MutableACL) (types.Permission, error) {
		return a.Check(value)
	})
}

// AddRule 向指定 kind 的 ACL 添加规则
//
// 示例:
//
//	err := manager.AddRule(acl.KindIP, "192.168.1.1", "10.0.0.0/8")
func (m *Manager) AddRule(kind string, rules ...string) error {
	return m.withACL(kind, func(a types.MutableACL) error {
		return a.Add(rules...)
	})
}

// RemoveRule 从指定 kind 的 ACL 移除规则
func (m *Manager) RemoveRule(kind string, rules ...string) error {
	return m.withACL(kind, func(a types.MutableACL) error {
		return a.Remove(rules...)
	})
}

// GetRules 获取指定 kind 的 ACL 规则列表
func (m *Manager) GetRules(kind string) []string {
	m.mu.RLock()
	a, ok := m.acls[kind]
	m.mu.RUnlock()

	if !ok {
		return nil
	}
	return a.GetRules()
}

// GetACLType 获取指定 kind 的 ACL 类型（黑/白名单）
func (m *Manager) GetACLType(kind string) (types.ListType, error) {
	m.mu.RLock()
	a, ok := m.acls[kind]
	m.mu.RUnlock()

	if !ok {
		return 0, types.ErrNoACL
	}
	return a.GetListType(), nil
}

// RegisteredKinds 返回当前已注册的所有 ACL kind
func (m *Manager) RegisteredKinds() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	kinds := make([]string, 0, len(m.acls))
	for k := range m.acls {
		kinds = append(kinds, k)
	}
	return kinds
}
