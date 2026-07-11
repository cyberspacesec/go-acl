// Package types 提供go-acl库的基础类型、接口和常量
package types

// ACL 是所有访问控制列表实现的接口
// 该接口定义了访问控制列表的核心功能 - 检查访问权限
// 库中所有的ACL实现（如IP ACL、域名ACL等）都必须实现此接口
//
// 接口实现示例:
//
//	type MyACL struct {
//	    // 实现细节...
//	}
//
//	func (m *MyACL) Check(value string) (Permission, error) {
//	    // 检查逻辑实现...
//	    return Allowed, nil
//	}
type ACL interface {
	// Check 检查请求是否允许访问
	// 这是ACL的核心方法，用于确定某个值是否允许访问
	//
	// 参数:
	//   - value: 要检查的值，通常是IP地址或域名
	//
	// 返回值:
	//   - Permission: 表示访问决策结果（Allowed或Denied）
	//   - error: 如果在检查过程中发生错误，将返回相关错误信息
	Check(value string) (Permission, error)
}

// ListTypeACL 扩展 ACL，暴露列表类型（黑/白名单）信息
//
// 实现此接口的 ACL 能够告知调用方其当前的工作模式。
// 库中的 IPACL 和 DomainACL 均实现此接口。
type ListTypeACL interface {
	ACL
	// GetListType 返回当前访问控制列表的类型（黑名单或白名单）
	GetListType() ListType
}

// MutableACL 扩展 ListTypeACL，支持运行时增删规则与查询规则列表
//
// 该接口是 Manager 进行统一委托的抽象基础：任何实现此接口的类型
// 都可以通过 Manager.RegisterACL 注册，从而获得 Manager 提供的
// 统一并发保护、文件加载等能力。用户可据此接入自定义的 ACL 实现。
//
// 实现要求：
//   - Add/Remove 必须并发安全（实现方自行加锁）
//   - Add 对无效输入返回 error，对空字符串可静默忽略
//   - GetRules 返回规则列表的副本，避免外部修改内部状态
type MutableACL interface {
	ListTypeACL
	// Add 向访问控制列表添加一个或多个规则
	// 无效输入应返回错误；空字符串可被忽略。
	Add(rules ...string) error
	// Remove 从访问控制列表移除一个或多个规则
	// 若规则不在列表中，返回 ErrIPNotFound/ErrDomainNotFound 等哨兵错误。
	Remove(rules ...string) error
	// GetRules 返回当前规则列表的副本
	GetRules() []string
}
