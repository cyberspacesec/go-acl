package core

// Package core 提供go-acl库的核心类型、接口和常量

// Acl 是所有访问控制列表实现的接口
// 该接口定义了访问控制列表的核心功能 - 检查访问权限
// 库中所有的ACL实现（如IP ACL、域名ACL等）都必须实现此接口
//
// 接口实现示例:
//
//	type MyAcl struct {
//	    // 实现细节...
//	}
//
//	func (m *MyAcl) Check(value string) (Permission, error) {
//	    // 检查逻辑实现...
//	    return Allowed, nil
//	}
type Acl interface {
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
