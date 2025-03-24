// Package core 提供go-acl库的核心类型、接口和常量
package core

// Permission 表示访问检查的结果
// 用于表示ACL检查后的决策结果，是允许访问还是拒绝访问
// 这是整个ACL系统的核心输出类型
type Permission int

const (
	// Denied 表示访问被拒绝
	// 当请求不符合访问控制规则时返回此值
	// 在黑名单模式下，表示请求匹配了黑名单规则
	// 在白名单模式下，表示请求未匹配白名单规则
	Denied Permission = iota

	// Allowed 表示访问被允许
	// 当请求符合访问控制规则时返回此值
	// 在黑名单模式下，表示请求未匹配黑名单规则
	// 在白名单模式下，表示请求匹配了白名单规则
	Allowed
)

// String 转换Permission为字符串表示
// 用于日志记录、调试输出和错误信息
//
// 返回值:
//   - "denied": 表示访问被拒绝
//   - "allowed": 表示访问被允许
//   - "unknown": 表示未知或无效的权限状态
func (p Permission) String() string {
	switch p {
	case Denied:
		return "denied"
	case Allowed:
		return "allowed"
	default:
		return "unknown"
	}
}
