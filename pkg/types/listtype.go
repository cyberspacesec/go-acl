// Package types 提供go-acl库的基础类型、接口和常量
// 该包是整个访问控制列表(ACL)系统的类型基础
package types

// ListType 表示访问控制列表的类型：黑名单或白名单
// 在ACL系统中，列表类型决定了默认的访问策略和规则的解释方式
type ListType int

const (
	// Blacklist 黑名单模式 - 列表中的项目会被拒绝访问，其他均允许
	// 适用场景：大部分请求是安全的，只有少数特定请求需要被阻止
	// 默认行为：如果请求不在列表中，则允许访问
	Blacklist ListType = iota

	// Whitelist 白名单模式 - 只有列表中的项目允许访问，其他均拒绝
	// 适用场景：大部分请求是不安全的，只有少数特定请求需要被允许
	// 默认行为：如果请求不在列表中，则拒绝访问
	Whitelist
)

// String 返回ListType的字符串表示
// 用于日志记录、调试输出和错误信息
//
// 返回值:
//   - "blacklist": 表示黑名单模式
//   - "whitelist": 表示白名单模式
//   - "unknown": 表示未知或无效的列表类型
func (lt ListType) String() string {
	switch lt {
	case Blacklist:
		return "blacklist"
	case Whitelist:
		return "whitelist"
	default:
		return "unknown"
	}
}
