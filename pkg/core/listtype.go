package core

// ListType 表示访问控制列表的类型：黑名单或白名单
type ListType int

const (
	// Blacklist 黑名单模式 - 列表中的项目会被拒绝访问，其他均允许
	Blacklist ListType = iota
	// Whitelist 白名单模式 - 只有列表中的项目允许访问，其他均拒绝
	Whitelist
)

// String 返回ListType的字符串表示
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
