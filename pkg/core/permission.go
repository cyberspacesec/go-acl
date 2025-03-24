package core

// Permission 表示访问检查的结果
type Permission int

const (
	// Denied 表示访问被拒绝
	Denied Permission = iota
	// Allowed 表示访问被允许
	Allowed
)

// String 转换Permission为字符串表示
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
