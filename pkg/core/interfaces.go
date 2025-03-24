package core

// Acl 是所有访问控制列表实现的接口
type Acl interface {
	// Check 检查请求是否允许访问
	// 返回Permission(Allowed或Denied)和可选的说明原因的错误
	Check(value string) (Permission, error)
}
