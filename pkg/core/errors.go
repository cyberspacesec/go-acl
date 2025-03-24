package core

import "errors"

var (
	// ErrNoAcl 表示没有配置对应的访问控制列表
	ErrNoAcl = errors.New("no ACL configured")
)
