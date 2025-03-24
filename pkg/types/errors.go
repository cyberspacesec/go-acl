// Package types 提供go-acl库的基础类型、接口和常量
package types

import "errors"

// 下面定义了库中使用的常见错误
// 这些错误在ACL操作过程中可能发生，应该被适当处理
var (
	// ErrNoACL 表示没有配置对应的访问控制列表
	// 当试图在Manager中使用某个ACL功能，但该ACL尚未配置时返回此错误
	//
	// 示例:
	//    err := manager.CheckIP("192.168.1.1")
	//    if errors.Is(err, ErrNoACL) {
	//        // 处理未配置ACL的情况
	//    }
	ErrNoACL = errors.New("no ACL configured")

	// 其他可能的错误可以在此处添加
	// 例如：权限错误、配置错误等
)
