// Package config 提供 JSON Policy 解析与文件 I/O。
//
// Policy 结构含 Domain 与 IP 两段，任一为 nil 表示不配置该类型 ACL。
// ApplyPolicy 将解析后的 Policy 注入 Manager，失败时在注入前返回，
// 避免半应用状态。
//
// 文件格式：每行一条规则，支持 # 行注释与行内注释。
package config
