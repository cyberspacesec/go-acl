// Package middleware 提供基于 net/http 的访问控制中间件。
//
// 它把 acl.Manager 的 CheckIP / CheckDomain 能力封装为可组合的 HTTP 中间件，
// 使 Web 服务能以一行代码完成"按客户端 IP + 目标域名做访问控制"。
//
// 默认行为（保守模式，TrustProxy=false）：
//   - 客户端 IP 取自 http.Request.RemoteAddr（TCP 连接对端地址）
//   - 目标域名取自 Host 头（去除端口）
//   - 任一检查 Denied → 返回 403 Forbidden
//   - 未配置对应 ACL kind → 该项检查视为通过（不强制阻断）
//
// 当部署在受信任的反向代理后端时，可设置 TrustProxy=true 以解析
// X-Forwarded-For / X-Real-IP 头获取真实客户端 IP。
package middleware
