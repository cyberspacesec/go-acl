package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// Options 控制中间件的行为
type Options struct {
	// TrustProxy 为 true 时，从 X-Forwarded-For（取首个）或 X-Real-IP 提取客户端 IP。
	// 默认 false：仅使用 Request.RemoteAddr，保守不信任代理头，避免被伪造头绕过黑名单。
	TrustProxy bool

	// CheckClientIP 为 true 时对客户端 IP 执行 CheckIP（需 Manager 注册了 IP ACL）。
	// 默认 true。
	CheckClientIP bool

	// CheckHost 为 true 时对请求 Host 执行 CheckDomain（需 Manager 注册了 Domain ACL）。
	// 默认 true。
	CheckHost bool

	// Denied 处理器：默认返回 403 + "Access Denied"。可自定义返回 JSON 或重定向。
	Denied http.HandlerFunc
}

// New 返回一个 HTTP 中间件，基于给定 Manager 与 Options 做访问控制。
//
// 用法:
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/api", apiHandler)
//	handler := middleware.New(manager, middleware.Options{CheckClientIP: true})(mux)
//	http.ListenAndServe(":8080", handler)
func New(manager *acl.Manager, opts Options) func(http.Handler) http.Handler {
	if opts.Denied == nil {
		opts.Denied = defaultDenied
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !opts.CheckClientIP && !opts.CheckHost {
				next.ServeHTTP(w, r)
				return
			}

			if opts.CheckHost {
				host := extractHost(r.Host)
				if host != "" {
					perm, err := manager.CheckDomain(host)
					// err==ErrNoACL 视为该项未配置 → 放行该项
					if err == nil && perm == types.Denied {
						opts.Denied(w, r)
						return
					}
				}
			}

			if opts.CheckClientIP {
				clientIP := extractClientIP(r, opts.TrustProxy)
				if clientIP != "" {
					perm, err := manager.CheckIP(clientIP)
					if err == nil && perm == types.Denied {
						opts.Denied(w, r)
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// defaultDenied 默认拒绝处理器：返回 403 与简短正文
func defaultDenied(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("Access Denied\n"))
}

// extractHost 从请求 Host 头提取域名（去除端口，IPv6 兼容）
func extractHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// IPv6 带端口：[2001:db8::1]:8080
	if strings.HasPrefix(host, "[") {
		if idx := strings.Index(host, "]"); idx != -1 {
			return host[:idx+1]
		}
	}
	// 普通 host:port
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

// extractClientIP 提取客户端 IP
//
// TrustProxy=false: 取 RemoteAddr 的 host 部分。
// TrustProxy=true: 优先 X-Real-IP，其次 X-Forwarded-For 首个，兜底 RemoteAddr。
func extractClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			if ip := net.ParseIP(strings.TrimSpace(xrip)); ip != nil {
				return ip.String()
			}
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For: client, proxy1, proxy2
			first := strings.Split(xff, ",")[0]
			if ip := net.ParseIP(strings.TrimSpace(first)); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
