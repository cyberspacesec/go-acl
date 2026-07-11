package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func newManager(t *testing.T) *acl.Manager {
	t.Helper()
	m := acl.NewManager()
	m.SetDomainACL([]string{"bad.com"}, types.Blacklist, true)
	if err := m.SetIPACL([]string{"10.0.0.0/8"}, types.Blacklist); err != nil {
		t.Fatalf("SetIPACL 失败: %v", err)
	}
	return m
}

// TestMiddleware_Allowed 验证正常请求放行
func TestMiddleware_Allowed(t *testing.T) {
	m := newManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckClientIP: true, CheckHost: true})(next)

	req := httptest.NewRequest("GET", "https://good.com/x", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Host = "good.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("正常请求应放行 200，得到 %d", rec.Code)
	}
}

// TestMiddleware_DomainDenied 验证黑名单域名返回 403
func TestMiddleware_DomainDenied(t *testing.T) {
	m := newManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckHost: true, CheckClientIP: false})(next)

	req := httptest.NewRequest("GET", "https://sub.bad.com/x", nil)
	req.Host = "sub.bad.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("黑名单域名应 403，得到 %d", rec.Code)
	}
}

// TestMiddleware_IPDenied 验证黑名单 IP 返回 403
func TestMiddleware_IPDenied(t *testing.T) {
	m := newManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckHost: false, CheckClientIP: true})(next)

	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("黑名单 IP 应 403，得到 %d", rec.Code)
	}
}

// TestMiddleware_TrustProxy 验证信任代理头时从 X-Forwarded-For 取 IP
func TestMiddleware_TrustProxy(t *testing.T) {
	m := newManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckHost: false, CheckClientIP: true, TrustProxy: true})(next)

	// RemoteAddr 是白名单 IP，但 X-Forwarded-For 是黑名单 IP
	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("X-Forwarded-For", "10.5.5.5, 192.168.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("信任代理头时应取首个 XFF 10.5.5.5 → 403，得到 %d", rec.Code)
	}
}

// TestMiddleware_NoProxyByDefault 验证默认不信任代理头，黑名单 IP 伪造 XFF 无效
func TestMiddleware_NoProxyByDefault(t *testing.T) {
	m := newManager(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckHost: false, CheckClientIP: true})(next) // TrustProxy 默认 false

	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Header.Set("X-Forwarded-For", "10.5.5.5")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("默认不信代理头，伪造 XFF 应放行 200，得到 %d", rec.Code)
	}
}

// TestMiddleware_CustomDenied 验证自定义 Denied 处理器
func TestMiddleware_CustomDenied(t *testing.T) {
	m := newManager(t)
	called := false
	custom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})
	handler := New(m, Options{CheckHost: false, CheckClientIP: true, Denied: custom})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "10.0.0.1:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("自定义 Denied 处理器未被调用")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("应返回自定义状态 418，得到 %d", rec.Code)
	}
}

// TestMiddleware_NoACLKindPasses 验证未配置某 kind 时该项视为放行
func TestMiddleware_NoACLKindPasses(t *testing.T) {
	m := acl.NewManager() // 空 Manager，无任何 ACL
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := New(m, Options{CheckHost: true, CheckClientIP: true})(next)

	req := httptest.NewRequest("GET", "/x", nil)
	req.RemoteAddr = "1.2.3.4:1"
	req.Host = "whatever.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("未配置 ACL 应放行 200，得到 %d", rec.Code)
	}
}
