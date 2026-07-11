// Package main 演示如何用统一 JSON 配置 + HTTP 中间件完成按 IP/域名的访问控制
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/config"
	"github.com/cyberspacesec/acl-skills/pkg/middleware"
)

func main() {
	// 1. 从一份 JSON 策略加载域名 + IP 规则
	policyPath := "../../testdata/security_policy.json"
	pol, err := config.LoadPolicyFromFile(policyPath)
	if err != nil {
		fmt.Printf("加载策略失败: %v\n", err)
		os.Exit(1)
	}

	manager := acl.NewManager()
	if err := manager.ApplyPolicy(pol); err != nil {
		fmt.Printf("应用策略失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("已从 JSON 加载域名 + IP 访问控制策略")

	// 2. 用一行中间件包装业务 handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %s!\n", r.Host)
	})

	// TrustProxy=false：默认不信任 X-Forwarded-For，防止伪造头绕过 IP 黑名单
	handler := middleware.New(manager, middleware.Options{
		CheckClientIP: true,
		CheckHost:     true,
	})(mux)

	fmt.Println("中间件已挂载，监听 :8080")
	fmt.Println("  - 域名黑名单 + 子域名 → 403")
	fmt.Println("  - IP 黑名单（内网/云元数据/Docker/203.0.113.0/24）→ 403")

	if err := http.ListenAndServe(":8080", handler); err != nil {
		fmt.Printf("服务退出: %v\n", err)
	}
}
