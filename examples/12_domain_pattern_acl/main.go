package main

import (
	"errors"
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
	fmt.Println("===== 域名模式匹配 ACL 示例 =====")

	m := acl.NewManager()
	// 前缀 api.* + 宽松后缀 *evil.com（含主域）+ 正则 /internal-\d+\.corp/
	m.SetDomainACL([]string{
		"api.*",
		"*evil.com",
		`/^internal-\d+\.corp$/`,
	}, types.Blacklist, false)

	testDomains := []string{
		"api.example.com",     // 前缀命中
		"api.sub.example.com", // 前缀多层命中
		"evil.com",            // 宽松后缀含主域
		"sub.evil.com",        // 宽松后缀子域
		"notevil.com",         // 宽松后缀不误伤（标签边界）
		"internal-7.corp",     // 正则命中
		"internal-x.corp",     // 正则不命中
		"safe.org",            // 无关放行
	}
	fmt.Println("\n测试结果:")
	for _, d := range testDomains {
		perm, err := m.CheckDomain(d)
		if err != nil {
			if errors.Is(err, types.ErrNoACL) {
				fmt.Printf("  %s: 未配置域名ACL\n", d)
			} else {
				fmt.Printf("  %s: 检查失败 - %v\n", d, err)
			}
			continue
		}
		if perm == types.Allowed {
			fmt.Printf("  %s: 允许访问 ✓\n", d)
		} else {
			fmt.Printf("  %s: 拒绝访问 ✗\n", d)
		}
	}
}

/*
预期输出:

===== 域名模式匹配 ACL 示例 =====

测试结果:
  api.example.com: 拒绝访问 ✗
  api.sub.example.com: 拒绝访问 ✗
  evil.com: 拒绝访问 ✗
  sub.evil.com: 拒绝访问 ✗
  notevil.com: 允许访问 ✓
  internal-7.corp: 拒绝访问 ✗
  internal-x.corp: 允许访问 ✓
  safe.org: 允许访问 ✓
*/
