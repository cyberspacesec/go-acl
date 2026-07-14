package main

import (
	"errors"
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
	fmt.Println("===== 子域名通配 ACL 示例 =====")

	m := acl.NewManager()
	// 阻止 *.evil.com 的所有子域，但放行 evil.com 主域本身
	m.SetDomainACL([]string{"*.evil.com"}, types.Blacklist, false)

	testDomains := []string{
		"evil.com",          // 主域：放行
		"phishing.evil.com", // 子域：阻止
		"a.b.evil.com",      // 多层子域：阻止
		"notevil.com",       // 相邻：放行
		"safe.org",          // 无关：放行
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

===== 子域名通配 ACL 示例 =====

测试结果:
  evil.com: 允许访问 ✓
  phishing.evil.com: 拒绝访问 ✗
  a.b.evil.com: 拒绝访问 ✗
  notevil.com: 允许访问 ✓
  safe.org: 允许访问 ✓
*/
