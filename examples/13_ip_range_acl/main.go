package main

import (
	"errors"
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
	fmt.Println("===== IP 区间 ACL 示例 =====")

	m := acl.NewManager()
	// IPv4 区间 + IPv6 区间 + CIDR 混合
	if err := m.SetIPACL([]string{
		"192.168.1.10-192.168.1.20",
		"2001:db8::1-2001:db8::5",
		"10.0.0.0/8",
	}, types.Blacklist); err != nil {
		fmt.Printf("配置失败: %v\n", err)
		return
	}

	testIPs := []string{
		"192.168.1.15", // IPv4 区间命中
		"192.168.1.25", // IPv4 区间外
		"2001:db8::3",  // IPv6 区间命中
		"2001:db8::6",  // IPv6 区间外
		"10.1.2.3",     // CIDR 命中
		"8.8.8.8",      // 无关放行
	}
	fmt.Println("\n测试结果:")
	for _, ip := range testIPs {
		perm, err := m.CheckIP(ip)
		if err != nil && !errors.Is(err, types.ErrNoACL) {
			fmt.Printf("  %s: 检查失败 - %v\n", ip, err)
			continue
		}
		if perm == types.Allowed {
			fmt.Printf("  %s: 允许访问 ✓\n", ip)
		} else {
			fmt.Printf("  %s: 拒绝访问 ✗\n", ip)
		}
	}
}

/*
预期输出:

===== IP 区间 ACL 示例 =====

测试结果:
  192.168.1.15: 拒绝访问 ✗
  192.168.1.25: 允许访问 ✓
  2001:db8::3: 拒绝访问 ✗
  2001:db8::6: 允许访问 ✓
  10.1.2.3: 拒绝访问 ✗
  8.8.8.8: 允许访问 ✓
*/
