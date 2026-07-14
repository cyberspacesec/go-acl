package main

import (
	"errors"
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
	fmt.Println("===== IPv6 子网 ACL 与反查示例 =====")

	m := acl.NewManager()
	// IPv4 + IPv6 子网混合黑名单
	if err := m.SetIPACL([]string{"10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32"}, types.Blacklist); err != nil {
		fmt.Printf("配置失败: %v\n", err)
		return
	}

	testIPs := []string{
		"10.1.2.3",     // 命中 /16（更具体）
		"10.2.0.1",     // 命中 /8
		"192.168.0.1",  // 无匹配
		"2001:db8::1",  // IPv6 子网命中
		"2001:db9::1",  // IPv6 无匹配
		"fe80::1%eth0", // zone id 剥离后无匹配
	}
	fmt.Println("\n检查 + 反查最长前缀:")
	for _, ip := range testIPs {
		perm, err := m.CheckIP(ip)
		if err != nil && !errors.Is(err, types.ErrNoACL) {
			fmt.Printf("  %s: 检查失败 - %v\n", ip, err)
			continue
		}
		cidr, _ := m.LookupIP(ip)
		if perm == types.Denied {
			fmt.Printf("  %s: 拒绝 ✗ (匹配 %s)\n", ip, cidr)
		} else {
			fmt.Printf("  %s: 允许 ✓ (匹配 %q)\n", ip, cidr)
		}
	}
}

/*
预期输出:

===== IPv6 子网 ACL 与反查示例 =====

检查 + 反查最长前缀:
  10.1.2.3: 拒绝 ✗ (匹配 10.1.0.0/16)
  10.2.0.1: 拒绝 ✗ (匹配 10.0.0.0/8)
  192.168.0.1: 允许 ✓ (匹配 "")
  2001:db8::1: 拒绝 ✗ (匹配 2001:db8::/32)
  2001:db9::1: 允许 ✓ (匹配 "")
  fe80::1%eth0: 允许 ✓ (匹配 "")
*/
