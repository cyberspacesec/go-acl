package main

import (
	"fmt"
	"log"

	"github.com/cyberspacesec/go-acl/pkg/ip"
	"github.com/cyberspacesec/go-acl/pkg/types"
)

func main() {
	fmt.Println("=== IP访问控制列表(IP ACL)基本用法示例 ===")

	// 示例1: 创建IP黑名单
	fmt.Println("\n示例1: 创建IP黑名单")
	// 创建一个IP黑名单，包含IPv4和CIDR
	blacklist, err := ip.NewIPACL(
		[]string{
			"192.168.1.100", // 单个IPv4地址
			"10.0.0.0/8",    // IPv4 CIDR范围
			"2001:db8::/32", // IPv6 CIDR范围
		},
		types.Blacklist,
	)
	if err != nil {
		log.Fatalf("创建IP黑名单失败: %v", err)
	}

	// 测试黑名单工作情况
	fmt.Println("检查IP访问权限 (黑名单模式):")
	checkIPs(blacklist, []string{
		"192.168.1.100", // 应该被阻止 - 精确匹配
		"10.0.0.5",      // 应该被阻止 - 在CIDR范围内
		"172.16.0.1",    // 应该被允许 - 不在黑名单中
		"2001:db8::1",   // 应该被阻止 - 在IPv6 CIDR范围内
		"2001:db8:1::1", // 应该被允许 - 不在IPv6 CIDR范围内
	})

	// 示例2: 创建IP白名单
	fmt.Println("\n示例2: 创建IP白名单")
	// 创建一个IP白名单，只允许特定的IP访问
	whitelist, err := ip.NewIPACL(
		[]string{
			"8.8.8.8",        // Google DNS
			"1.1.1.1",        // Cloudflare DNS
			"192.168.0.0/16", // 私有网络范围
		},
		types.Whitelist,
	)
	if err != nil {
		log.Fatalf("创建IP白名单失败: %v", err)
	}

	// 测试白名单工作情况
	fmt.Println("检查IP访问权限 (白名单模式):")
	checkIPs(whitelist, []string{
		"8.8.8.8",       // 应该被允许 - 精确匹配
		"192.168.1.100", // 应该被允许 - 在CIDR范围内
		"172.16.0.1",    // 应该被阻止 - 不在白名单中
		"1.1.1.1",       // 应该被允许 - 精确匹配
		"8.8.4.4",       // 应该被阻止 - 不在白名单中
	})

	// 示例3: 动态管理IP规则
	fmt.Println("\n示例3: 动态管理IP规则")
	// 创建一个空的IP黑名单
	dynamicAcl, err := ip.NewIPACL([]string{}, types.Blacklist)
	if err != nil {
		log.Fatalf("创建空IP黑名单失败: %v", err)
	}

	// 当前没有任何规则
	fmt.Println("初始状态 - IP列表:", dynamicAcl.GetIPRanges())

	// 添加IP
	fmt.Println("添加IP: 192.168.1.1, 10.0.0.0/8")
	if err := dynamicAcl.Add("192.168.1.1", "10.0.0.0/8"); err != nil {
		log.Fatalf("添加IP失败: %v", err)
	}
	fmt.Println("添加后 - IP列表:", dynamicAcl.GetIPRanges())

	// 检查是否生效
	fmt.Println("检查新添加的IP:")
	checkIP(dynamicAcl, "192.168.1.1") // 应该被阻止
	checkIP(dynamicAcl, "10.0.0.5")    // 应该被阻止

	// 移除IP
	fmt.Println("\n移除IP: 192.168.1.1")
	if err := dynamicAcl.Remove("192.168.1.1"); err != nil {
		log.Fatalf("移除IP失败: %v", err)
	}
	fmt.Println("移除后 - IP列表:", dynamicAcl.GetIPRanges())

	// 检查移除是否生效
	fmt.Println("检查移除后的IP:")
	checkIP(dynamicAcl, "192.168.1.1") // 应该被允许
	checkIP(dynamicAcl, "10.0.0.5")    // 应该被阻止

	// 尝试添加无效的IP
	fmt.Println("\n尝试添加无效的IP: 999.999.999.999")
	err = dynamicAcl.Add("999.999.999.999")
	if err != nil {
		fmt.Printf("预期的错误: %v\n", err)
	}

	// 示例4: IPv6支持
	fmt.Println("\n示例4: IPv6支持")
	// 创建一个同时包含IPv4和IPv6的ACL
	ipv6Acl, err := ip.NewIPACL(
		[]string{
			"192.168.1.0/24",  // IPv4 CIDR
			"2001:db8::/32",   // IPv6 CIDR
			"::1",             // IPv6回环地址
			"fe80::1234:5678", // IPv6链路本地地址
		},
		types.Blacklist,
	)
	if err != nil {
		log.Fatalf("创建IPv6 ACL失败: %v", err)
	}

	// 测试IPv6支持
	fmt.Println("检查IPv6访问权限:")
	checkIPs(ipv6Acl, []string{
		"192.168.1.100",        // 应该被阻止 - 在IPv4 CIDR内
		"2001:db8::1",          // 应该被阻止 - 在IPv6 CIDR内
		"::1",                  // 应该被阻止 - 精确匹配
		"fe80::1234:5678",      // 应该被阻止 - 精确匹配
		"2001:4860:4860::8888", // 应该被允许 - 不在黑名单中 (Google IPv6 DNS)
	})
}

// 辅助函数：检查一系列IP
func checkIPs(acl *ip.IPACL, ips []string) {
	for _, ip := range ips {
		checkIP(acl, ip)
	}
}

// 辅助函数：检查单个IP
func checkIP(acl *ip.IPACL, ipAddr string) {
	permission, err := acl.Check(ipAddr)
	if err != nil {
		fmt.Printf("  IP %-18s -> 错误: %v\n", ipAddr, err)
		return
	}

	if permission == types.Allowed {
		fmt.Printf("  IP %-18s -> 允许访问\n", ipAddr)
	} else {
		fmt.Printf("  IP %-18s -> 拒绝访问\n", ipAddr)
	}
}

/* 预期输出:
=== IP访问控制列表(IP ACL)基本用法示例 ===

示例1: 创建IP黑名单
检查IP访问权限 (黑名单模式):
  IP 192.168.1.100      -> 拒绝访问
  IP 10.0.0.5           -> 拒绝访问
  IP 172.16.0.1         -> 允许访问
  IP 2001:db8::1        -> 拒绝访问
  IP 2001:db8:1::1      -> 允许访问

示例2: 创建IP白名单
检查IP访问权限 (白名单模式):
  IP 8.8.8.8            -> 允许访问
  IP 192.168.1.100      -> 允许访问
  IP 172.16.0.1         -> 拒绝访问
  IP 1.1.1.1            -> 允许访问
  IP 8.8.4.4            -> 拒绝访问

示例3: 动态管理IP规则
初始状态 - IP列表: []
添加IP: 192.168.1.1, 10.0.0.0/8
添加后 - IP列表: [192.168.1.1 10.0.0.0/8]
检查新添加的IP:
  IP 192.168.1.1        -> 拒绝访问
  IP 10.0.0.5           -> 拒绝访问

移除IP: 192.168.1.1
移除后 - IP列表: [10.0.0.0/8]
检查移除后的IP:
  IP 192.168.1.1        -> 允许访问
  IP 10.0.0.5           -> 拒绝访问

尝试添加无效的IP: 999.999.999.999
预期的错误: 无效的IP地址格式

示例4: IPv6支持
检查IPv6访问权限:
  IP 192.168.1.100      -> 拒绝访问
  IP 2001:db8::1        -> 拒绝访问
  IP ::1                -> 拒绝访问
  IP fe80::1234:5678    -> 拒绝访问
  IP 2001:4860:4860::8888 -> 允许访问
*/
