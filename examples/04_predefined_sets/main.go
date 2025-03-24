package main

import (
	"fmt"
	"net"

	"github.com/cyberspacesec/go-acl/pkg/ip"
	"github.com/cyberspacesec/go-acl/pkg/types"
)

func main() {
	fmt.Println("===== 预定义IP集合示例 =====")

	// 示例1: 使用预定义IP集合创建ACL
	fmt.Println("\n示例1: 使用预定义IP集合创建ACL")
	example1()

	// 示例2: 向已有ACL添加预定义集合
	fmt.Println("\n示例2: 向已有ACL添加预定义集合")
	example2()

	// 示例3: 使用所有特殊网络创建安全ACL
	fmt.Println("\n示例3: 使用所有特殊网络创建安全ACL")
	example3()
}

func example1() {
	// 使用预定义集合创建IP黑名单，限制访问私有网络和云元数据服务
	ipAcl, err := ip.NewIPACLWithDefaults(
		[]string{"203.0.113.1"}, // 额外的自定义IP
		types.Blacklist,
		[]ip.PredefinedSet{
			ip.PrivateNetworks, // 私有网络地址范围
			ip.CloudMetadata,   // 云服务商元数据地址
		},
		false, // 设为false将阻止这些预定义集合中的IP
	)
	if err != nil {
		fmt.Printf("创建IP黑名单失败: %v\n", err)
		return
	}

	// 显示ACL内容
	fmt.Println("已创建包含以下IP/CIDR的黑名单:")
	for i, ipRange := range ipAcl.GetIPRanges() {
		fmt.Printf("  %d. %s\n", i+1, ipRange)
	}

	// 测试一些IP
	testIPs := []string{
		"192.168.1.1",     // 私有网络IP
		"10.0.0.1",        // 私有网络IP
		"169.254.169.254", // AWS元数据IP
		"8.8.8.8",         // 公共IP
		"203.0.113.1",     // 我们添加的自定义IP
	}
	fmt.Println("\n测试访问权限:")
	for _, ipAddr := range testIPs {
		perm, err := ipAcl.Check(ipAddr)
		if err != nil {
			fmt.Printf("  %s: 检查失败 - %v\n", ipAddr, err)
		} else if perm == types.Allowed {
			fmt.Printf("  %s: 允许访问 ✓\n", ipAddr)
		} else {
			fmt.Printf("  %s: 拒绝访问 ✗\n", ipAddr)
		}
	}
}

func example2() {
	// 创建一个基本的IP白名单
	ipAcl, err := ip.NewIPACL(
		[]string{"203.0.113.1"}, // 初始只有一个IP
		types.Whitelist,
	)
	if err != nil {
		fmt.Printf("创建IP白名单失败: %v\n", err)
		return
	}

	// 显示初始状态
	fmt.Println("初始白名单IP列表:")
	for i, ipRange := range ipAcl.GetIPRanges() {
		fmt.Printf("  %d. %s\n", i+1, ipRange)
	}

	// 添加公共DNS服务器到白名单
	fmt.Println("\n添加公共DNS服务器到白名单...")
	err = ipAcl.AddPredefinedSet(ip.PublicDNS, true)
	if err != nil {
		fmt.Printf("添加公共DNS服务器失败: %v\n", err)
		return
	}

	// 显示更新后的状态
	fmt.Println("\n更新后的白名单IP列表:")
	for i, ipRange := range ipAcl.GetIPRanges() {
		fmt.Printf("  %d. %s\n", i+1, ipRange)
	}

	// 测试一些IP
	testIPs := []string{
		"8.8.8.8",     // Google DNS
		"1.1.1.1",     // Cloudflare DNS
		"203.0.113.1", // 我们添加的自定义IP
		"192.168.1.1", // 不在白名单中的IP
	}
	fmt.Println("\n测试访问权限:")
	for _, ipAddr := range testIPs {
		perm, err := ipAcl.Check(ipAddr)
		if err != nil {
			fmt.Printf("  %s: 检查失败 - %v\n", ipAddr, err)
		} else if perm == types.Allowed {
			fmt.Printf("  %s: 允许访问 ✓\n", ipAddr)
		} else {
			fmt.Printf("  %s: 拒绝访问 ✗\n", ipAddr)
		}
	}
}

func example3() {
	// 创建一个防SSRF的黑名单ACL
	// 阻止所有特殊网络和内部地址
	ipAcl, err := ip.NewIPACLWithDefaults(
		[]string{}, // 不添加自定义IP
		types.Blacklist,
		[]ip.PredefinedSet{
			ip.PrivateNetworks,    // 私有网络 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
			ip.LoopbackNetworks,   // 本地回环 (127.0.0.0/8, ::1/128)
			ip.LinkLocalNetworks,  // 链路本地 (169.254.0.0/16, fe80::/10)
			ip.CloudMetadata,      // 云元数据 (169.254.169.254等)
			ip.DockerNetworks,     // Docker默认网络
			ip.BroadcastAddresses, // 广播地址 (255.255.255.255)
			ip.MulticastAddresses, // 组播地址 (224.0.0.0/4, ff00::/8)
		},
		false, // 阻止这些IP范围
	)
	if err != nil {
		fmt.Printf("创建防SSRF黑名单失败: %v\n", err)
		return
	}

	// 显示黑名单IP数量
	fmt.Printf("防SSRF黑名单包含 %d 个IP/CIDR范围\n", len(ipAcl.GetIPRanges()))

	// 打印部分黑名单内容
	fmt.Println("\n部分黑名单内容:")
	ranges := ipAcl.GetIPRanges()
	// 显示前5个（如果有这么多）
	maxShow := 5
	if len(ranges) < maxShow {
		maxShow = len(ranges)
	}
	for i := 0; i < maxShow; i++ {
		fmt.Printf("  %d. %s\n", i+1, ranges[i])
	}
	if len(ranges) > maxShow {
		fmt.Printf("  ...以及其他 %d 个范围\n", len(ranges)-maxShow)
	}

	// 测试不同类型的IP
	testIPs := []string{
		"10.0.0.1",        // 私有网络
		"127.0.0.1",       // 本地回环
		"169.254.169.254", // 云元数据
		"224.0.0.1",       // 组播
		"8.8.8.8",         // 公共DNS (应该允许)
		"203.0.113.1",     // 公共IP (应该允许)
	}

	fmt.Println("\n测试IP访问权限:")
	for _, ipAddr := range testIPs {
		perm, err := ipAcl.Check(ipAddr)
		if err != nil {
			fmt.Printf("  %s: 检查失败 - %v\n", ipAddr, err)
		} else if perm == types.Allowed {
			fmt.Printf("  %s: 允许访问 ✓\n", ipAddr)
		} else {
			fmt.Printf("  %s: 拒绝访问 ✗\n", ipAddr)
		}
	}

	// 演示如何检查任意IP是否为内部地址
	fmt.Println("\n手动检查IP是否为内部/特殊地址:")
	customIPs := []string{
		"192.168.1.1",
		"8.8.8.8",
		"172.17.0.1", // Docker默认网关
	}

	for _, ipStr := range customIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			fmt.Printf("  %s: 无效的IP格式\n", ipStr)
			continue
		}

		isInternal := false
		// 检查该IP是否在任何预定义集合中
		for _, ipRange := range ipAcl.GetIPRanges() {
			_, ipNet, _ := net.ParseCIDR(ipRange)
			if ipNet != nil && ipNet.Contains(ip) {
				isInternal = true
				fmt.Printf("  %s: 内部/特殊地址 (匹配 %s)\n", ipStr, ipRange)
				break
			}
		}

		if !isInternal {
			fmt.Printf("  %s: 公共地址\n", ipStr)
		}
	}
}

/*
预期输出:

===== 预定义IP集合示例 =====

示例1: 使用预定义IP集合创建ACL
已创建包含以下IP/CIDR的黑名单:
  1. 203.0.113.1
  2. 10.0.0.0/8
  3. 172.16.0.0/12
  4. 192.168.0.0/16
  5. 169.254.169.254
  ... (更多云元数据IP)

测试访问权限:
  192.168.1.1: 拒绝访问 ✗
  10.0.0.1: 拒绝访问 ✗
  169.254.169.254: 拒绝访问 ✗
  8.8.8.8: 允许访问 ✓
  203.0.113.1: 拒绝访问 ✗

示例2: 向已有ACL添加预定义集合
初始白名单IP列表:
  1. 203.0.113.1

添加公共DNS服务器到白名单...

更新后的白名单IP列表:
  1. 203.0.113.1
  2. 8.8.8.8
  3. 8.8.4.4
  4. 1.1.1.1
  5. 1.0.0.1
  ... (可能还有其他公共DNS服务器)

测试访问权限:
  8.8.8.8: 允许访问 ✓
  1.1.1.1: 允许访问 ✓
  203.0.113.1: 允许访问 ✓
  192.168.1.1: 拒绝访问 ✗

示例3: 使用所有特殊网络创建安全ACL
防SSRF黑名单包含 40+ 个IP/CIDR范围

部分黑名单内容:
  1. 10.0.0.0/8
  2. 172.16.0.0/12
  3. 192.168.0.0/16
  4. 127.0.0.0/8
  5. ::1/128
  ...以及其他 35+ 个范围

测试IP访问权限:
  10.0.0.1: 拒绝访问 ✗
  127.0.0.1: 拒绝访问 ✗
  169.254.169.254: 拒绝访问 ✗
  224.0.0.1: 拒绝访问 ✗
  8.8.8.8: 允许访问 ✓
  203.0.113.1: 允许访问 ✓

手动检查IP是否为内部/特殊地址:
  192.168.1.1: 内部/特殊地址 (匹配 192.168.0.0/16)
  8.8.8.8: 公共地址
  172.17.0.1: 内部/特殊地址 (匹配 172.16.0.0/12)
*/
