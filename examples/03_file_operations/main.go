package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cyberspacesec/go-acl/pkg/config"
	"github.com/cyberspacesec/go-acl/pkg/ip"
	"github.com/cyberspacesec/go-acl/pkg/types"
)

func main() {
	fmt.Println("===== 文件操作示例 =====")

	// 创建示例文件目录
	tmpDir := "tmp_ip_files"
	_ = os.Mkdir(tmpDir, 0755)
	defer os.RemoveAll(tmpDir) // 在程序结束时清理临时文件

	// 示例1: 保存IP列表到文件
	fmt.Println("\n示例1: 保存IP列表到文件")
	example1(tmpDir)

	// 示例2: 从文件加载IP列表
	fmt.Println("\n示例2: 从文件加载IP列表")
	example2(tmpDir)

	// 示例3: 向已有ACL添加来自文件的IP
	fmt.Println("\n示例3: 向已有ACL添加来自文件的IP")
	example3(tmpDir)
}

func example1(tmpDir string) {
	// 创建一个IP列表
	ipList := []string{
		"192.168.1.1",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"2001:db8::/32",
		"fe80::/10",
	}

	// 保存到文件
	blacklistPath := filepath.Join(tmpDir, "blacklist.txt")
	err := config.SaveIPList(blacklistPath, ipList, "IP黑名单示例", true)
	if err != nil {
		fmt.Printf("保存IP列表失败: %v\n", err)
		return
	}
	fmt.Printf("IP列表已保存到: %s\n", blacklistPath)

	// 打印文件内容
	content, err := os.ReadFile(blacklistPath)
	if err != nil {
		fmt.Printf("读取文件失败: %v\n", err)
		return
	}
	fmt.Println("文件内容:")
	fmt.Println(string(content))
}

func example2(tmpDir string) {
	// 创建示例文件
	whitelistPath := filepath.Join(tmpDir, "whitelist.txt")
	whitelistContent := `# 这是一个IP白名单示例文件
# 注释行会被忽略

# 允许本地网络
127.0.0.1
192.168.0.0/16

# 允许特定IPv6地址
::1
2001:db8:1234::/48

# 空行会被忽略

# 无效的条目会被忽略并记录错误
invalid-entry
`
	err := os.WriteFile(whitelistPath, []byte(whitelistContent), 0644)
	if err != nil {
		fmt.Printf("创建示例文件失败: %v\n", err)
		return
	}

	// 从文件加载IP列表
	ipList, err := config.ReadIPList(whitelistPath)
	if err != nil {
		fmt.Printf("加载IP列表失败: %v\n", err)
		return
	}

	fmt.Println("成功加载的IP条目:")
	for i, ip := range ipList {
		fmt.Printf("  %d. %s\n", i+1, ip)
	}

	// 注意：现在ReadIPList不再返回invalidEntries，需要在应用程序中自行处理
}

func example3(tmpDir string) {
	// 创建一个新的示例文件
	additionalIPsPath := filepath.Join(tmpDir, "additional_ips.txt")
	additionalContent := `# 这些IP将被添加到现有的ACL中
8.8.8.8
8.8.4.4
203.0.113.0/24
`
	err := os.WriteFile(additionalIPsPath, []byte(additionalContent), 0644)
	if err != nil {
		fmt.Printf("创建附加IP文件失败: %v\n", err)
		return
	}

	// 创建一个基本的IP ACL
	ipAcl, err := ip.NewIPACL([]string{
		"192.168.1.1",
		"10.0.0.0/8",
	}, types.Blacklist)
	if err != nil {
		fmt.Printf("创建IP ACL失败: %v\n", err)
		return
	}

	// 显示初始ACL状态
	fmt.Println("初始黑名单IP列表:")
	for i, ipAddr := range ipAcl.GetIPRanges() {
		fmt.Printf("  %d. %s\n", i+1, ipAddr)
	}

	// 从文件加载IP并添加到ACL
	fmt.Println("\n从文件加载IP并添加到ACL...")
	ips, err := config.ReadIPList(additionalIPsPath)
	if err != nil {
		fmt.Printf("加载IP列表失败: %v\n", err)
		return
	}

	// 添加到现有ACL
	for _, ipAddr := range ips {
		err := ipAcl.Add(ipAddr)
		if err != nil {
			fmt.Printf("添加IP %s 失败: %v\n", ipAddr, err)
		}
	}

	// 显示更新后的ACL状态
	fmt.Println("\n更新后的黑名单IP列表:")
	for i, ipAddr := range ipAcl.GetIPRanges() {
		fmt.Printf("  %d. %s\n", i+1, ipAddr)
	}

	// 测试一些IP
	testIPs := []string{
		"192.168.1.1",  // 初始黑名单中的IP
		"8.8.8.8",      // 从文件添加的IP
		"203.0.113.10", // 从文件添加的CIDR范围内的IP
		"1.1.1.1",      // 不在黑名单中的IP
	}
	checkIPs(ipAcl, testIPs)
}

// 辅助函数：检查多个IP
func checkIPs(ipAcl *ip.IPACL, ips []string) {
	fmt.Println("\n检查IP访问权限:")
	for _, ipAddr := range ips {
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

/*
预期输出:

===== 文件操作示例 =====

示例1: 保存IP列表到文件
IP列表已保存到: tmp_ip_files/blacklist.txt
文件内容:
# IP黑名单示例
# Generated at: 2023-11-10 12:34:56
192.168.1.1
10.0.0.0/8
172.16.0.0/12
2001:db8::/32
fe80::/10

示例2: 从文件加载IP列表
成功加载的IP条目:
  1. 127.0.0.1
  2. 192.168.0.0/16
  3. ::1
  4. 2001:db8:1234::/48

示例3: 向已有ACL添加来自文件的IP
初始黑名单IP列表:
  1. 192.168.1.1
  2. 10.0.0.0/8

从文件加载IP并添加到ACL...

更新后的黑名单IP列表:
  1. 192.168.1.1
  2. 10.0.0.0/8
  3. 8.8.8.8
  4. 8.8.4.4
  5. 203.0.113.0/24

检查IP访问权限:
  192.168.1.1: 拒绝访问 ✗
  8.8.8.8: 拒绝访问 ✗
  203.0.113.10: 拒绝访问 ✗
  1.1.1.1: 允许访问 ✓
*/
