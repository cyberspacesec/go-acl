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
	fmt.Println("\n=== 示例1: 保存IP列表到文件 ===")
	example1(tmpDir)

	// 示例2: 从文件加载IP列表
	fmt.Println("\n=== 示例2: 从文件加载IP列表 ===")
	example2(tmpDir)

	// 示例3: 向已有ACL添加来自文件的IP
	fmt.Println("\n=== 示例3: 向现有ACL添加文件中的IP ===")
	example3(tmpDir)
}

func example1(tmpDir string) {
	// 创建一个IP黑名单
	ipAcl, err := ip.NewIPACL([]string{
		"192.168.1.0/24", // 局域网IP段
		"10.0.0.0/8",     // 私有IP段
		"8.8.8.8",        // Google DNS
	}, types.Blacklist)

	if err != nil {
		fmt.Printf("创建IP黑名单失败: %v\n", err)
		return
	}

	// 获取IP列表
	ipList := ipAcl.GetIPRanges()
	fmt.Printf("IP列表包含 %d 个IP/CIDR\n", len(ipList))

	// 保存到文件
	filePath := filepath.Join(tmpDir, "blacklist.txt")
	err = config.SaveIPACL(filePath, ipList, true)
	if err != nil {
		fmt.Printf("保存IP列表失败: %v\n", err)
		return
	}

	fmt.Printf("成功保存IP列表到文件: %s\n", filePath)

	// 显示文件内容
	printFileContent(filePath)
}

func example2(tmpDir string) {
	// 文件路径
	filePath := filepath.Join(tmpDir, "blacklist.txt")

	// 从文件加载IP列表
	ipList, err := config.ReadIPACL(filePath)
	if err != nil {
		fmt.Printf("读取IP列表失败: %v\n", err)
		return
	}

	fmt.Printf("成功从文件加载了 %d 个IP/CIDR\n", len(ipList))
	for i, ip := range ipList {
		fmt.Printf("  %d. %s\n", i+1, ip)
	}

	// 使用加载的IP列表创建新的IP ACL
	ipAcl, err := ip.NewIPACL(ipList, types.Blacklist)
	if err != nil {
		fmt.Printf("创建IP黑名单失败: %v\n", err)
		return
	}

	// 测试一些IP
	checkIPs(ipAcl, []string{
		"192.168.1.100", // 在黑名单中的局域网IP
		"8.8.4.4",       // 不在黑名单中的公共DNS
	})
}

func example3(tmpDir string) {
	fmt.Println("\n=== 示例3: 向现有ACL添加文件中的IP ===")

	// 创建包含一些初始IP的ACL
	ipAcl, err := ip.NewIPACL([]string{
		"192.168.1.1",
		"10.0.0.1",
	}, types.Blacklist)

	if err != nil {
		fmt.Printf("创建初始IP黑名单失败: %v\n", err)
		return
	}

	// 显示初始IP
	fmt.Println("初始IP列表:")
	for i, ip := range ipAcl.GetIPRanges() {
		fmt.Printf("  %d. %s\n", i+1, ip)
	}

	// 创建一个包含额外IP的文件
	additionalIPsFile := filepath.Join(tmpDir, "additional_ips.txt")
	additionalIPs := []string{
		"172.16.0.0/12", // 另一个私有IP段
		"8.8.8.8",       // Google DNS
	}

	err = config.SaveIPACL(additionalIPsFile, additionalIPs, true)
	if err != nil {
		fmt.Printf("创建额外IP文件失败: %v\n", err)
		return
	}

	fmt.Printf("创建了包含额外IP的文件: %s\n", additionalIPsFile)
	printFileContent(additionalIPsFile)

	// 从文件读取IP
	ipsFromFile, err := config.ReadIPACL(additionalIPsFile)
	if err != nil {
		fmt.Printf("读取额外IP文件失败: %v\n", err)
		return
	}

	// 添加到ACL
	err = ipAcl.Add(ipsFromFile...)
	if err != nil {
		fmt.Printf("添加IP失败: %v\n", err)
		return
	}

	// 显示合并后的IP列表
	fmt.Println("合并后的IP列表:")
	for i, ip := range ipAcl.GetIPRanges() {
		fmt.Printf("  %d. %s\n", i+1, ip)
	}

	// 测试一些IP
	checkIPs(ipAcl, []string{
		"192.168.1.1",  // 原始列表中的IP
		"172.16.10.10", // 新添加的CIDR范围内的IP
		"8.8.8.8",      // 新添加的特定IP
		"1.1.1.1",      // 不在列表中的IP
	})
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

// 辅助函数：打印文件内容
func printFileContent(filePath string) {
	// 读取文件内容
	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("读取文件失败: %v\n", err)
		return
	}

	// 打印文件内容
	fmt.Println("文件内容:")
	fmt.Println(string(content))
}

/*
预期输出:

===== 文件操作示例 =====

=== 示例1: 保存IP列表到文件 ===
IP列表包含 5 个IP/CIDR
成功保存IP列表到文件: tmp_ip_files/blacklist.txt
文件内容:
# IP黑名单示例
# Generated at: 2023-11-10 12:34:56
192.168.1.1
10.0.0.0/8
172.16.0.0/12
2001:db8::/32
fe80::/10

=== 示例2: 从文件加载IP列表 ===
成功从文件加载了 5 个IP/CIDR
  1. 192.168.1.1
  2. 10.0.0.0/8
  3. 172.16.0.0/12
  4. 2001:db8::/32
  5. fe80::/10

检查IP访问权限:
  192.168.1.100: 拒绝访问 ✗
  8.8.4.4: 拒绝访问 ✗

=== 示例3: 向现有ACL添加文件中的IP ===
初始IP列表:
  1. 192.168.1.1
  2. 10.0.0.1

创建了包含额外IP的文件: tmp_ip_files/additional_ips.txt
文件内容:
# 这些IP将被添加到现有的ACL中
172.16.0.0/12
8.8.8.8

合并后的IP列表:
  1. 192.168.1.1
  2. 10.0.0.1
  3. 172.16.0.0/12
  4. 8.8.8.8

检查IP访问权限:
  192.168.1.1: 允许访问 ✓
  172.16.10.10: 拒绝访问 ✗
  8.8.8.8: 允许访问 ✓
  1.1.1.1: 拒绝访问 ✗
*/
