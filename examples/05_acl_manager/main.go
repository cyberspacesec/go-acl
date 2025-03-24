package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyberspacesec/go-acl/pkg/acl"
	"github.com/cyberspacesec/go-acl/pkg/ip"
	"github.com/cyberspacesec/go-acl/pkg/types"
)

func main() {
	fmt.Println("===== ACL管理器示例 =====")

	// 创建临时目录
	tmpDir := "tmp_acl_files"
	_ = os.Mkdir(tmpDir, 0755)
	defer os.RemoveAll(tmpDir) // 在程序结束时清理临时文件

	// 示例1: 创建和配置ACL管理器
	fmt.Println("\n示例1: 创建和配置ACL管理器")
	manager := example1(tmpDir)

	// 示例2: 使用管理器检查访问权限
	fmt.Println("\n示例2: 使用管理器检查访问权限")
	example2(manager)

	// 示例3: 动态更新规则
	fmt.Println("\n示例3: 动态更新规则")
	example3(manager, tmpDir)
}

func example1(tmpDir string) *acl.Manager {
	// 创建ACL管理器
	manager := acl.NewManager()

	// 1. 配置域名ACL（黑名单模式）
	domainBlacklist := []string{
		"evil-site.com",        // 阻止该域名
		"malicious-domain.org", // 阻止该域名
		"ads.example.com",      // 阻止该域名
	}
	manager.SetDomainACL(domainBlacklist, types.Blacklist, true) // 包含子域名
	fmt.Println("已配置域名黑名单，阻止恶意域名及其子域名")

	// 2. 配置IP ACL（白名单模式）
	// 创建IP白名单文件
	whitelistPath := filepath.Join(tmpDir, "ip_whitelist.txt")
	whitelistContent := `# 允许的IP白名单
# 只有这些IP可以访问

# 公司内网
203.0.113.0/24  # 办公室IP段
198.51.100.0/24 # 数据中心IP段

# 特定合作伙伴
192.0.2.10
192.0.2.11
`
	err := os.WriteFile(whitelistPath, []byte(whitelistContent), 0644)
	if err != nil {
		fmt.Printf("创建IP白名单文件失败: %v\n", err)
		return manager
	}

	// 从文件加载IP白名单
	err = manager.SetIPACLFromFile(whitelistPath, types.Whitelist)
	if err != nil {
		fmt.Printf("加载IP白名单失败: %v\n", err)
		return manager
	}
	fmt.Println("已从文件加载IP白名单")

	// 3. 添加预定义安全设置
	// 添加公共DNS服务器到IP白名单
	// 需要先获取现有的IP列表
	ipRanges := manager.GetIPRanges()

	// 创建一个新的IP ACL，包含原有IP和公共DNS服务器
	ipAcl, err := ip.NewIPACLWithDefaults(
		ipRanges,
		types.Whitelist,
		[]ip.PredefinedSet{ip.PublicDNS},
		true, // 允许这些预定义集合
	)
	if err != nil {
		fmt.Printf("添加公共DNS服务器失败: %v\n", err)
	} else {
		// 更新manager的IP ACL
		err = manager.SetIPACL(ipAcl.GetIPRanges(), types.Whitelist)
		if err != nil {
			fmt.Printf("更新IP ACL失败: %v\n", err)
		} else {
			fmt.Println("已添加公共DNS服务器到IP白名单")
		}
	}

	// 4. 显示当前配置
	displayManagerConfig(manager)

	return manager
}

func example2(manager *acl.Manager) {
	// 准备测试数据
	domains := []string{
		"example.com",              // 合法域名
		"evil-site.com",            // 黑名单域名
		"sub.malicious-domain.org", // 黑名单子域名
		"ads.example.com",          // 黑名单域名
		"legitimate-site.com",      // 合法域名
	}

	ips := []string{
		"203.0.113.10",   // 白名单内IP
		"8.8.8.8",        // 公共DNS（白名单内）
		"192.168.1.1",    // 白名单外IP
		"198.51.100.100", // 白名单内IP
		"10.0.0.1",       // 私有网络IP（白名单外）
	}

	// 测试域名访问
	fmt.Println("\n检查域名访问权限:")
	for _, domain := range domains {
		perm, err := manager.CheckDomain(domain)
		if err != nil {
			if errors.Is(err, types.ErrNoAcl) {
				fmt.Printf("  %s: 未配置域名ACL\n", domain)
			} else {
				fmt.Printf("  %s: 检查失败 - %v\n", domain, err)
			}
		} else if perm == types.Allowed {
			fmt.Printf("  %s: 允许访问 ✓\n", domain)
		} else {
			fmt.Printf("  %s: 拒绝访问 ✗\n", domain)
		}
	}

	// 测试IP访问
	fmt.Println("\n检查IP访问权限:")
	for _, ipAddr := range ips {
		perm, err := manager.CheckIP(ipAddr)
		if err != nil {
			if errors.Is(err, types.ErrNoAcl) {
				fmt.Printf("  %s: 未配置IP ACL\n", ipAddr)
			} else {
				fmt.Printf("  %s: 检查失败 - %v\n", ipAddr, err)
			}
		} else if perm == types.Allowed {
			fmt.Printf("  %s: 允许访问 ✓\n", ipAddr)
		} else {
			fmt.Printf("  %s: 拒绝访问 ✗\n", ipAddr)
		}
	}

	// 使用管理器检查通用URL或请求
	fmt.Println("\n检查综合URL:")
	urls := []string{
		"https://example.com/api/data",        // 合法域名
		"http://evil-site.com/malware.exe",    // 黑名单域名
		"https://8.8.8.8/dns-query",           // 公共DNS IP（白名单内）
		"http://192.168.1.1/admin",            // 私有网络IP（白名单外）
		"https://ads.example.com/tracking.js", // 黑名单域名
	}

	for _, url := range urls {
		domainPerm, domainErr := checkURL(manager, url, true) // 优先检查域名
		ipPerm, ipErr := checkURL(manager, url, false)        // 优先检查IP

		fmt.Printf("  %s:\n", url)
		if domainErr != nil {
			fmt.Printf("    域名检查: 失败 - %v\n", domainErr)
		} else {
			fmt.Printf("    域名检查: %s\n", permissionString(domainPerm))
		}

		if ipErr != nil {
			fmt.Printf("    IP检查: 失败 - %v\n", ipErr)
		} else {
			fmt.Printf("    IP检查: %s\n", permissionString(ipPerm))
		}

		// 综合判断（域名检查优先）
		finalPerm := domainPerm
		if domainErr != nil || (domainPerm == types.Allowed && ipPerm == types.Denied) {
			finalPerm = ipPerm // 如果域名检查允许但IP检查拒绝，使用IP检查结果
		}
		fmt.Printf("    最终决策: %s\n", permissionString(finalPerm))
	}
}

// 从URL中提取域名或IP，并使用管理器检查访问权限
func checkURL(manager *acl.Manager, url string, domainPriority bool) (types.Permission, error) {
	// 移除协议前缀
	url = strings.TrimSpace(url)
	if strings.HasPrefix(url, "http://") {
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		url = url[8:]
	} else if strings.HasPrefix(url, "//") {
		url = url[2:]
	}

	// 移除路径部分
	if pathIndex := strings.Index(url, "/"); pathIndex != -1 {
		url = url[:pathIndex]
	}

	// 移除端口号
	if portIndex := strings.LastIndex(url, ":"); portIndex != -1 {
		// 确保不是IPv6地址的一部分
		if !strings.Contains(url[:portIndex], "]") {
			url = url[:portIndex]
		}
	}

	// 检查是否是IP地址
	ip := net.ParseIP(url)

	if domainPriority {
		// 优先作为域名检查
		if ip == nil || !strings.Contains(url, ".") {
			// 不是有效IP或看起来像域名，作为域名检查
			return manager.CheckDomain(url)
		}
		// 是IP地址，但要求域名优先，所以先尝试域名检查
		domainPerm, err := manager.CheckDomain(url)
		if err == nil {
			return domainPerm, nil
		}
		// 域名检查失败，回退到IP检查
		return manager.CheckIP(url)
	} else {
		// 优先作为IP检查
		if ip != nil {
			// 是有效IP地址，作为IP检查
			return manager.CheckIP(url)
		}
		// 不是IP地址，作为域名检查
		return manager.CheckDomain(url)
	}
}

func example3(manager *acl.Manager, tmpDir string) {
	// 1. 动态添加域名到黑名单
	fmt.Println("\n动态添加域名到黑名单:")
	err := manager.AddDomain("new-threat.com")
	if err != nil {
		fmt.Printf("添加域名失败: %v\n", err)
	} else {
		fmt.Println("已添加 new-threat.com 到域名黑名单")
	}

	// 检查更新后的域名访问权限
	domain := "malware.new-threat.com"
	perm, err := manager.CheckDomain(domain)
	if err != nil {
		fmt.Printf("检查域名失败: %v\n", err)
	} else if perm == types.Allowed {
		fmt.Printf("%s: 允许访问 ✓\n", domain)
	} else {
		fmt.Printf("%s: 拒绝访问 ✗\n", domain)
	}

	// 2. 从黑名单中移除域名
	fmt.Println("\n从黑名单移除域名:")
	err = manager.RemoveDomain("ads.example.com")
	if err != nil {
		fmt.Printf("移除域名失败: %v\n", err)
	} else {
		fmt.Println("已从黑名单移除 ads.example.com")
	}

	// 检查更新后的域名访问权限
	domain = "ads.example.com"
	perm, err = manager.CheckDomain(domain)
	if err != nil {
		fmt.Printf("检查域名失败: %v\n", err)
	} else if perm == types.Allowed {
		fmt.Printf("%s: 允许访问 ✓\n", domain)
	} else {
		fmt.Printf("%s: 拒绝访问 ✗\n", domain)
	}

	// 3. 完全重置所有ACL
	fmt.Println("\n重置所有ACL:")
	manager.Reset()
	fmt.Println("已重置所有ACL设置")

	// 检查重置后的状态
	_, err = manager.CheckDomain("example.com")
	if errors.Is(err, types.ErrNoAcl) {
		fmt.Println("域名ACL已成功重置")
	}

	_, err = manager.CheckIP("8.8.8.8")
	if errors.Is(err, types.ErrNoAcl) {
		fmt.Println("IP ACL已成功重置")
	}

	// 4. 使用预定义集合创建新的IP黑名单
	fmt.Println("\n使用预定义集合创建新的安全ACL:")
	// 使用Manager的SetIPACLWithDefaults方法
	err = manager.SetIPACLWithDefaults(
		[]string{},
		types.Blacklist,
		[]ip.PredefinedSet{
			ip.PrivateNetworks,
			ip.CloudMetadata,
		},
		false,
	)

	if err != nil {
		fmt.Printf("创建防SSRF黑名单失败: %v\n", err)
		return
	}
	fmt.Println("已设置防SSRF IP黑名单")

	// 保存到文件
	blacklistPath := filepath.Join(tmpDir, "ip_blacklist.txt")
	err = manager.SaveIPACLToFile(blacklistPath, true)
	if err != nil {
		fmt.Printf("保存IP黑名单失败: %v\n", err)
	} else {
		fmt.Printf("已保存IP黑名单到: %s\n", blacklistPath)
	}

	// 检查更新后的IP访问权限
	fmt.Println("\n检查IP访问权限:")
	testIPs := []string{
		"192.168.1.1",     // 私有网络（应拒绝）
		"169.254.169.254", // 云元数据（应拒绝）
		"8.8.8.8",         // 公共DNS（应允许）
	}

	for _, ipAddr := range testIPs {
		perm, err := manager.CheckIP(ipAddr)
		if err != nil {
			fmt.Printf("  %s: 检查失败 - %v\n", ipAddr, err)
		} else if perm == types.Allowed {
			fmt.Printf("  %s: 允许访问 ✓\n", ipAddr)
		} else {
			fmt.Printf("  %s: 拒绝访问 ✗\n", ipAddr)
		}
	}
}

// 辅助函数：显示管理器配置
func displayManagerConfig(manager *acl.Manager) {
	fmt.Println("\n当前ACL管理器配置:")

	// 显示域名ACL信息
	domainListType, err := manager.GetDomainACLType()
	if err != nil {
		if errors.Is(err, types.ErrNoAcl) {
			fmt.Println("  域名ACL: 未配置")
		} else {
			fmt.Printf("  域名ACL: 获取类型失败 - %v\n", err)
		}
	} else {
		var typeStr string
		if domainListType == types.Blacklist {
			typeStr = "黑名单"
		} else {
			typeStr = "白名单"
		}
		domains := manager.GetDomains()
		fmt.Printf("  域名ACL: %s (包含 %d 个域名)\n", typeStr, len(domains))
		if len(domains) > 0 {
			fmt.Println("  域名列表:")
			maxShow := 5
			if len(domains) < maxShow {
				maxShow = len(domains)
			}
			for i := 0; i < maxShow; i++ {
				fmt.Printf("    %d. %s\n", i+1, domains[i])
			}
			if len(domains) > maxShow {
				fmt.Printf("    ...以及其他 %d 个域名\n", len(domains)-maxShow)
			}
		}
	}

	// 显示IP ACL信息
	ipAclType, err := manager.GetIPACLType()
	if err != nil {
		if errors.Is(err, types.ErrNoAcl) {
			fmt.Println("  IP ACL: 未配置")
		} else {
			fmt.Printf("  IP ACL: 获取失败 - %v\n", err)
		}
	} else {
		var typeStr string
		if ipAclType == types.Blacklist {
			typeStr = "黑名单"
		} else {
			typeStr = "白名单"
		}
		ipRanges := manager.GetIPRanges()
		fmt.Printf("  IP ACL: %s (包含 %d 个IP/CIDR)\n", typeStr, len(ipRanges))
		if len(ipRanges) > 0 {
			fmt.Println("  IP列表:")
			maxShow := 5
			if len(ipRanges) < maxShow {
				maxShow = len(ipRanges)
			}
			for i := 0; i < maxShow; i++ {
				fmt.Printf("    %d. %s\n", i+1, ipRanges[i])
			}
			if len(ipRanges) > maxShow {
				fmt.Printf("    ...以及其他 %d 个IP/CIDR\n", len(ipRanges)-maxShow)
			}
		}
	}
}

// 辅助函数：将权限转换为友好字符串
func permissionString(perm types.Permission) string {
	if perm == types.Allowed {
		return "允许访问 ✓"
	}
	return "拒绝访问 ✗"
}

/*
预期输出:

===== ACL管理器示例 =====

示例1: 创建和配置ACL管理器
已配置域名黑名单，阻止恶意域名及其子域名
已从文件加载IP白名单
已添加公共DNS服务器到IP白名单

当前ACL管理器配置:
  域名ACL: 黑名单 (包含 3 个域名)
  域名列表:
    1. evil-site.com
    2. malicious-domain.org
    3. ads.example.com
  IP ACL: 白名单 (包含 6+ 个IP/CIDR)
  IP列表:
    1. 203.0.113.0/24
    2. 198.51.100.0/24
    3. 192.0.2.10
    4. 192.0.2.11
    5. 8.8.8.8
    ...以及其他 IP/CIDR

示例2: 使用管理器检查访问权限

检查域名访问权限:
  example.com: 允许访问 ✓
  evil-site.com: 拒绝访问 ✗
  sub.malicious-domain.org: 拒绝访问 ✗
  ads.example.com: 拒绝访问 ✗
  legitimate-site.com: 允许访问 ✓

检查IP访问权限:
  203.0.113.10: 允许访问 ✓
  8.8.8.8: 允许访问 ✓
  192.168.1.1: 拒绝访问 ✗
  198.51.100.100: 允许访问 ✓
  10.0.0.1: 拒绝访问 ✗

检查综合URL:
  https://example.com/api/data:
    域名检查: 允许访问 ✓
    IP检查: 失败 - 无效的IP地址格式
    最终决策: 允许访问 ✓
  http://evil-site.com/malware.exe:
    域名检查: 拒绝访问 ✗
    IP检查: 失败 - 无效的IP地址格式
    最终决策: 拒绝访问 ✗
  https://8.8.8.8/dns-query:
    域名检查: 拒绝访问 ✗
    IP检查: 允许访问 ✓
    最终决策: 拒绝访问 ✗
  http://192.168.1.1/admin:
    域名检查: 拒绝访问 ✗
    IP检查: 拒绝访问 ✗
    最终决策: 拒绝访问 ✗
  https://ads.example.com/tracking.js:
    域名检查: 拒绝访问 ✗
    IP检查: 失败 - 无效的IP地址格式
    最终决策: 拒绝访问 ✗

示例3: 动态更新规则

动态添加域名到黑名单:
已添加 new-threat.com 到域名黑名单
malware.new-threat.com: 拒绝访问 ✗

从黑名单移除域名:
已从黑名单移除 ads.example.com
ads.example.com: 允许访问 ✓

重置所有ACL:
已重置所有ACL设置
域名ACL已成功重置
IP ACL已成功重置

使用预定义集合创建新的安全ACL:
已设置防SSRF IP黑名单
已保存IP黑名单到: tmp_acl_files/ip_blacklist.txt

检查IP访问权限:
  192.168.1.1: 拒绝访问 ✗
  169.254.169.254: 拒绝访问 ✗
  8.8.8.8: 允许访问 ✓
*/
