package main

import (
	"errors"
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/acl"
	"github.com/cyberspacesec/acl-skills/pkg/config"
	"github.com/cyberspacesec/acl-skills/pkg/domain"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func main() {
	fmt.Println("===== 预定义域名集合示例 =====")

	fmt.Println("\n示例1: 使用预定义域名集合创建黑名单")
	example1()

	fmt.Println("\n示例2: 向已有白名单追加预定义集合")
	example2()

	fmt.Println("\n示例3: 从 JSON Policy 加载预定义域名集合")
	example3()
}

// example1 用 SetDomainACLWithDefaults 一次性注入自定义域名 + 短链/一次性邮箱预定义集合
func example1() {
	manager := acl.NewManager()
	err := manager.SetDomainACLWithDefaults(
		[]string{"custom-malware.com"}, // 额外的自定义恶意域名
		types.Blacklist,
		true, // 包含子域名
		[]domain.PredefinedSet{
			domain.Shorteners,      // 短链服务
			domain.DisposableEmail, // 一次性邮箱
		},
		false, // 黑名单 + false = 阻止这些集合
	)
	if err != nil {
		fmt.Printf("创建域名黑名单失败: %v\n", err)
		return
	}

	// 显示黑名单域名数量与部分内容
	domains := manager.GetDomains()
	fmt.Printf("已创建包含 %d 个域名的黑名单\n", len(domains))
	maxShow := 5
	if len(domains) < maxShow {
		maxShow = len(domains)
	}
	fmt.Println("部分黑名单域名:")
	for i := 0; i < maxShow; i++ {
		fmt.Printf("  %d. %s\n", i+1, domains[i])
	}
	if len(domains) > maxShow {
		fmt.Printf("  ...以及其他 %d 个域名\n", len(domains)-maxShow)
	}

	// 测试访问权限
	testDomains := []string{
		"bit.ly",             // 短链（应拒绝）
		"mailinator.com",     // 一次性邮箱（应拒绝）
		"sub.bit.ly",         // 短链子域名（应拒绝）
		"custom-malware.com", // 自定义恶意域名（应拒绝）
		"example.com",        // 无关域名（应允许）
	}
	fmt.Println("\n测试域名访问权限:")
	for _, d := range testDomains {
		printDomainResult(manager, d)
	}
}

// example2 从一个基础白名单出发，再用 AddPredefinedDomainSet 追加可信 CDN 集合
func example2() {
	manager := acl.NewManager()
	// 白名单：只允许 trusted-service.com 及其子域名
	manager.SetDomainACL([]string{"trusted-service.com"}, types.Whitelist, true)
	fmt.Println("初始白名单仅含 trusted-service.com")

	// 白名单 + allowSet=true => 把 TrustedCDN 集合加入允许列表
	err := manager.AddPredefinedDomainSet(domain.TrustedCDN, true)
	if err != nil {
		fmt.Printf("追加 TrustedCDN 失败: %v\n", err)
		return
	}
	fmt.Println("已追加可信 CDN 预定义集合到白名单")

	// 测试访问权限
	testDomains := []string{
		"jsdelivr.net",           // 可信 CDN（应允许）
		"unpkg.com",              // 可信 CDN（应允许）
		"sub.cdn.cloudflare.net", // 可信 CDN 子域名（应允许）
		"trusted-service.com",    // 原始白名单（应允许）
		"random-site.com",        // 不在白名单（应拒绝）
	}
	fmt.Println("\n测试域名访问权限:")
	for _, d := range testDomains {
		printDomainResult(manager, d)
	}
}

// example3 从 config.Policy 加载带预定义集合的域名 ACL，并演示集合内省
func example3() {
	manager := acl.NewManager()
	pol := &config.Policy{
		Domain: &config.DomainPolicy{
			Domains:           []string{"custom-malware.com"},
			ListType:          "blacklist",
			IncludeSubdomains: true,
			PredefinedSets:    []string{"shorteners", "disposable_email"},
			AllowPredefined:   false,
		},
	}
	if err := manager.ApplyPolicy(pol); err != nil {
		fmt.Printf("应用 Policy 失败: %v\n", err)
		return
	}
	fmt.Println("已从 JSON Policy 加载域名黑名单（含短链 + 一次性邮箱预定义集合）")

	testDomains := []string{
		"bit.ly",             // 短链（应拒绝）
		"mailinator.com",     // 一次性邮箱（应拒绝）
		"custom-malware.com", // 自定义恶意域名（应拒绝）
		"safe-site.org",      // 无关域名（应允许）
	}
	fmt.Println("\n测试域名访问权限:")
	for _, d := range testDomains {
		printDomainResult(manager, d)
	}

	// 演示集合内省：列出短链集合的实际域名
	fmt.Println("\n短链预定义集合包含的域名:")
	for _, d := range domain.GetPredefinedDomains(domain.Shorteners) {
		fmt.Printf("  %s\n", d)
	}
}

// printDomainResult 用 Manager 检查单个域名并打印结果
func printDomainResult(manager *acl.Manager, d string) {
	perm, err := manager.CheckDomain(d)
	if err != nil {
		if errors.Is(err, types.ErrNoACL) {
			fmt.Printf("  %s: 未配置域名ACL\n", d)
		} else {
			fmt.Printf("  %s: 检查失败 - %v\n", d, err)
		}
		return
	}
	fmt.Printf("  %s: %s\n", d, permissionString(perm))
}

// permissionString 将权限转为友好字符串
func permissionString(perm types.Permission) string {
	if perm == types.Allowed {
		return "允许访问 ✓"
	}
	return "拒绝访问 ✗"
}

/*
预期输出:

===== 预定义域名集合示例 =====

示例1: 使用预定义域名集合创建黑名单
已创建包含 17 个域名的黑名单
部分黑名单域名:
  1. custom-malware.com
  2. bit.ly
  ... (其余短链/一次性邮箱域名)

测试域名访问权限:
  bit.ly: 拒绝访问 ✗
  mailinator.com: 拒绝访问 ✗
  sub.bit.ly: 拒绝访问 ✗
  custom-malware.com: 拒绝访问 ✗
  example.com: 允许访问 ✓

示例2: 向已有白名单追加预定义集合
初始白名单仅含 trusted-service.com
已追加可信 CDN 预定义集合到白名单

测试域名访问权限:
  jsdelivr.net: 允许访问 ✓
  unpkg.com: 允许访问 ✓
  sub.cdn.cloudflare.net: 允许访问 ✓
  trusted-service.com: 允许访问 ✓
  random-site.com: 拒绝访问 ✗

示例3: 从 JSON Policy 加载预定义域名集合
已从 JSON Policy 加载域名黑名单（含短链 + 一次性邮箱预定义集合）

测试域名访问权限:
  bit.ly: 拒绝访问 ✗
  mailinator.com: 拒绝访问 ✗
  custom-malware.com: 拒绝访问 ✗
  safe-site.org: 允许访问 ✓

短链预定义集合包含的域名:
  bit.ly
  tinyurl.com
  t.co
  goo.gl
  ow.ly
  is.gd
  buff.ly
  rebrand.ly
  cutt.ly
*/
