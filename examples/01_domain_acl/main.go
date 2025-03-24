package main

import (
	"fmt"
	"log"

	"github.com/cyberspacesec/go-acl/pkg/domain"
	"github.com/cyberspacesec/go-acl/pkg/types"
)

func main() {
	fmt.Println("=== 域名访问控制列表(Domain ACL)基本用法示例 ===")

	// 示例1: 创建黑名单模式的域名ACL（不包含子域名匹配）
	fmt.Println("\n示例1: 创建黑名单模式的域名ACL")
	// 创建一个阻止特定域名的黑名单，禁用子域名匹配
	blacklist := domain.NewDomainAcl(
		[]string{"evil.com", "malware.org"}, // 要阻止的域名列表
		types.Blacklist,                     // 列表类型：黑名单
		false,                               // 不检查子域名
	)

	// 测试黑名单工作情况
	checkDomains(blacklist, []string{
		"evil.com",        // 应该被阻止
		"sub.evil.com",    // 子域名应该被允许(因为禁用了子域名检查)
		"innocent.com",    // 应该被允许
		"malware.org",     // 应该被阻止
		"www.malware.org", // 子域名应该被允许
	})

	// 示例2: 创建白名单模式的域名ACL（包含子域名匹配）
	fmt.Println("\n示例2: 创建白名单模式的域名ACL")
	// 创建一个只允许特定域名及其子域名的白名单
	whitelist := domain.NewDomainAcl(
		[]string{"example.com", "trusted.org"}, // 要允许的域名列表
		types.Whitelist,                        // 列表类型：白名单
		true,                                   // 启用子域名匹配
	)

	// 测试白名单工作情况
	checkDomains(whitelist, []string{
		"example.com",     // 应该被允许
		"sub.example.com", // 子域名应该被允许
		"malicious.com",   // 应该被阻止
		"trusted.org",     // 应该被允许
		"api.trusted.org", // 子域名应该被允许
	})

	// 示例3: 动态管理域名规则
	fmt.Println("\n示例3: 动态管理域名规则")
	// 创建一个空的域名黑名单
	dynamicAcl := domain.NewDomainAcl(
		[]string{}, // 初始为空
		types.Blacklist,
		true, // 启用子域名匹配
	)

	// 当前没有任何规则
	fmt.Println("初始状态 - 域名列表:", dynamicAcl.GetDomains())

	// 添加域名
	fmt.Println("添加域名: badsite.com, malware.net")
	dynamicAcl.Add("badsite.com", "malware.net")
	fmt.Println("添加后 - 域名列表:", dynamicAcl.GetDomains())

	// 检查是否生效
	checkDomain(dynamicAcl, "sub.badsite.com") // 应该被阻止

	// 移除域名
	fmt.Println("移除域名: badsite.com")
	err := dynamicAcl.Remove("badsite.com")
	if err != nil {
		log.Fatalf("移除域名失败: %v", err)
	}
	fmt.Println("移除后 - 域名列表:", dynamicAcl.GetDomains())

	// 检查移除是否生效
	checkDomain(dynamicAcl, "sub.badsite.com") // 应该被允许

	// 尝试移除不存在的域名
	fmt.Println("尝试移除不存在的域名: notexist.com")
	err = dynamicAcl.Remove("notexist.com")
	if err != nil {
		fmt.Printf("预期的错误: %v\n", err)
	}

	// 示例4: 域名规范化
	fmt.Println("\n示例4: 域名规范化功能")
	normAcl := domain.NewDomainAcl(
		[]string{"example.com"}, // 只有一个域名
		types.Blacklist,
		false,
	)

	// 测试不同格式的域名都能被正确匹配
	testDomains := []string{
		"example.com",             // 基本域名
		"EXAMPLE.COM",             // 大写域名
		"http://example.com",      // 带HTTP前缀
		"https://example.com",     // 带HTTPS前缀
		"www.example.com",         // 带www前缀(这个会被规范化，但不会匹配，因为禁用了子域名匹配)
		"example.com/path",        // 带路径
		"example.com?query=value", // 带查询参数
		"example.com#fragment",    // 带片段标识符
		"  example.com  ",         // 带空格
		"http://www.example.com/path?query=value#fragment", // 复杂URL
	}

	for _, d := range testDomains {
		fmt.Printf("检查域名 %-45s -> ", d)
		perm, _ := normAcl.Check(d)
		if perm == types.Denied {
			fmt.Println("被阻止 [域名匹配]")
		} else {
			fmt.Println("被允许 [域名不匹配]")
		}
	}
}

// 辅助函数：检查一系列域名
func checkDomains(acl *domain.DomainAcl, domains []string) {
	listType := "黑名单"
	if acl.GetListType() == types.Whitelist {
		listType = "白名单"
	}

	fmt.Printf("检查域名访问权限 (%s模式):\n", listType)
	for _, d := range domains {
		checkDomain(acl, d)
	}
}

// 辅助函数：检查单个域名
func checkDomain(acl *domain.DomainAcl, domain string) {
	permission, err := acl.Check(domain)
	if err != nil {
		fmt.Printf("  域名 %-20s -> 错误: %v\n", domain, err)
		return
	}

	if permission == types.Allowed {
		fmt.Printf("  域名 %-20s -> 允许访问\n", domain)
	} else {
		fmt.Printf("  域名 %-20s -> 拒绝访问\n", domain)
	}
}

/* 预期输出:
=== 域名访问控制列表(Domain ACL)基本用法示例 ===

示例1: 创建黑名单模式的域名ACL
检查域名访问权限 (黑名单模式):
  域名 evil.com            -> 拒绝访问
  域名 sub.evil.com        -> 允许访问
  域名 innocent.com        -> 允许访问
  域名 malware.org         -> 拒绝访问
  域名 www.malware.org     -> 允许访问

示例2: 创建白名单模式的域名ACL
检查域名访问权限 (白名单模式):
  域名 example.com         -> 允许访问
  域名 sub.example.com     -> 允许访问
  域名 malicious.com       -> 拒绝访问
  域名 trusted.org         -> 允许访问
  域名 api.trusted.org     -> 允许访问

示例3: 动态管理域名规则
初始状态 - 域名列表: []
添加域名: badsite.com, malware.net
添加后 - 域名列表: [badsite.com malware.net]
  域名 sub.badsite.com     -> 拒绝访问
移除域名: badsite.com
移除后 - 域名列表: [malware.net]
  域名 sub.badsite.com     -> a允许访问
尝试移除不存在的域名: notexist.com
预期的错误: 域名不在列表中

示例4: 域名规范化功能
检查域名 example.com                                -> 被阻止 [域名匹配]
检查域名 EXAMPLE.COM                                -> 被阻止 [域名匹配]
检查域名 http://example.com                         -> 被阻止 [域名匹配]
检查域名 https://example.com                        -> 被阻止 [域名匹配]
检查域名 www.example.com                            -> 被允许 [域名不匹配]
检查域名 example.com/path                           -> 被阻止 [域名匹配]
检查域名 example.com?query=value                    -> 被阻止 [域名匹配]
检查域名 example.com#fragment                       -> 被阻止 [域名匹配]
检查域名   example.com                              -> 被阻止 [域名匹配]
检查域名 http://www.example.com/path?query=value#fragment -> 被允许 [域名不匹配]
*/
