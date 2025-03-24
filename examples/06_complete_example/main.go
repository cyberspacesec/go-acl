package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cyberspacesec/go-acl/pkg/acl"
	"github.com/cyberspacesec/go-acl/pkg/ip"
	"github.com/cyberspacesec/go-acl/pkg/types"
)

// WebApp 模拟一个使用访问控制的Web应用程序
type WebApp struct {
	Name              string
	ConfigDir         string
	AccessController  *acl.Manager
	AccessLog         []string
	LastConfigChanged time.Time
}

// Request 模拟一个Web请求
type Request struct {
	URL       string
	ClientIP  string
	Timestamp time.Time
	Method    string
	Path      string
}

func main() {
	fmt.Println("===== 完整综合示例：Web应用访问控制 =====")

	// 创建配置目录
	configDir := "app_config"
	_ = os.Mkdir(configDir, 0755)
	defer os.RemoveAll(configDir)

	// 创建并配置Web应用
	app := NewWebApp("演示应用", configDir)
	fmt.Printf("\n已创建Web应用: %s\n", app.Name)

	// 初始化访问控制
	fmt.Println("\n1. 初始化访问控制系统")
	app.InitAccessControl()

	// 模拟处理请求
	fmt.Println("\n2. 模拟Web请求处理")
	app.SimulateRequests()

	// 动态更新规则
	fmt.Println("\n3. 动态更新访问规则")
	app.UpdateAccessRules()

	// 加载安全配置
	fmt.Println("\n4. 加载安全配置")
	app.LoadSecurityConfig()

	// 模拟更多请求
	fmt.Println("\n5. 处理更多请求")
	app.SimulateMoreRequests()

	// 显示访问日志摘要
	fmt.Println("\n6. 访问日志摘要")
	app.ShowAccessLogSummary()
}

// NewWebApp 创建一个新的Web应用实例
func NewWebApp(name, configDir string) *WebApp {
	return &WebApp{
		Name:              name,
		ConfigDir:         configDir,
		AccessController:  acl.NewManager(),
		AccessLog:         make([]string, 0),
		LastConfigChanged: time.Now(),
	}
}

// InitAccessControl 初始化访问控制配置
func (app *WebApp) InitAccessControl() {
	// 1. 创建并保存域名黑名单
	fmt.Println("- 创建域名黑名单")
	domainBlacklist := []string{
		"malware-site.com",     // 已知恶意网站
		"phishing-example.org", // 钓鱼网站
		"spam-domain.net",      // 垃圾邮件域名
		"malicious-ads.com",    // 恶意广告域名
	}
	app.AccessController.SetDomainACL(domainBlacklist, types.Blacklist, true)

	// 保存黑名单到文件
	domainsFile := filepath.Join(app.ConfigDir, "domain_blacklist.txt")
	content := "# 域名黑名单\n# 以下域名及其子域名将被阻止\n\n"
	for _, domain := range domainBlacklist {
		content += domain + "\n"
	}
	err := os.WriteFile(domainsFile, []byte(content), 0644)
	if err != nil {
		fmt.Printf("保存域名黑名单失败: %v\n", err)
	} else {
		fmt.Printf("域名黑名单已保存到: %s\n", domainsFile)
	}

	// 2. 创建IP安全配置（防止SSRF攻击）
	fmt.Println("- 创建IP访问控制")
	err = app.AccessController.SetIPACLWithDefaults(
		[]string{}, // 没有额外自定义IP
		types.Blacklist,
		[]ip.PredefinedSet{
			ip.PrivateNetworks,   // 阻止访问内网
			ip.LoopbackNetworks,  // 阻止访问本地回环
			ip.CloudMetadata,     // 阻止访问云元数据服务
			ip.LinkLocalNetworks, // 阻止链路本地地址
			ip.DockerNetworks,    // 阻止Docker默认网络
		},
		false, // 阻止这些预定义集合
	)
	if err != nil {
		fmt.Printf("创建IP访问控制失败: %v\n", err)
	}

	// 添加一些自定义IP规则
	app.AccessController.AddIP(
		"203.0.113.1",     // 阻止特定IP
		"198.51.100.0/24", // 阻止特定网段
	)

	// 3. 保存配置
	ipFile := filepath.Join(app.ConfigDir, "ip_blacklist.txt")
	err = app.AccessController.SaveIPACLToFile(ipFile, true)
	if err != nil {
		fmt.Printf("保存IP黑名单失败: %v\n", err)
	} else {
		fmt.Printf("IP黑名单已保存到: %s\n", ipFile)
	}

	// 显示初始配置
	app.PrintAccessControlConfig()
	app.LastConfigChanged = time.Now()
}

// PrintAccessControlConfig 打印当前访问控制配置
func (app *WebApp) PrintAccessControlConfig() {
	fmt.Println("\n当前访问控制配置:")

	// 显示域名配置
	domainType, err := app.AccessController.GetDomainACLType()
	if err == nil {
		typeStr := "黑名单"
		if domainType == types.Whitelist {
			typeStr = "白名单"
		}
		domains := app.AccessController.GetDomains()
		fmt.Printf("域名 %s: 包含 %d 个域名\n", typeStr, len(domains))

		if len(domains) > 0 {
			fmt.Println("部分域名列表:")
			maxShow := 3
			if len(domains) < maxShow {
				maxShow = len(domains)
			}
			for i := 0; i < maxShow; i++ {
				fmt.Printf("  %d. %s\n", i+1, domains[i])
			}
			if len(domains) > maxShow {
				fmt.Printf("  ...共 %d 个域名\n", len(domains))
			}
		}
	} else if errors.Is(err, types.ErrNoAcl) {
		fmt.Println("域名ACL: 未配置")
	} else {
		fmt.Printf("获取域名ACL失败: %v\n", err)
	}

	// 显示IP配置
	ipType, err := app.AccessController.GetIPACLType()
	if err == nil {
		typeStr := "黑名单"
		if ipType == types.Whitelist {
			typeStr = "白名单"
		}
		ips := app.AccessController.GetIPRanges()
		fmt.Printf("IP %s: 包含 %d 个IP/CIDR\n", typeStr, len(ips))

		if len(ips) > 0 {
			fmt.Println("部分IP列表:")
			maxShow := 3
			if len(ips) < maxShow {
				maxShow = len(ips)
			}
			for i := 0; i < maxShow; i++ {
				fmt.Printf("  %d. %s\n", i+1, ips[i])
			}
			if len(ips) > maxShow {
				fmt.Printf("  ...共 %d 个IP/CIDR\n", len(ips))
			}
		}
	} else if errors.Is(err, types.ErrNoAcl) {
		fmt.Println("IP ACL: 未配置")
	} else {
		fmt.Printf("获取IP ACL失败: %v\n", err)
	}

	fmt.Printf("上次配置修改时间: %s\n", app.LastConfigChanged.Format("2006-01-02 15:04:05"))
}

// ProcessRequest 处理Web请求并进行访问控制检查
func (app *WebApp) ProcessRequest(req *Request) bool {
	now := time.Now()
	var allowed bool
	var reason string

	// 提取域名或IP
	host := extractHost(req.URL)

	// 检查域名
	domainPerm, domainErr := app.AccessController.CheckDomain(host)
	if domainErr == nil && domainPerm == types.Denied {
		allowed = false
		reason = "域名黑名单"
	} else {
		// 检查目标IP (如果host是IP地址)
		ipPerm, ipErr := app.AccessController.CheckIP(host)
		if ipErr == nil && ipPerm == types.Denied {
			allowed = false
			reason = "IP黑名单"
		} else {
			// 检查客户端IP
			clientPerm, clientErr := app.AccessController.CheckIP(req.ClientIP)
			if clientErr == nil && clientPerm == types.Denied {
				allowed = false
				reason = "客户端IP黑名单"
			} else {
				allowed = true
				reason = "无限制"
			}
		}
	}

	// 记录访问日志
	var status string
	if allowed {
		status = "允许"
	} else {
		status = "拒绝"
	}

	logEntry := fmt.Sprintf("[%s] %s %s -> %s %s (%s)",
		now.Format("15:04:05"),
		req.ClientIP,
		req.Method,
		req.URL,
		status,
		reason)
	app.AccessLog = append(app.AccessLog, logEntry)

	// 打印访问记录
	fmt.Printf("- %s\n", logEntry)

	return allowed
}

// SimulateRequests 模拟处理一系列Web请求
func (app *WebApp) SimulateRequests() {
	requests := []Request{
		{
			URL:       "https://api.example.com/data",
			ClientIP:  "203.0.113.5",
			Timestamp: time.Now(),
			Method:    "GET",
			Path:      "/data",
		},
		{
			URL:       "https://malware-site.com/download",
			ClientIP:  "198.51.100.5",
			Timestamp: time.Now().Add(1 * time.Second),
			Method:    "GET",
			Path:      "/download",
		},
		{
			URL:       "http://internal-service.local/admin",
			ClientIP:  "203.0.113.10",
			Timestamp: time.Now().Add(2 * time.Second),
			Method:    "POST",
			Path:      "/admin",
		},
		{
			URL:       "https://legitimate-site.org/api",
			ClientIP:  "203.0.113.1", // 黑名单中的IP
			Timestamp: time.Now().Add(3 * time.Second),
			Method:    "GET",
			Path:      "/api",
		},
		{
			URL:       "http://192.168.1.1/router-admin",
			ClientIP:  "203.0.113.20",
			Timestamp: time.Now().Add(4 * time.Second),
			Method:    "GET",
			Path:      "/router-admin",
		},
	}

	fmt.Println("处理Web请求:")
	for _, req := range requests {
		app.ProcessRequest(&req)
	}
}

// UpdateAccessRules 动态更新访问规则
func (app *WebApp) UpdateAccessRules() {
	// 添加新发现的恶意域名
	fmt.Println("- 添加新发现的恶意域名")
	err := app.AccessController.AddDomain(
		"new-threat.com",
		"suspicious-site.org",
	)
	if err != nil {
		fmt.Printf("添加恶意域名失败: %v\n", err)
	} else {
		fmt.Println("已添加新发现的恶意域名到黑名单")
	}

	// 从IP黑名单中移除误判的IP
	fmt.Println("- 从黑名单中移除误判的IP")
	err = app.AccessController.RemoveIP("203.0.113.1")
	if err != nil {
		fmt.Printf("移除IP失败: %v\n", err)
	} else {
		fmt.Println("已从黑名单中移除IP 203.0.113.1")
	}

	// 保存更新后的配置
	fmt.Println("- 保存更新后的配置")
	ipFile := filepath.Join(app.ConfigDir, "ip_blacklist_updated.txt")
	err = app.AccessController.SaveIPACLToFile(ipFile, true)
	if err != nil {
		fmt.Printf("保存更新后的IP黑名单失败: %v\n", err)
	} else {
		fmt.Printf("更新后的IP黑名单已保存到: %s\n", ipFile)
	}

	app.LastConfigChanged = time.Now()
	app.PrintAccessControlConfig()
}

// LoadSecurityConfig 加载安全配置
func (app *WebApp) LoadSecurityConfig() {
	// 演示加载安全配置（这里我们重新设置配置来模拟）
	fmt.Println("- 切换到高安全模式")

	// 重置当前配置
	app.AccessController.Reset()

	// 1. 设置域名白名单（只允许特定域名访问）
	trustedDomains := []string{
		"api.example.com",
		"trusted-partner.org",
		"our-cdn.net",
	}
	app.AccessController.SetDomainACL(trustedDomains, types.Whitelist, true)
	fmt.Println("已切换至域名白名单模式")

	// 2. 设置IP白名单（阻止所有非特定IP的访问）
	allowedIPs := []string{
		"203.0.113.0/24", // 公司网络
		"198.51.100.5",   // 特定合作伙伴
	}

	// 添加公共DNS服务器到白名单
	err := app.AccessController.SetIPACLWithDefaults(
		allowedIPs,
		types.Whitelist,
		[]ip.PredefinedSet{ip.PublicDNS},
		true, // 允许这些预定义集合
	)
	if err != nil {
		fmt.Printf("设置IP白名单失败: %v\n", err)
	} else {
		fmt.Println("已切换至IP白名单模式")
	}

	// 保存高安全模式配置
	fmt.Println("- 保存高安全模式配置")
	securityConfigDir := filepath.Join(app.ConfigDir, "security")
	_ = os.Mkdir(securityConfigDir, 0755)

	ipFile := filepath.Join(securityConfigDir, "whitelist.txt")
	err = app.AccessController.SaveIPACLToFile(ipFile, true)
	if err != nil {
		fmt.Printf("保存IP白名单失败: %v\n", err)
	}

	// 将白名单域名写入文件
	domainsFile := filepath.Join(securityConfigDir, "domain_whitelist.txt")
	content := "# 域名白名单\n# 仅允许以下域名及其子域名\n\n"
	for _, domain := range trustedDomains {
		content += domain + "\n"
	}
	err = os.WriteFile(domainsFile, []byte(content), 0644)
	if err != nil {
		fmt.Printf("保存域名白名单失败: %v\n", err)
	}

	app.LastConfigChanged = time.Now()
	app.PrintAccessControlConfig()
}

// SimulateMoreRequests 模拟处理更多请求（在高安全模式下）
func (app *WebApp) SimulateMoreRequests() {
	requests := []Request{
		{
			URL:       "https://api.example.com/data",
			ClientIP:  "203.0.113.5",
			Timestamp: time.Now(),
			Method:    "GET",
			Path:      "/data",
		},
		{
			URL:       "https://unknown-site.com/page",
			ClientIP:  "203.0.113.10",
			Timestamp: time.Now().Add(1 * time.Second),
			Method:    "GET",
			Path:      "/page",
		},
		{
			URL:       "https://subdomain.trusted-partner.org/api",
			ClientIP:  "198.51.100.5",
			Timestamp: time.Now().Add(2 * time.Second),
			Method:    "POST",
			Path:      "/api",
		},
		{
			URL:       "https://legitimate-site.org/api",
			ClientIP:  "203.0.113.1",
			Timestamp: time.Now().Add(3 * time.Second),
			Method:    "GET",
			Path:      "/api",
		},
		{
			URL:       "https://our-cdn.net/assets/image.jpg",
			ClientIP:  "192.168.1.1", // 内网IP（不在白名单中）
			Timestamp: time.Now().Add(4 * time.Second),
			Method:    "GET",
			Path:      "/assets/image.jpg",
		},
	}

	fmt.Println("处理更多Web请求（高安全模式）:")
	for _, req := range requests {
		app.ProcessRequest(&req)
	}
}

// ShowAccessLogSummary 显示访问日志摘要
func (app *WebApp) ShowAccessLogSummary() {
	totalRequests := len(app.AccessLog)
	allowedCount := 0
	deniedCount := 0

	for _, log := range app.AccessLog {
		if strings.Contains(log, "允许") {
			allowedCount++
		} else if strings.Contains(log, "拒绝") {
			deniedCount++
		}
	}

	fmt.Printf("总请求数: %d\n", totalRequests)
	fmt.Printf("允许请求: %d (%.1f%%)\n", allowedCount, float64(allowedCount)/float64(totalRequests)*100)
	fmt.Printf("拒绝请求: %d (%.1f%%)\n", deniedCount, float64(deniedCount)/float64(totalRequests)*100)

	// 显示最近的几条日志
	if totalRequests > 0 {
		fmt.Println("\n最近的日志记录:")
		start := 0
		if totalRequests > 5 {
			start = totalRequests - 5
		}
		for i := start; i < totalRequests; i++ {
			fmt.Printf("%d. %s\n", i+1, app.AccessLog[i])
		}
	}
}

// 提取URL中的主机部分（域名或IP）
func extractHost(url string) string {
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

	return url
}

/*
预期输出:

===== 完整综合示例：Web应用访问控制 =====

已创建Web应用: 演示应用

1. 初始化访问控制系统
- 创建域名黑名单
域名黑名单已保存到: app_config/domain_blacklist.txt
- 创建IP访问控制
IP黑名单已保存到: app_config/ip_blacklist.txt

当前访问控制配置:
域名 黑名单: 包含 4 个域名
部分域名列表:
  1. malware-site.com
  2. phishing-example.org
  3. spam-domain.net
  ...共 4 个域名
IP 黑名单: 包含 20+ 个IP/CIDR
部分IP列表:
  1. 10.0.0.0/8
  2. 172.16.0.0/12
  3. 192.168.0.0/16
  ...共 20+ 个IP/CIDR
上次配置修改时间: 2023-11-10 12:34:56

2. 模拟Web请求处理
处理Web请求:
- [12:34:56] 203.0.113.5 GET -> https://api.example.com/data 允许 (无限制)
- [12:34:57] 198.51.100.5 GET -> https://malware-site.com/download 拒绝 (域名黑名单)
- [12:34:58] 203.0.113.10 POST -> http://internal-service.local/admin 允许 (无限制)
- [12:34:59] 203.0.113.1 GET -> https://legitimate-site.org/api 拒绝 (客户端IP黑名单)
- [12:35:00] 203.0.113.20 GET -> http://192.168.1.1/router-admin 拒绝 (IP黑名单)

3. 动态更新访问规则
- 添加新发现的恶意域名
已添加新发现的恶意域名到黑名单
- 从黑名单中移除误判的IP
已从黑名单中移除IP 203.0.113.1
- 保存更新后的配置
更新后的IP黑名单已保存到: app_config/ip_blacklist_updated.txt

当前访问控制配置:
域名 黑名单: 包含 6 个域名
部分域名列表:
  1. malware-site.com
  2. phishing-example.org
  3. spam-domain.net
  ...共 6 个域名
IP 黑名单: 包含 19+ 个IP/CIDR
部分IP列表:
  1. 10.0.0.0/8
  2. 172.16.0.0/12
  3. 192.168.0.0/16
  ...共 19+ 个IP/CIDR
上次配置修改时间: 2023-11-10 12:35:05

4. 加载安全配置
- 切换到高安全模式
已切换至域名白名单模式
已切换至IP白名单模式
- 保存高安全模式配置

当前访问控制配置:
域名 白名单: 包含 3 个域名
部分域名列表:
  1. api.example.com
  2. trusted-partner.org
  3. our-cdn.net
  ...共 3 个域名
IP 白名单: 包含 8+ 个IP/CIDR
部分IP列表:
  1. 203.0.113.0/24
  2. 198.51.100.5
  3. 8.8.8.8
  ...共 8+ 个IP/CIDR
上次配置修改时间: 2023-11-10 12:35:10

5. 处理更多请求
处理更多Web请求（高安全模式）:
- [12:35:15] 203.0.113.5 GET -> https://api.example.com/data 允许 (无限制)
- [12:35:16] 203.0.113.10 GET -> https://unknown-site.com/page 拒绝 (域名黑名单)
- [12:35:17] 198.51.100.5 POST -> https://subdomain.trusted-partner.org/api 允许 (无限制)
- [12:35:18] 203.0.113.1 GET -> https://legitimate-site.org/api 拒绝 (域名黑名单)
- [12:35:19] 192.168.1.1 GET -> https://our-cdn.net/assets/image.jpg 拒绝 (客户端IP黑名单)

6. 访问日志摘要
总请求数: 10
允许请求: 3 (30.0%)
拒绝请求: 7 (70.0%)

最近的日志记录:
6. [12:35:15] 203.0.113.5 GET -> https://api.example.com/data 允许 (无限制)
7. [12:35:16] 203.0.113.10 GET -> https://unknown-site.com/page 拒绝 (域名黑名单)
8. [12:35:17] 198.51.100.5 POST -> https://subdomain.trusted-partner.org/api 允许 (无限制)
9. [12:35:18] 203.0.113.1 GET -> https://legitimate-site.org/api 拒绝 (域名黑名单)
10. [12:35:19] 192.168.1.1 GET -> https://our-cdn.net/assets/image.jpg 拒绝 (客户端IP黑名单)
*/
