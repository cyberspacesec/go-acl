package domain

import "errors"

// ErrInvalidPredefinedSet 表示请求的预定义域名集合不存在
var ErrInvalidPredefinedSet = errors.New("无效的预定义域名集合")

// PredefinedSet 表示预定义域名集合的类型
//
// 预定义集合是一组相关的域名，用于简化常见安全场景的访问控制。
// 例如可一键阻止短链/网盘/代码托管等高风险域名类别，或放行可信公共服务域名。
type PredefinedSet string

// 预定义域名集合常量，用于参数传递
const (
	// Shorteners 包含常见的 URL 短链服务域名
	// 这些域名常被用于隐藏真实跳转目标，在反钓鱼/反恶意场景中常被整体阻止
	Shorteners PredefinedSet = "shorteners"

	// PublicFileSharing 包含常见公共网盘/文件分享服务域名
	// 数据外泄场景中常需阻止上传到这些服务
	PublicFileSharing PredefinedSet = "public_file_sharing"

	// CodeHosting 包含常见代码托管平台域名
	// 防止源码外泄或阻止从不受信源拉取代码时使用
	CodeHosting PredefinedSet = "code_hosting"

	// SocialMedia 包含主流社交媒体域名
	// 用于限制企业环境对外访问或防止社工攻击载荷投递
	SocialMedia PredefinedSet = "social_media"

	// WebmailProviders 包含常见网页邮箱服务域名
	// 数据外泄/钓鱼场景中常需控制
	WebmailProviders PredefinedSet = "webmail_providers"

	// TorExitNodes 包含 Tor 出口节点常用域名标识
	// 用于阻断匿名网络流量到已知 Tor 相关域名
	TorExitNodes PredefinedSet = "tor_exit_nodes"

	// DisposableEmail 包含一次性邮箱服务域名
	// 注册场景中常需阻止一次性邮箱绕过验证
	DisposableEmail PredefinedSet = "disposable_email"

	// TrustedCDN 包含可信公共 CDN 域名
	// 白名单场景下放行这些 CDN 加速域名
	TrustedCDN PredefinedSet = "trusted_cdn"

	// AllMaliciousDomains 包含上述所有高风险域名类别的合集
	// 这是一个便捷集合，适用于需要最全面外联管控的场景
	AllMaliciousDomains PredefinedSet = "all_malicious_domains"
)

// PredefinedSets 存储所有可用的预定义域名集合
//
// 每个集合的域名均为规范化后的小写裸域名（无协议/端口/路径），
// 在 AddPredefinedSet 注入时会再经 normalizeDomain 处理一次，保持幂等。
var PredefinedSets = map[PredefinedSet][]string{
	Shorteners: {
		"bit.ly",
		"tinyurl.com",
		"t.co",
		"goo.gl",
		"ow.ly",
		"is.gd",
		"buff.ly",
		"rebrand.ly",
		"cutt.ly",
	},

	PublicFileSharing: {
		"dropbox.com",
		"drive.google.com",
		"onedrive.live.com",
		"mega.nz",
		"wetransfer.com",
		"mediafire.com",
		"sendspace.com",
		"uploadfiles.io",
	},

	CodeHosting: {
		"github.com",
		"gitlab.com",
		"bitbucket.org",
		"gitee.com",
		"codeberg.org",
		"sourceforge.net",
	},

	SocialMedia: {
		"facebook.com",
		"twitter.com",
		"instagram.com",
		"linkedin.com",
		"tiktok.com",
		"weibo.com",
		"reddit.com",
	},

	WebmailProviders: {
		"gmail.com",
		"outlook.com",
		"yahoo.com",
		"hotmail.com",
		"mail.com",
		"protonmail.com",
		"icloud.com",
	},

	TorExitNodes: {
		"torproject.org",
		"check.torproject.org",
		"exit-relay.org",
	},

	DisposableEmail: {
		"mailinator.com",
		"guerrillamail.com",
		"tempmail.com",
		"10minutemail.com",
		"throwawaymail.com",
		"yopmail.com",
		"getnada.com",
	},

	TrustedCDN: {
		"cdn.cloudflare.net",
		"jsdelivr.net",
		"unpkg.com",
		"cdnjs.cloudflare.com",
		"ajax.googleapis.com",
	},
}

// init 合成 AllMaliciousDomains：合并除自身外所有集合，去重并排序保证幂等
func init() {
	seen := make(map[string]struct{})
	var all []string
	for set, domains := range PredefinedSets {
		if set == AllMaliciousDomains {
			continue
		}
		for _, d := range domains {
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			all = append(all, d)
		}
	}
	// 排序保证 init 幂等（map 遍历顺序不确定，排序后结果稳定）
	sortStrings(all)
	PredefinedSets[AllMaliciousDomains] = all
}

// sortStrings 对字符串切片做原地升序排序（仅标准库 sort，避免引入额外依赖感知）
func sortStrings(s []string) {
	// 使用插入排序：集合规模小（百级以内），且保持文件无额外 import 的简洁性
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j] < s[j-1] {
			s[j], s[j-1] = s[j-1], s[j]
			j--
		}
	}
}

// GetPredefinedDomains 获取指定预定义集合中的域名列表
//
// 参数:
//   - setName: 预定义集合名称
//     例如: domain.Shorteners, domain.DisposableEmail 等
//
// 返回:
//   - []string: 预定义集合中的域名列表
//     如果指定的集合不存在，返回 nil
//
// 示例:
//
//	shorteners := domain.GetPredefinedDomains(domain.Shorteners)
//	fmt.Printf("短链服务集合包含 %d 个域名\n", len(shorteners))
func GetPredefinedDomains(setName PredefinedSet) []string {
	if domains, ok := PredefinedSets[setName]; ok {
		return domains
	}
	return nil
}

// getPredefinedSet 内部辅助：返回集合与不存在的错误
func getPredefinedSet(setName PredefinedSet) ([]string, error) {
	if domains, ok := PredefinedSets[setName]; ok {
		return domains, nil
	}
	return nil, ErrInvalidPredefinedSet
}
