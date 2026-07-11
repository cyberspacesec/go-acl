package acl

import (
	"fmt"

	"github.com/cyberspacesec/acl-skills/pkg/config"
	"github.com/cyberspacesec/acl-skills/pkg/ip"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// ApplyPolicy 将一份 JSON 配置解析得到的 Policy 应用到 Manager
//
// 根据 Policy 中的 Domain / IP 字段，调用 Manager 既有的 SetDomainACL / SetIPACL /
// SetIPACLWithDefaults 注入规则。零值字段（nil）表示跳过该类型 ACL，不覆盖已注册的同名 kind。
//
// 参数:
//   - p: 已解析的策略；若为 nil 直接返回 nil
//
// 返回:
//   - error: listType 取值非法、IP 格式错误、预定义集合名错误等
//
// 示例:
//
//	pol, err := config.LoadPolicyFromFile("./policy.json")
//	if err != nil { return err }
//	if err := manager.ApplyPolicy(pol); err != nil { return err }
func (m *Manager) ApplyPolicy(p *config.Policy) error {
	if p == nil {
		return nil
	}

	if p.Domain != nil {
		domains := p.Domain.Domains
		// 若配置了 File，从文件追加加载域名（与显式 Domains 合并）
		if p.Domain.File != "" {
			fileDomains, err := config.ReadIPACL(p.Domain.File)
			if err != nil {
				return fmt.Errorf("load domain file %q: %w", p.Domain.File, err)
			}
			domains = append(domains, fileDomains...)
		}
		listType, err := parseListType(p.Domain.ListType)
		if err != nil {
			return fmt.Errorf("domain listType: %w", err)
		}
		m.SetDomainACL(domains, listType, p.Domain.IncludeSubdomains)
	}

	if p.IP != nil {
		listType, err := parseListType(p.IP.ListType)
		if err != nil {
			return fmt.Errorf("ip listType: %w", err)
		}

		var predefinedSets []ip.PredefinedSet
		for _, name := range p.IP.PredefinedSets {
			predefinedSets = append(predefinedSets, ip.PredefinedSet(name))
		}

		// 优先用 SetIPACLWithDefaults（当有预定义集合时），否则用 SetIPACL
		if len(predefinedSets) > 0 {
			if err := m.SetIPACLWithDefaults(p.IP.Ranges, listType, predefinedSets, p.IP.AllowPredefined); err != nil {
				return fmt.Errorf("apply ip policy: %w", err)
			}
		} else {
			if err := m.SetIPACL(p.IP.Ranges, listType); err != nil {
				return fmt.Errorf("apply ip policy: %w", err)
			}
		}

		// 若配置了 File，从文件追加 IP 规则
		if p.IP.File != "" {
			if err := m.AddIPFromFile(p.IP.File); err != nil {
				return fmt.Errorf("load ip file %q: %w", p.IP.File, err)
			}
		}
	}

	return nil
}

// parseListType 将字符串 "blacklist"/"whitelist" 转为 types.ListType
//
// 空字符串默认按 blacklist 处理（与库默认行为一致）。
func parseListType(s string) (types.ListType, error) {
	switch s {
	case "", "blacklist":
		return types.Blacklist, nil
	case "whitelist":
		return types.Whitelist, nil
	default:
		return 0, fmt.Errorf("invalid listType %q (want blacklist|whitelist)", s)
	}
}
