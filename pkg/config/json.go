package config

import (
	"encoding/json"
	"os"
)

// DomainPolicy 描述一份域名 ACL 配置
//
// ListType 取 "blacklist" 或 "whitelist"；IncludeSubdomains 控制子域名匹配。
type DomainPolicy struct {
	Domains           []string `json:"domains"`
	ListType          string   `json:"listType"`
	IncludeSubdomains bool     `json:"includeSubdomains"`
	// File 可选：从该文件加载域名规则，与 Domains 合并
	File string `json:"file,omitempty"`
}

// IPPolicy 描述一份 IP ACL 配置
//
// ListType 取 "blacklist" 或 "whitelist"；PredefinedSets 引用预定义集合名。
type IPPolicy struct {
	Ranges          []string `json:"ranges"`
	ListType        string   `json:"listType"`
	PredefinedSets  []string `json:"predefinedSets,omitempty"`
	AllowPredefined bool     `json:"allowPredefined,omitempty"`
	// File 可选：从该文件加载 IP 规则，与 Ranges 合并
	File string `json:"file,omitempty"`
}

// Policy 是一份完整的访问控制策略，可同时包含域名与 IP 规则
//
// 任一字段为零值时表示不配置该类型 ACL，允许只配置域名或只配置 IP。
type Policy struct {
	Domain *DomainPolicy `json:"domain,omitempty"`
	IP     *IPPolicy     `json:"ip,omitempty"`
}

// LoadPolicyFromBytes 从 JSON 字节流解析 Policy
func LoadPolicyFromBytes(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadPolicyFromFile 从 JSON 文件加载 Policy
//
// 参数:
//   - filePath: JSON 配置文件路径
//
// 返回:
//   - *Policy: 解析得到的策略
//   - error: 文件不存在返回 ErrFileNotFound，其他返回原错误
func LoadPolicyFromFile(filePath string) (*Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrFileNotFound
		}
		return nil, err
	}
	return LoadPolicyFromBytes(data)
}
