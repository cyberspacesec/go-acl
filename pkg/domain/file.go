package domain

import (
	"github.com/cyberspacesec/acl-skills/pkg/config"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// NewDomainACLFromFile 从文件创建域名访问控制列表
//
// 参数:
//   - filePath: 包含域名列表的文件路径（每行一个域名，支持 # 注释与行内注释）
//   - listType: 列表类型（黑名单或白名单）
//   - includeSubdomains: 是否包含子域名匹配
//
// 返回:
//   - *DomainACL: 创建的域名访问控制列表
//   - error: config.ErrFileNotFound / config.ErrEmptyFile / 其他系统错误
//
// 文件格式与 config.ReadIPACL 相同（每行一条，# 开头注释，行内 # 后内容忽略，空行忽略）。
func NewDomainACLFromFile(filePath string, listType types.ListType, includeSubdomains bool) (*DomainACL, error) {
	domains, err := config.ReadIPACL(filePath)
	if err != nil {
		return nil, err
	}
	return NewDomainACL(domains, listType, includeSubdomains), nil
}

// SaveToFile 将域名访问控制列表保存到文件
//
// 参数:
//   - filePath: 要保存的文件路径
//   - overwrite: 是否覆盖已存在的文件
//
// 返回:
//   - error: config.ErrFileExists / config.ErrFilePermission / 其他系统错误
//
// 生成的文件格式: 标题注释行 + 生成时间注释行 + 每行一个域名。
func (d *DomainACL) SaveToFile(filePath string, overwrite bool) error {
	var header string
	if d.listType == types.Blacklist {
		header = "Domain Blacklist - domains in this list will be denied access"
	} else {
		header = "Domain Whitelist - only domains in this list will be allowed access"
	}
	return config.SaveIPACLWithHeader(filePath, d.GetDomains(), header, overwrite)
}

// SaveToFileWithOverwrite 兼容旧版风格，默认覆盖已存在的文件
// 已废弃：请改用 SaveToFile
func (d *DomainACL) SaveToFileWithOverwrite(filePath string) error {
	return d.SaveToFile(filePath, true)
}

// AddFromFile 从文件添加域名到现有的访问控制列表
//
// 参数:
//   - filePath: 包含域名列表的文件路径
//
// 返回:
//   - error: config.ErrFileNotFound / config.ErrEmptyFile / 其他系统错误
//
// 与 NewDomainACLFromFile 不同，此方法将文件中的域名添加到现有列表，不替换原有内容。
func (d *DomainACL) AddFromFile(filePath string) error {
	domains, err := config.ReadIPACL(filePath)
	if err != nil {
		return err
	}
	return d.Add(domains...)
}
