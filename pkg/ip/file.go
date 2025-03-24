package ip

import (
	"github.com/cyberspacesec/go-acl/pkg/config"
	"github.com/cyberspacesec/go-acl/pkg/types"
)

// NewIPAclFromFile 从配置文件创建一个新的IP访问控制列表
func NewIPAclFromFile(filePath string, listType types.ListType) (*IPAcl, error) {
	ipRanges, err := config.ReadIPList(filePath)
	if err != nil {
		return nil, err
	}

	return NewIPAcl(ipRanges, listType)
}

// SaveToFile 将当前IP访问控制列表保存到文件
// 如果文件已存在，overwrite参数决定是否覆盖文件
func (i *IPAcl) SaveToFile(filePath string, overwrite bool) error {
	// 获取当前的所有IP范围
	ipRanges := i.GetIPRanges()

	// 创建文件头部
	var header string
	if i.listType == types.Blacklist {
		header = "IP Blacklist - IPs in this list will be denied access"
	} else {
		header = "IP Whitelist - Only IPs in this list will be allowed access"
	}

	// 保存到文件
	return config.SaveIPList(filePath, ipRanges, header, overwrite)
}

// SaveToFileWithOverwrite 兼容旧版API，默认覆盖已存在的文件
// 已废弃：请改用 SaveToFile
func (i *IPAcl) SaveToFileWithOverwrite(filePath string) error {
	return i.SaveToFile(filePath, true)
}

// AddFromFile 从文件添加IP或CIDR到访问控制列表
func (i *IPAcl) AddFromFile(filePath string) error {
	ipRanges, err := config.ReadIPList(filePath)
	if err != nil {
		return err
	}

	return i.Add(ipRanges...)
}
