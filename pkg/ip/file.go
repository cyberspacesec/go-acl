package ip

import (
	"github.com/cyberspacesec/go-acl/pkg/config"
	"github.com/cyberspacesec/go-acl/pkg/types"
)

// NewIPACLFromFile 从指定文件创建IP访问控制列表
//
// 参数:
//   - filePath: 包含IP/CIDR列表的文件路径
//     例如: "/path/to/iplist.txt", "./config/blacklist.txt"
//   - listType: 列表类型（黑名单或白名单）
//     可用值: types.Blacklist（黑名单）或 types.Whitelist（白名单）
//
// 返回:
//   - *IPACL: 创建的IP访问控制列表，成功时非nil
//   - error: 可能的错误:
//   - config.ErrFileNotFound: 文件不存在
//   - config.ErrEmptyFile: 文件为空或只包含注释
//   - ErrInvalidIP: 文件中包含无效的IP地址
//   - ErrInvalidCIDR: 文件中包含无效的CIDR格式
//   - 其他系统错误: 如权限错误、I/O错误等
//
// 文件格式要求与config.ReadIPList相同:
//   - 每行一个IP/CIDR
//   - #开头的行被视为注释，将被忽略
//   - 行内#后的内容被视为注释，将被忽略
//   - 空行会被忽略
//
// 示例文件内容:
//
//	# 这是IP列表
//	192.168.1.1     # 单个IPv4地址
//	10.0.0.0/8      # IPv4网段
//	2001:db8::/32   # IPv6网段
//
// 示例:
//
//	// 从文件创建IP黑名单
//	ipACL, err := ip.NewIPACLFromFile("./blacklist.txt", types.Blacklist)
//	if err != nil {
//	    if errors.Is(err, config.ErrFileNotFound) {
//	        log.Println("指定的IP列表文件不存在")
//	    } else if errors.Is(err, config.ErrEmptyFile) {
//	        log.Println("IP列表文件为空")
//	    } else if errors.Is(err, ip.ErrInvalidIP) || errors.Is(err, ip.ErrInvalidCIDR) {
//	        log.Printf("文件包含无效的IP格式: %v", err)
//	    } else {
//	        log.Printf("创建IP ACL失败: %v", err)
//	    }
//	    return
//	}
//
//	// 使用创建的ACL
//	fmt.Printf("已创建包含 %d 个IP/CIDR的%s\n",
//	           len(ipACL.GetIPRanges()),
//	           ipACL.GetListType())
func NewIPACLFromFile(filePath string, listType types.ListType) (*IPACL, error) {
	// 从文件读取IP列表
	ipRanges, err := config.ReadIPList(filePath)
	if err != nil {
		return nil, err
	}

	// 创建IP访问控制列表
	return NewIPACL(ipRanges, listType)
}

// SaveToFile 将IP访问控制列表保存到文件
//
// 参数:
//   - filePath: 要保存的文件路径
//     例如: "/path/to/iplist.txt", "./config/blacklist.txt"
//   - overwrite: 是否覆盖已存在的文件
//     true: 如果文件已存在，会被覆盖
//     false: 如果文件已存在，返回config.ErrFileExists错误
//
// 返回:
//   - error: 可能的错误:
//   - config.ErrFileExists: 文件已存在且overwrite=false
//   - config.ErrFilePermission: 无权限写入文件
//   - 其他系统错误: 如路径不存在、I/O错误等
//
// 生成的文件格式:
//   - 第一行是自动生成的标题（基于列表类型）
//   - 第二行是生成时间
//   - 之后每行一个IP/CIDR
//
// 默认标题格式:
//   - 黑名单: "IP Blacklist - IPs in this list will be denied access"
//   - 白名单: "IP Whitelist - Only IPs in this list will be allowed access"
//
// 示例:
//
//	// 创建一个IP黑名单
//	ipACL, _ := ip.NewIPACL(
//	    []string{"192.168.1.1", "10.0.0.0/8"},
//	    types.Blacklist
//	)
//
//	// 保存到文件，允许覆盖
//	err := ipACL.SaveToFile("./my_blacklist.txt", true)
//	if err != nil {
//	    log.Printf("保存IP列表失败: %v", err)
//	    return
//	}
//
//	log.Println("成功保存IP列表到文件")
//
//	// 保存到另一个文件，不允许覆盖
//	err = ipACL.SaveToFile("./backup.txt", false)
//	if errors.Is(err, config.ErrFileExists) {
//	    log.Println("备份文件已存在，未覆盖")
//	}
func (a *IPACL) SaveToFile(filePath string, overwrite bool) error {
	// 根据列表类型生成适当的标题
	var header string
	if a.listType == types.Blacklist {
		header = "IP Blacklist - IPs in this list will be denied access"
	} else {
		header = "IP Whitelist - Only IPs in this list will be allowed access"
	}

	// 保存到文件
	return config.SaveIPList(filePath, a.GetIPRanges(), header, overwrite)
}

// SaveToFileWithOverwrite 兼容旧版API，默认覆盖已存在的文件
// 已废弃：请改用 SaveToFile
func (i *IPACL) SaveToFileWithOverwrite(filePath string) error {
	return i.SaveToFile(filePath, true)
}

// AddFromFile 从文件添加IP/CIDR到现有的访问控制列表
//
// 参数:
//   - filePath: 包含IP/CIDR列表的文件路径
//     例如: "/path/to/additional_ips.txt", "./more_ips.txt"
//
// 返回:
//   - error: 可能的错误:
//   - config.ErrFileNotFound: 文件不存在
//   - config.ErrEmptyFile: 文件为空或只包含注释
//   - ErrInvalidIP: 文件中包含无效的IP地址
//   - ErrInvalidCIDR: 文件中包含无效的CIDR格式
//   - 其他系统错误: 如权限错误、I/O错误等
//
// 文件格式要求与NewIPACLFromFile相同。
// 与创建新ACL不同，此方法将文件中的IP/CIDR添加到现有列表中，
// 不会替换原有内容。
//
// 示例:
//
//	// 创建一个初始IP黑名单
//	ipACL, _ := ip.NewIPACL(
//	    []string{"192.168.1.1"},
//	    types.Blacklist
//	)
//
//	// 从文件添加更多IP
//	err := ipACL.AddFromFile("./more_ips.txt")
//	if err != nil {
//	    if errors.Is(err, config.ErrFileNotFound) {
//	        log.Println("指定的IP列表文件不存在")
//	    } else if errors.Is(err, ip.ErrInvalidIP) {
//	        log.Printf("文件包含无效的IP: %v", err)
//	    } else {
//	        log.Printf("添加IP失败: %v", err)
//	    }
//	    return
//	}
//
//	// 查看更新后的IP列表
//	fmt.Printf("当前包含 %d 个IP/CIDR\n", len(ipACL.GetIPRanges()))
func (a *IPACL) AddFromFile(filePath string) error {
	// 从文件读取IP列表
	ipRanges, err := config.ReadIPList(filePath)
	if err != nil {
		return err
	}

	// 添加到现有列表
	return a.Add(ipRanges...)
}
