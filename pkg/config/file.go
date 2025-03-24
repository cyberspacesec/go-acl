package config

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"time"
)

// 标准错误定义
var (
	// ErrFileNotFound 表示要操作的文件不存在
	ErrFileNotFound = errors.New("文件不存在")
	// ErrEmptyFile 表示文件为空或只包含注释
	ErrEmptyFile = errors.New("文件为空或只包含注释")
	// ErrFileExists 表示要创建的文件已经存在
	ErrFileExists = errors.New("文件已存在")
	// ErrFilePermission 表示无权限操作文件
	ErrFilePermission = errors.New("文件权限错误")
)

// ReadIPACL 从文件中读取IP/CIDR列表
//
// 参数:
//   - filePath: 要读取的文件路径
//     例如: "/path/to/iplist.txt", "./config/blacklist.txt"
//
// 返回:
//   - []string: 成功读取的IP/CIDR列表
//     例如: []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
//   - error: 可能的错误:
//   - ErrFileNotFound: 文件不存在
//   - ErrEmptyFile: 文件为空或只包含注释
//   - 其他系统错误: 如权限错误、I/O错误等
//
// 文件格式要求:
//   - 每行一个IP/CIDR
//   - #开头的行被视为注释，将被忽略
//   - 行内#后的内容被视为注释，将被忽略
//   - 空行和只包含空白字符的行会被忽略
//   - 每个IP/CIDR前后的空白字符会被自动移除
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
//	// 读取IP列表
//	ips, err := config.ReadIPACL("./blacklist.txt")
//	if err != nil {
//	    if errors.Is(err, config.ErrFileNotFound) {
//	        log.Println("指定的IP列表文件不存在")
//	    } else if errors.Is(err, config.ErrEmptyFile) {
//	        log.Println("IP列表文件为空")
//	    } else {
//	        log.Printf("读取IP列表失败: %v", err)
//	    }
//	    return
//	}
//
//	fmt.Printf("成功读取 %d 个IP/CIDR\n", len(ips))
//	for _, ip := range ips {
//	    fmt.Println(ip)
//	}
func ReadIPACL(filePath string) ([]string, error) {
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, ErrFileNotFound
	}

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		// 去除首尾空格
		line = strings.TrimSpace(line)

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 移除行内注释
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// 如果处理后的行不为空，则添加到列表中
		if line != "" {
			ips = append(ips, line)
		}
	}

	// 检查扫描错误
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// 检查是否为空列表
	if len(ips) == 0 {
		return nil, ErrEmptyFile
	}

	return ips, nil
}

// SaveIPACLWithHeader 将IP/CIDR列表保存到文件
//
// 参数:
//   - filePath: 要保存的文件路径
//     例如: "/path/to/iplist.txt", "./config/whitelist.txt"
//   - ipList: 要保存的IP/CIDR列表
//     例如: []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
//   - header: 添加到文件顶部的标题/描述信息
//     例如: "IP Blacklist - Blocked IPs", "Trusted IP Whitelist"
//   - overwrite: 是否覆盖已存在的文件
//     true: 如果文件已存在，会被覆盖
//     false: 如果文件已存在，返回ErrFileExists错误
//
// 返回:
//   - error: 可能的错误:
//   - ErrFileExists: 文件已存在且overwrite=false
//   - ErrFilePermission: 无权限写入文件
//   - 其他系统错误: 如路径不存在、I/O错误等
//
// 生成的文件格式:
//   - 第一行是提供的header（如有）
//   - 第二行是生成时间
//   - 之后每行一个IP/CIDR
//
// 示例:
//
//	// 保存IP黑名单到文件
//	ips := []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
//	err := config.SaveIPACLWithHeader(
//	    "./my_blacklist.txt",            // 保存路径
//	    ips,                             // IP列表
//	    "IP Blacklist - Generated List", // 文件头
//	    true,                           // 允许覆盖
//	)
//	if err != nil {
//	    if errors.Is(err, config.ErrFileExists) {
//	        log.Println("文件已存在且不允许覆盖")
//	    } else {
//	        log.Printf("保存IP列表失败: %v", err)
//	    }
//	    return
//	}
//	fmt.Println("IP列表已成功保存")
func SaveIPACLWithHeader(filePath string, ipList []string, header string, overwrite bool) error {
	// 检查文件是否已存在
	if _, err := os.Stat(filePath); err == nil && !overwrite {
		return ErrFileExists
	} else if err != nil && !os.IsNotExist(err) {
		// 其他非"不存在"的错误
		return err
	}

	// 创建或打开文件
	file, err := os.Create(filePath)
	if err != nil {
		if os.IsPermission(err) {
			return ErrFilePermission
		}
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// 写入头部信息
	if header != "" {
		if _, err := writer.WriteString("# " + header + "\n"); err != nil {
			return err
		}
	}

	// 写入生成时间
	generatedTime := time.Now().Format("2006-01-02 15:04:05")
	if _, err := writer.WriteString("# Generated: " + generatedTime + "\n"); err != nil {
		return err
	}

	// 写入IP列表
	for _, ip := range ipList {
		if _, err := writer.WriteString(ip + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

// SaveIPACL 将IP/CIDR列表保存到文件，使用默认头部
//
// 这是SaveIPACLWithHeader的简化版本，使用默认的头部信息
//
// 参数:
//   - filePath: 要保存的文件路径
//   - ipList: 要保存的IP/CIDR列表
//   - overwrite: 是否覆盖已存在的文件
//
// 返回:
//   - error: 可能的错误
//
// 示例:
//
//	ips := []string{"192.168.1.1", "10.0.0.0/8"}
//	err := config.SaveIPACL("./list.txt", ips, true)
func SaveIPACL(filePath string, ipList []string, overwrite bool) error {
	return SaveIPACLWithHeader(filePath, ipList, "IP Access Control List", overwrite)
}
