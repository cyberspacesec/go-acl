package config

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"time"
)

var (
	// ErrFileNotFound 表示配置文件未找到
	ErrFileNotFound = errors.New("configuration file not found")
	// ErrFilePermission 表示无法访问配置文件
	ErrFilePermission = errors.New("permission denied when accessing configuration file")
	// ErrEmptyFile 表示配置文件为空
	ErrEmptyFile = errors.New("configuration file is empty")
	// ErrFileExists 表示文件已经存在且不允许覆盖
	ErrFileExists = errors.New("file already exists and overwrite is not allowed")
)

// ReadIPList 从文件中读取IP列表，每行一个IP或CIDR
// 支持"#"开头的注释行
//
// 参数:
//   - filePath: 要读取的文件路径
//     例如: "/path/to/blacklist.txt", "./whitelist.txt"
//
// 返回:
//   - []string: 读取到的IP地址列表，例如 ["192.168.1.1", "10.0.0.0/8", "2001:db8::/32"]
//   - error: 错误信息，可能的错误: ErrFileNotFound, ErrFilePermission, ErrEmptyFile
//
// 示例文件内容:
//
//	# 这是注释行，会被忽略
//	192.168.1.100  # 行内注释也支持
//	10.0.0.0/8
//
//	# 空行会被忽略
//	2001:db8::/32
func ReadIPList(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrFileNotFound
		}
		if os.IsPermission(err) {
			return nil, ErrFilePermission
		}
		return nil, err
	}
	defer file.Close()

	var ipList []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过空行和注释
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 处理行内注释
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			ipList = append(ipList, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(ipList) == 0 {
		return nil, ErrEmptyFile
	}

	return ipList, nil
}

// SaveIPList 将IP列表保存到文件，每行一个IP或CIDR
// 如果文件已存在，overwrite参数决定是否覆盖文件
//
// 参数:
//   - filePath: 要保存的文件路径
//     例如: "/path/to/blacklist.txt", "./whitelist.txt"
//   - ipList: 要保存的IP地址列表
//     例如: ["192.168.1.1", "10.0.0.0/8", "2001:db8::/32"]
//   - header: 文件顶部的注释信息，将自动添加"#"前缀
//     例如: "IP Blacklist - IPs in this list will be denied access"
//   - overwrite: 是否覆盖已存在的文件
//     true: 如果文件已存在，将覆盖
//     false: 如果文件已存在，将返回ErrFileExists错误
//
// 返回:
//   - error: 错误信息，可能的错误: ErrFileExists, ErrFilePermission
//
// 生成的文件格式示例:
//
//	# IP Blacklist - IPs in this list will be denied access
//	# Generated at: 2023-10-15 14:30:25
//	#-------------------------------------
//
//	192.168.1.100
//	10.0.0.0/8
//	2001:db8::/32
func SaveIPList(filePath string, ipList []string, header string, overwrite bool) error {
	// 检查文件是否存在
	if !overwrite {
		if _, err := os.Stat(filePath); err == nil {
			// 文件存在且不允许覆盖
			return ErrFileExists
		} else if !os.IsNotExist(err) {
			// 其他错误
			return err
		}
	}

	// 创建或覆盖文件
	file, err := os.Create(filePath)
	if err != nil {
		if os.IsPermission(err) {
			return ErrFilePermission
		}
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// 写入文件头部注释
	if header != "" {
		_, err = writer.WriteString("# " + header + "\n")
		if err != nil {
			return err
		}
	}

	// 写入时间标记
	_, err = writer.WriteString("# Generated at: " +
		(time.Now().Format("2006-01-02 15:04:05")) + "\n")
	if err != nil {
		return err
	}

	// 写入分隔线
	_, err = writer.WriteString("#-------------------------------------\n\n")
	if err != nil {
		return err
	}

	// 写入每一个IP或CIDR
	for _, ip := range ipList {
		_, err = writer.WriteString(ip + "\n")
		if err != nil {
			return err
		}
	}

	return writer.Flush()
}
