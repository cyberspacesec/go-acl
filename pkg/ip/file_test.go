package ip

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cyberspacesec/go-acl/pkg/config"
	"github.com/cyberspacesec/go-acl/pkg/types"
)

// 测试数据和辅助函数
var (
	testDir       = "testdata"
	blacklistFile = "blacklist.txt"
	whitelistFile = "whitelist.txt"
	addIPsFile    = "additional_ips.txt"
	savedFile     = "saved_ips.txt"

	blacklistContent = `# 测试黑名单
192.168.1.1
10.0.0.0/8 # CIDR
`

	whitelistContent = `# 测试白名单
8.8.8.8
2001:db8::/32 # IPv6
`

	additionalIPsContent = `# 额外的IP
172.16.0.1
172.17.0.0/16
`
)

// setUp 创建测试环境
func setUp(t *testing.T) {
	// 创建测试目录
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("无法创建测试目录: %v", err)
	}

	// 创建测试文件
	writeTestFile(t, filepath.Join(testDir, blacklistFile), blacklistContent)
	writeTestFile(t, filepath.Join(testDir, whitelistFile), whitelistContent)
	writeTestFile(t, filepath.Join(testDir, addIPsFile), additionalIPsContent)
}

// tearDown 清理测试环境
func tearDown(t *testing.T) {
	if err := os.RemoveAll(testDir); err != nil {
		t.Logf("警告: 无法清理测试目录: %v", err)
	}
}

// writeTestFile 写入测试文件
func writeTestFile(t *testing.T, path, content string) {
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("无法创建测试文件 %s: %v", path, err)
	}
}

// TestNewIPAclFromFile 测试从文件创建IP访问控制列表
func TestNewIPAclFromFile(t *testing.T) {
	setUp(t)
	defer tearDown(t)

	tests := []struct {
		name           string
		filePath       string
		listType       types.ListType
		wantErr        bool
		errType        error
		expectedIPsLen int
	}{
		{
			name:           "从黑名单文件创建",
			filePath:       filepath.Join(testDir, blacklistFile),
			listType:       types.Blacklist,
			wantErr:        false,
			expectedIPsLen: 2,
		},
		{
			name:           "从白名单文件创建",
			filePath:       filepath.Join(testDir, whitelistFile),
			listType:       types.Whitelist,
			wantErr:        false,
			expectedIPsLen: 2,
		},
		{
			name:     "从不存在的文件创建",
			filePath: filepath.Join(testDir, "nonexistent.txt"),
			listType: types.Blacklist,
			wantErr:  true,
			errType:  config.ErrFileNotFound,
		},
		{
			name:     "从空文件创建",
			filePath: filepath.Join(testDir, "empty.txt"),
			listType: types.Blacklist,
			wantErr:  true,
			errType:  config.ErrEmptyFile,
		},
	}

	// 创建一个空文件用于测试
	writeTestFile(t, filepath.Join(testDir, "empty.txt"), "")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := NewIPAclFromFile(tt.filePath, tt.listType)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIPAclFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				// 如果期望错误，检查错误类型
				if tt.errType != nil && err != tt.errType {
					t.Errorf("NewIPAclFromFile() error = %v, want error type %v", err, tt.errType)
				}
				return
			}

			// 检查ACL
			if acl == nil {
				t.Fatal("Expected non-nil ACL")
			}

			// 检查列表类型
			if acl.GetListType() != tt.listType {
				t.Errorf("ACL list type = %v, want %v", acl.GetListType(), tt.listType)
			}

			// 检查IP数量
			ipRanges := acl.GetIPRanges()
			if len(ipRanges) != tt.expectedIPsLen {
				t.Errorf("Expected %d IPs, got %d: %v", tt.expectedIPsLen, len(ipRanges), ipRanges)
			}
		})
	}
}

// TestIPAcl_SaveToFile 测试保存IP访问控制列表到文件
func TestIPAcl_SaveToFile(t *testing.T) {
	setUp(t)
	defer tearDown(t)

	tests := []struct {
		name         string
		ipRanges     []string
		listType     types.ListType
		filePath     string
		overwrite    bool
		fileExists   bool // 文件是否预先存在
		wantErr      bool
		errType      error
		expectedFile bool // 是否期望文件存在
	}{
		{
			name:         "保存黑名单到新文件",
			ipRanges:     []string{"192.168.1.1", "10.0.0.0/8"},
			listType:     types.Blacklist,
			filePath:     filepath.Join(testDir, savedFile),
			overwrite:    false,
			fileExists:   false,
			wantErr:      false,
			expectedFile: true,
		},
		{
			name:         "保存白名单到新文件",
			ipRanges:     []string{"8.8.8.8", "2001:db8::/32"},
			listType:     types.Whitelist,
			filePath:     filepath.Join(testDir, "whitelist_saved.txt"),
			overwrite:    false,
			fileExists:   false,
			wantErr:      false,
			expectedFile: true,
		},
		{
			name:         "不覆盖已存在的文件",
			ipRanges:     []string{"192.168.1.1"},
			listType:     types.Blacklist,
			filePath:     filepath.Join(testDir, blacklistFile), // 已存在的文件
			overwrite:    false,
			fileExists:   true,
			wantErr:      true,
			errType:      config.ErrFileExists,
			expectedFile: true, // 文件应保持不变
		},
		{
			name:         "覆盖已存在的文件",
			ipRanges:     []string{"192.168.1.100", "10.10.10.0/24"},
			listType:     types.Blacklist,
			filePath:     filepath.Join(testDir, blacklistFile), // 已存在的文件
			overwrite:    true,
			fileExists:   true,
			wantErr:      false,
			expectedFile: true, // 文件应被覆盖
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建ACL
			acl, err := NewIPAcl(tt.ipRanges, tt.listType)
			if err != nil {
				t.Fatalf("无法创建测试ACL: %v", err)
			}

			// 保存到文件
			err = acl.SaveToFile(tt.filePath, tt.overwrite)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveToFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errType != nil {
				if err != tt.errType {
					t.Errorf("SaveToFile() error = %v, want error type %v", err, tt.errType)
				}
				return
			}

			// 检查文件是否存在
			fileInfo, err := os.Stat(tt.filePath)
			fileExists := err == nil && fileInfo.Size() > 0
			if fileExists != tt.expectedFile {
				t.Errorf("File exists = %v, want %v", fileExists, tt.expectedFile)
			}

			// 如果文件应该存在且没有错误，验证内容
			if !tt.wantErr && tt.expectedFile {
				// 读取保存的文件
				ips, err := config.ReadIPList(tt.filePath)
				if err != nil {
					t.Errorf("Failed to read saved file: %v", err)
					return
				}

				// 验证保存的IP列表
				if !reflect.DeepEqual(ips, tt.ipRanges) {
					t.Errorf("Saved IPs = %v, want %v", ips, tt.ipRanges)
				}
			}
		})
	}
}

// TestIPAcl_SaveToFileWithOverwrite 测试使用默认覆盖选项保存
func TestIPAcl_SaveToFileWithOverwrite(t *testing.T) {
	setUp(t)
	defer tearDown(t)

	// 创建一个已存在的文件
	existingFile := filepath.Join(testDir, "existing.txt")
	writeTestFile(t, existingFile, "原始内容")

	// 创建测试ACL
	acl, _ := NewIPAcl([]string{"192.168.1.1", "10.0.0.0/8"}, types.Blacklist)

	// 使用SaveToFileWithOverwrite方法保存
	err := acl.SaveToFileWithOverwrite(existingFile)
	if err != nil {
		t.Errorf("SaveToFileWithOverwrite() error = %v", err)
		return
	}

	// 检查文件是否被覆盖
	ips, err := config.ReadIPList(existingFile)
	if err != nil {
		t.Errorf("Failed to read saved file: %v", err)
		return
	}

	expected := []string{"192.168.1.1", "10.0.0.0/8"}
	if !reflect.DeepEqual(ips, expected) {
		t.Errorf("Saved IPs = %v, want %v", ips, expected)
	}
}

// TestIPAcl_AddFromFile 测试从文件添加IP
func TestIPAcl_AddFromFile(t *testing.T) {
	setUp(t)
	defer tearDown(t)

	tests := []struct {
		name           string
		initialIPs     []string
		listType       types.ListType
		filePath       string
		wantErr        bool
		errType        error
		expectedIPsLen int // 添加后期望的IP数量
	}{
		{
			name:           "添加有效IP文件",
			initialIPs:     []string{"8.8.8.8"},
			listType:       types.Blacklist,
			filePath:       filepath.Join(testDir, addIPsFile),
			wantErr:        false,
			expectedIPsLen: 3, // 初始1个 + 文件中2个
		},
		{
			name:           "添加不存在的文件",
			initialIPs:     []string{"8.8.8.8"},
			listType:       types.Blacklist,
			filePath:       filepath.Join(testDir, "nonexistent.txt"),
			wantErr:        true,
			errType:        config.ErrFileNotFound,
			expectedIPsLen: 1, // 保持不变
		},
		{
			name:           "添加空文件",
			initialIPs:     []string{"8.8.8.8"},
			listType:       types.Blacklist,
			filePath:       filepath.Join(testDir, "empty.txt"),
			wantErr:        true,
			errType:        config.ErrEmptyFile,
			expectedIPsLen: 1, // 保持不变
		},
	}

	// 创建一个空文件用于测试
	writeTestFile(t, filepath.Join(testDir, "empty.txt"), "")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试ACL
			acl, _ := NewIPAcl(tt.initialIPs, tt.listType)
			initialCount := len(acl.GetIPRanges())

			// 从文件添加IP
			err := acl.AddFromFile(tt.filePath)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("AddFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errType != nil {
				if err != tt.errType {
					t.Errorf("AddFromFile() error = %v, want error type %v", err, tt.errType)
				}
				return
			}

			// 检查IP数量
			ipRanges := acl.GetIPRanges()
			if len(ipRanges) != tt.expectedIPsLen {
				t.Errorf("After AddFromFile(), expected %d IPs, got %d: %v",
					tt.expectedIPsLen, len(ipRanges), ipRanges)
			}

			// 如果成功添加，检查是否包含文件中的IP
			if !tt.wantErr && initialCount < len(ipRanges) {
				fileIPs, _ := config.ReadIPList(tt.filePath)
				for _, ip := range fileIPs {
					found := false
					for _, existingIP := range ipRanges {
						if ip == existingIP {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("IP %s from file not found in result %v", ip, ipRanges)
					}
				}
			}
		})
	}
}

// TestEndToEndFileOperations 测试完整的文件操作流程
func TestEndToEndFileOperations(t *testing.T) {
	setUp(t)
	defer tearDown(t)

	// 1. 从文件创建ACL
	sourcePath := filepath.Join(testDir, blacklistFile)
	acl, err := NewIPAclFromFile(sourcePath, types.Blacklist)
	if err != nil {
		t.Fatalf("无法从文件创建ACL: %v", err)
	}

	// 验证初始IP数量
	initialIPs := acl.GetIPRanges()
	if len(initialIPs) != 2 {
		t.Errorf("Expected 2 initial IPs, got %d: %v", len(initialIPs), initialIPs)
	}

	// 2. 添加更多IP
	additionalPath := filepath.Join(testDir, addIPsFile)
	if err := acl.AddFromFile(additionalPath); err != nil {
		t.Fatalf("添加IP失败: %v", err)
	}

	// 验证添加后的IP数量
	afterAddIPs := acl.GetIPRanges()
	if len(afterAddIPs) != 4 {
		t.Errorf("Expected 4 IPs after adding, got %d: %v", len(afterAddIPs), afterAddIPs)
	}

	// 3. 保存到新文件
	savedPath := filepath.Join(testDir, "combined.txt")
	if err := acl.SaveToFile(savedPath, false); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	// 4. 从保存的文件重新加载
	reloadedAcl, err := NewIPAclFromFile(savedPath, types.Blacklist)
	if err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}

	// 验证重新加载的IP数量和内容
	reloadedIPs := reloadedAcl.GetIPRanges()
	if !reflect.DeepEqual(reloadedIPs, afterAddIPs) {
		t.Errorf("Reloaded IPs = %v, want %v", reloadedIPs, afterAddIPs)
	}
}
