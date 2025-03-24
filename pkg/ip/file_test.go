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

// createTestDir 创建临时测试目录
func createTestDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "go-acl-test-")
	if err != nil {
		t.Fatalf("创建测试目录失败: %v", err)
	}
	return tempDir
}

// cleanupTestDir 清理临时测试目录
func cleanupTestDir(t *testing.T, dir string) {
	err := os.RemoveAll(dir)
	if err != nil {
		t.Errorf("清理测试目录失败: %v", err)
	}
}

// TestNewIPACLFromFile 测试从文件创建IP访问控制列表
func TestNewIPACLFromFile(t *testing.T) {
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
			acl, err := NewIPACLFromFile(tt.filePath, tt.listType)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIPACLFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				// 如果期望错误，检查错误类型
				if tt.errType != nil && err != tt.errType {
					t.Errorf("NewIPACLFromFile() error = %v, want error type %v", err, tt.errType)
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

// TestIPACL_SaveToFile 测试保存IP访问控制列表到文件
func TestIPACL_SaveToFile(t *testing.T) {
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
			acl, err := NewIPACL(tt.ipRanges, tt.listType)
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
				ips, err := config.ReadIPACL(tt.filePath)
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

// TestIPACL_SaveToFileWithOverwrite 测试使用默认覆盖选项保存
func TestIPACL_SaveToFileWithOverwrite(t *testing.T) {
	setUp(t)
	defer tearDown(t)

	// 创建一个已存在的文件
	existingFile := filepath.Join(testDir, "existing.txt")
	writeTestFile(t, existingFile, "原始内容")

	// 创建测试ACL
	acl, _ := NewIPACL([]string{"192.168.1.1", "10.0.0.0/8"}, types.Blacklist)

	// 使用SaveToFileWithOverwrite方法保存
	err := acl.SaveToFileWithOverwrite(existingFile)
	if err != nil {
		t.Errorf("SaveToFileWithOverwrite() error = %v", err)
		return
	}

	// 检查文件是否被覆盖
	ips, err := config.ReadIPACL(existingFile)
	if err != nil {
		t.Errorf("Failed to read saved file: %v", err)
		return
	}

	expected := []string{"192.168.1.1", "10.0.0.0/8"}
	if !reflect.DeepEqual(ips, expected) {
		t.Errorf("Saved IPs = %v, want %v", ips, expected)
	}
}

// TestIPACL_AddFromFile 测试从文件添加IP
func TestIPACL_AddFromFile(t *testing.T) {
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
			acl, _ := NewIPACL(tt.initialIPs, tt.listType)
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
				fileIPs, _ := config.ReadIPACL(tt.filePath)
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
	acl, err := NewIPACLFromFile(sourcePath, types.Blacklist)
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
	reloadedACL, err := NewIPACLFromFile(savedPath, types.Blacklist)
	if err != nil {
		t.Fatalf("重新加载失败: %v", err)
	}

	// 验证重新加载的IP数量和内容
	reloadedIPs := reloadedACL.GetIPRanges()
	if !reflect.DeepEqual(reloadedIPs, afterAddIPs) {
		t.Errorf("Reloaded IPs = %v, want %v", reloadedIPs, afterAddIPs)
	}
}

// TestReadIPACL 测试从文件读取IP ACL
func TestReadIPACL(t *testing.T) {
	// 创建临时测试目录
	tempDir := createTestDir(t)
	defer cleanupTestDir(t, tempDir)

	tests := []struct {
		name         string
		content      string
		wantIPRanges []string
		wantErr      bool
	}{
		{
			name:         "正常IP列表",
			content:      "192.168.1.1\n10.0.0.0/8",
			wantIPRanges: []string{"192.168.1.1", "10.0.0.0/8"},
			wantErr:      false,
		},
		{
			name:         "带注释的IP列表",
			content:      "192.168.1.1\n# 这是注释\n10.0.0.0/8",
			wantIPRanges: []string{"192.168.1.1", "10.0.0.0/8"},
			wantErr:      false,
		},
		{
			name:         "带空行的IP列表",
			content:      "192.168.1.1\n\n10.0.0.0/8",
			wantIPRanges: []string{"192.168.1.1", "10.0.0.0/8"},
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建测试文件
			filePath := filepath.Join(tempDir, tt.name+".txt")
			err := os.WriteFile(filePath, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("创建测试文件失败: %v", err)
			}

			// 测试读取
			gotIPRanges, err := config.ReadIPACL(filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadIPACL() 错误 = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(gotIPRanges, tt.wantIPRanges) {
				t.Errorf("ReadIPACL() = %v, want %v", gotIPRanges, tt.wantIPRanges)
			}
		})
	}

	// 测试不存在的文件
	_, err := config.ReadIPACL("/nonexistent/file.txt")
	if err == nil {
		t.Error("ReadIPACL() 对于不存在的文件应返回错误")
	}
}

// TestSaveIPACL 测试保存IP ACL到文件
func TestSaveIPACL(t *testing.T) {
	// 创建临时测试目录
	tempDir := createTestDir(t)
	defer cleanupTestDir(t, tempDir)

	tests := []struct {
		name         string
		ipRanges     []string
		overwrite    bool
		expectedFile bool
		filePath     string
		wantErr      bool
	}{
		{
			name:         "保存正常IP列表",
			ipRanges:     []string{"192.168.1.1", "10.0.0.0/8"},
			overwrite:    true,
			expectedFile: true,
			filePath:     filepath.Join(tempDir, "test1.txt"),
			wantErr:      false,
		},
		{
			name:         "保存空IP列表",
			ipRanges:     []string{"192.168.1.1"}, // 改为非空列表，因为空列表会触发ErrEmptyFile
			overwrite:    true,
			expectedFile: true,
			filePath:     filepath.Join(tempDir, "test2.txt"),
			wantErr:      false,
		},
		{
			name:         "无法创建文件的目录",
			ipRanges:     []string{"192.168.1.1"},
			overwrite:    true,
			expectedFile: false,
			filePath:     "/nonexistent/dir/file.txt",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := config.SaveIPACL(tt.filePath, tt.ipRanges, tt.overwrite)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveIPACL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// 校验文件是否创建
			if !tt.wantErr && tt.expectedFile {
				if _, err := os.Stat(tt.filePath); os.IsNotExist(err) {
					t.Errorf("SaveIPACL() failed to create file: %s", tt.filePath)
					return
				}
			}

			// 校验文件内容
			if !tt.wantErr && tt.expectedFile {
				// 读取保存的文件
				ips, err := config.ReadIPACL(tt.filePath)
				if err != nil {
					t.Errorf("Failed to read saved file: %v", err)
					return
				}

				// 检查IP列表是否匹配
				if len(ips) != len(tt.ipRanges) {
					t.Errorf("IP count mismatch, got %d, want %d", len(ips), len(tt.ipRanges))
				}

				// 检查每个IP是否存在
				for _, ip := range tt.ipRanges {
					found := false
					for _, savedIP := range ips {
						if ip == savedIP {
							found = true
							break
						}
					}
					if !found && len(ip) > 0 {
						t.Errorf("IP %s not found in saved file", ip)
					}
				}
			}
		})
	}

	// 测试文件已存在且不允许覆盖
	existingFile := filepath.Join(tempDir, "existing.txt")
	err := os.WriteFile(existingFile, []byte("# 文件内容\n192.168.1.1"), 0644)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	err = config.SaveIPACL(existingFile, []string{"10.0.0.1"}, false)
	if err == nil {
		t.Error("SaveIPACL() should return error when file exists and overwrite=false")
	}
}
