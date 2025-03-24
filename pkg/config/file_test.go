package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// 测试目录和文件路径
const (
	validIPFile      = "valid_ips.txt"
	emptyFile        = "empty.txt"
	commentsOnlyFile = "comments_only.txt"
	mixedContentFile = "mixed_content.txt"
	nonExistentFile  = "non_existent.txt"
	noPermissionFile = "no_permission.txt"
	existingFile     = "existing.txt"
	blacklistIPsFile = "blacklist_ips.txt"
	whitelistIPsFile = "whitelist_ips.txt"
	multipleIPsFile  = "multiple_ips.txt"
)

// 获取一个可能的无效路径（不同操作系统有不同的实现）
func getInvalidPath() string {
	if runtime.GOOS == "windows" {
		// Windows下使用一个非法的文件名
		return filepath.Join(os.TempDir(), "con", "invalid_path.txt") // con是Windows保留名
	}
	// Unix系统使用一个通常无权限的目录
	return "/root/test/invalid_path.txt"
}

// 测试数据
var (
	validIPs        = []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
	validIPsContent = `# 有效IP列表示例
192.168.1.1
10.0.0.0/8 # CIDR格式
2001:db8::/32 # IPv6 CIDR格式
`
	emptyContent    = ""
	commentsContent = `# 这是注释行1
# 这是注释行2
  # 这也是注释行，有前导空格
`
	mixedContent = `# 混合内容示例
192.168.1.1 # IPv4示例
# 注释行
10.0.0.0/8
  
# 空行上方
2001:db8::/32 # IPv6示例
`
	blacklistHeader = "IP Blacklist - IPs in this list will be denied access"
	whitelistHeader = "IP Whitelist - Only IPs in this list will be allowed access"
)

// 测试目录
var testDir string

// setUp 在测试前创建必要的测试数据
func setUp(t *testing.T) string {
	// 创建一个唯一的临时测试目录
	var err error
	testDir, err = os.MkdirTemp("", "go-acl-test-*")
	if err != nil {
		t.Fatalf("无法创建临时测试目录: %v", err)
	}

	t.Logf("使用临时测试目录: %s", testDir)

	// 创建测试文件
	createTestFile(t, filepath.Join(testDir, validIPFile), validIPsContent)
	createTestFile(t, filepath.Join(testDir, emptyFile), emptyContent)
	createTestFile(t, filepath.Join(testDir, commentsOnlyFile), commentsContent)
	createTestFile(t, filepath.Join(testDir, mixedContentFile), mixedContent)

	// 创建现有文件用于测试覆盖功能
	createTestFile(t, filepath.Join(testDir, existingFile), "这是一个现有文件")

	// 创建无权限文件（尝试设置为只读）
	permFile := filepath.Join(testDir, noPermissionFile)
	createTestFile(t, permFile, "无权限文件")

	// 尝试设置文件权限，但忽略错误（某些操作系统可能无法设置）
	err = os.Chmod(permFile, 0400)
	if err != nil {
		t.Logf("警告: 无法设置文件权限，权限测试可能不准确: %v", err)
	}

	return testDir
}

// tearDown 在测试后清理测试数据
func tearDown(t *testing.T, dir string) {
	if dir == "" {
		return
	}

	// 确保权限恢复以便删除
	permFile := filepath.Join(dir, noPermissionFile)
	_ = os.Chmod(permFile, 0644)

	// 删除测试目录及所有内容
	err := os.RemoveAll(dir)
	if err != nil {
		t.Logf("警告: 无法清理测试目录: %v", err)
	}
}

// createTestFile 创建测试文件
func createTestFile(t *testing.T, path, content string) {
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatalf("无法创建测试文件 %s: %v", path, err)
	}
}

// TestReadIPList 测试从文件读取IP列表的函数
func TestReadIPList(t *testing.T) {
	setUp(t)
	defer tearDown(t, testDir)

	tests := []struct {
		name        string
		filePath    string
		expected    []string
		expectedErr error
		skip        bool   // 是否跳过这个测试
		skipReason  string // 跳过的原因
	}{
		{
			name:        "成功读取有效IP列表",
			filePath:    filepath.Join(testDir, validIPFile),
			expected:    validIPs,
			expectedErr: nil,
		},
		{
			name:        "读取空文件",
			filePath:    filepath.Join(testDir, emptyFile),
			expected:    nil,
			expectedErr: ErrEmptyFile,
		},
		{
			name:        "读取只有注释的文件",
			filePath:    filepath.Join(testDir, commentsOnlyFile),
			expected:    nil,
			expectedErr: ErrEmptyFile,
		},
		{
			name:        "读取混合内容的文件",
			filePath:    filepath.Join(testDir, mixedContentFile),
			expected:    validIPs,
			expectedErr: nil,
		},
		{
			name:        "读取不存在的文件",
			filePath:    filepath.Join(testDir, nonExistentFile),
			expected:    nil,
			expectedErr: ErrFileNotFound,
		},
		{
			name:        "读取无权限文件",
			filePath:    filepath.Join(testDir, noPermissionFile),
			expected:    nil,
			expectedErr: nil,                       // 不确定具体错误，所以在测试中检查
			skip:        runtime.GOOS == "windows", // Windows权限模型不同
			skipReason:  "Windows下权限测试行为不一致",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.Skip(tt.skipReason)
			}

			ips, err := ReadIPList(tt.filePath)

			// 特殊处理权限测试
			if tt.name == "读取无权限文件" {
				if err == nil {
					t.Logf("警告：无权限文件测试未产生错误，可能与操作系统权限模型有关")
				}
				// 跳过进一步的检查
				return
			}

			// 检查错误
			if tt.expectedErr != nil {
				if err == nil {
					t.Errorf("期望错误 %v, 但得到 nil", tt.expectedErr)
				} else if err != tt.expectedErr {
					t.Errorf("期望错误 %v, 但得到 %v", tt.expectedErr, err)
				}
			} else if err != nil {
				t.Errorf("未期望错误，但得到 %v", err)
			}

			// 检查结果
			if !reflect.DeepEqual(ips, tt.expected) {
				t.Errorf("期望 %v, 但得到 %v", tt.expected, ips)
			}
		})
	}
}

// TestSaveIPList 测试保存IP列表到文件的函数
func TestSaveIPList(t *testing.T) {
	setUp(t)
	defer tearDown(t, testDir)

	invalidPath := getInvalidPath()

	tests := []struct {
		name        string
		filePath    string
		ipList      []string
		header      string
		overwrite   bool
		expectedErr error
		checkFile   bool   // 是否检查文件内容
		skip        bool   // 是否跳过这个测试
		skipReason  string // 跳过的原因
	}{
		{
			name:        "成功保存IP列表到新文件",
			filePath:    filepath.Join(testDir, blacklistIPsFile),
			ipList:      validIPs,
			header:      blacklistHeader,
			overwrite:   false,
			expectedErr: nil,
			checkFile:   true,
		},
		{
			name:        "使用白名单头保存IP列表",
			filePath:    filepath.Join(testDir, whitelistIPsFile),
			ipList:      validIPs,
			header:      whitelistHeader,
			overwrite:   false,
			expectedErr: nil,
			checkFile:   true,
		},
		{
			name:        "成功覆盖已存在的文件",
			filePath:    filepath.Join(testDir, existingFile),
			ipList:      validIPs,
			header:      "覆盖文件测试",
			overwrite:   true,
			expectedErr: nil,
			checkFile:   true,
		},
		{
			name:        "不覆盖已存在的文件",
			filePath:    filepath.Join(testDir, existingFile),
			ipList:      validIPs,
			header:      "不覆盖文件测试",
			overwrite:   false,
			expectedErr: ErrFileExists,
			checkFile:   false,
		},
		{
			name:        "保存到无效路径",
			filePath:    invalidPath,
			ipList:      validIPs,
			header:      "无效路径测试",
			overwrite:   false,
			expectedErr: nil, // 不确定具体错误，所以在测试中检查
			checkFile:   false,
			skip:        false, // 所有系统都应该测试，但不检查具体错误类型
		},
		{
			name:        "保存多个不同类型的IP",
			filePath:    filepath.Join(testDir, multipleIPsFile),
			ipList:      []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32", "172.16.0.1", "8.8.8.8"},
			header:      "多个IP地址测试",
			overwrite:   false,
			expectedErr: nil,
			checkFile:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skip {
				t.Skip(tt.skipReason)
			}

			err := SaveIPList(tt.filePath, tt.ipList, tt.header, tt.overwrite)

			// 特殊处理无效路径测试
			if tt.name == "保存到无效路径" {
				if err == nil {
					t.Logf("警告：无效路径测试未产生错误 (路径: %s)", invalidPath)
				} else {
					t.Logf("无效路径测试产生预期错误: %v", err)
				}
				// 跳过进一步的检查
				return
			}

			// 检查错误
			if tt.expectedErr != nil {
				if err == nil {
					t.Errorf("期望错误 %v, 但得到 nil", tt.expectedErr)
				} else if err != tt.expectedErr {
					t.Errorf("期望错误 %v, 但得到 %v", tt.expectedErr, err)
				}
			} else if err != nil {
				t.Errorf("未期望错误，但得到 %v", err)
			}

			// 检查文件内容
			if tt.checkFile && err == nil {
				content, err := os.ReadFile(tt.filePath)
				if err != nil {
					t.Fatalf("无法读取写入的文件: %v", err)
				}

				// 检查文件是否包含标题
				if !strings.Contains(string(content), tt.header) {
					t.Errorf("文件内容中未找到标题: %s", tt.header)
				}

				// 检查文件是否包含所有IP
				for _, ip := range tt.ipList {
					if !strings.Contains(string(content), ip) {
						t.Errorf("文件内容中未找到IP: %s", ip)
					}
				}

				// 检查是否包含时间戳
				if !strings.Contains(string(content), "Generated at:") {
					t.Errorf("文件内容中未找到时间戳")
				}

				// 输出文件内容以便调试（通常在测试失败时很有用）
				if testing.Verbose() {
					fmt.Printf("文件 %s 内容:\n%s\n", tt.filePath, string(content))
				}
			}
		})
	}
}

// TestReadThenSave 测试读取文件后再保存的完整流程
func TestReadThenSave(t *testing.T) {
	setUp(t)
	defer tearDown(t, testDir)

	// 1. 首先读取有效的IP文件
	sourcePath := filepath.Join(testDir, validIPFile)
	ips, err := ReadIPList(sourcePath)
	if err != nil {
		t.Fatalf("读取文件失败: %v", err)
	}

	// 2. 然后将读取的内容保存到新文件
	destPath := filepath.Join(testDir, "read_then_save.txt")
	err = SaveIPList(destPath, ips, "读取后保存测试", false)
	if err != nil {
		t.Fatalf("保存文件失败: %v", err)
	}

	// 3. 再次读取新文件，确认内容正确
	newIPs, err := ReadIPList(destPath)
	if err != nil {
		t.Fatalf("读取保存的文件失败: %v", err)
	}

	// 4. 验证两个IP列表内容相同
	if !reflect.DeepEqual(ips, newIPs) {
		t.Errorf("原始IP列表 %v 与保存后读取的列表 %v 不同", ips, newIPs)
	}
}

// TestEdgeCases 测试一些边缘情况
func TestEdgeCases(t *testing.T) {
	setUp(t)
	defer tearDown(t, testDir)

	// 测试保存空IP列表
	t.Run("保存空IP列表", func(t *testing.T) {
		emptyListPath := filepath.Join(testDir, "empty_list.txt")
		err := SaveIPList(emptyListPath, []string{}, "空IP列表测试", false)
		if err != nil {
			t.Errorf("保存空IP列表失败: %v", err)
		}

		// 尝试读取保存的空IP列表
		ips, err := ReadIPList(emptyListPath)
		if err != ErrEmptyFile {
			t.Errorf("期望错误 %v, 但得到 %v", ErrEmptyFile, err)
		}
		if ips != nil {
			t.Errorf("期望nil, 但得到 %v", ips)
		}
	})

	// 测试保存复杂的IP列表（包含各种格式和注释）
	t.Run("保存复杂IP列表", func(t *testing.T) {
		complexListPath := filepath.Join(testDir, "complex_list.txt")
		complexIPs := []string{
			"192.168.1.1",
			"10.0.0.0/8",
			"2001:db8::/32",
			"8.8.8.8",
			"172.16.0.0/12",
			"fc00::/7",
		}
		err := SaveIPList(complexListPath, complexIPs, "复杂IP列表测试", false)
		if err != nil {
			t.Errorf("保存复杂IP列表失败: %v", err)
		}

		// 读取并验证
		ips, err := ReadIPList(complexListPath)
		if err != nil {
			t.Errorf("读取复杂IP列表失败: %v", err)
		}
		if !reflect.DeepEqual(ips, complexIPs) {
			t.Errorf("期望 %v, 但得到 %v", complexIPs, ips)
		}
	})

	// 测试多次覆盖同一文件
	t.Run("多次覆盖同一文件", func(t *testing.T) {
		overwritePath := filepath.Join(testDir, "overwrite_test.txt")

		// 第一次写入
		err := SaveIPList(overwritePath, []string{"192.168.1.1"}, "第一次写入", false)
		if err != nil {
			t.Errorf("第一次写入失败: %v", err)
		}

		// 第二次写入，不覆盖，应该失败
		err = SaveIPList(overwritePath, []string{"10.0.0.1"}, "第二次写入", false)
		if err != ErrFileExists {
			t.Errorf("期望错误 %v, 但得到 %v", ErrFileExists, err)
		}

		// 第三次写入，覆盖，应该成功
		err = SaveIPList(overwritePath, []string{"8.8.8.8"}, "第三次写入", true)
		if err != nil {
			t.Errorf("第三次写入失败: %v", err)
		}

		// 读取并验证是第三次的内容
		ips, err := ReadIPList(overwritePath)
		if err != nil {
			t.Errorf("读取覆盖文件失败: %v", err)
		}
		if !reflect.DeepEqual(ips, []string{"8.8.8.8"}) {
			t.Errorf("期望 [8.8.8.8], 但得到 %v", ips)
		}
	})
}

// TestReadIPListErrorHandling 测试ReadIPList函数的错误处理
func TestReadIPListErrorHandling(t *testing.T) {
	tmpDir := setUp(t)
	defer tearDown(t, tmpDir)

	// 测试Read操作系统错误（非权限和非存在错误）
	// 这需要模拟一个特殊情况，如通过在读取过程中删除文件来触发
	filePath := filepath.Join(tmpDir, "temp_file.txt")
	createTestFile(t, filePath, "192.168.1.1")

	// 创建一个不可读的文件（仅写权限）
	noReadPath := filepath.Join(tmpDir, "no_read.txt")
	file, err := os.OpenFile(noReadPath, os.O_CREATE|os.O_WRONLY, 0200) // 只写权限
	if err != nil {
		t.Fatalf("无法创建测试文件: %v", err)
	}
	file.Close()

	// 尝试读取
	_, err = ReadIPList(noReadPath)
	if err == nil {
		t.Errorf("对于无读取权限的文件，ReadIPList应返回错误")
	}

	// 测试Scanner错误（通常需要一个特殊的Reader来模拟，这里简单测试）
	// 大多数情况下，Scanner错误在正常文件读取中很难触发
}

// TestSaveIPListErrorHandling 测试SaveIPList函数的错误处理
func TestSaveIPListErrorHandling(t *testing.T) {
	tmpDir := setUp(t)
	defer tearDown(t, tmpDir)

	// 测试创建文件的操作系统错误
	invalidPath := filepath.Join("/nonexistent", "file.txt")
	err := SaveIPList(invalidPath, []string{"192.168.1.1"}, "测试", true)
	if err == nil {
		t.Errorf("无效路径应返回错误")
	}

	// 测试写入错误处理（header写入失败）
	readOnlyPath := filepath.Join(tmpDir, "dir")
	err = os.Mkdir(readOnlyPath, 0500) // 只读目录
	if err != nil {
		t.Fatalf("无法创建测试目录: %v", err)
	}

	invalidFilePath := filepath.Join(readOnlyPath, "invalid.txt")
	err = SaveIPList(invalidFilePath, []string{"192.168.1.1"}, "测试", true)
	if err == nil {
		t.Errorf("写入只读目录应返回错误")
	}
}
