package acl

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cyberspacesec/go-acl/pkg/ip"
	"github.com/cyberspacesec/go-acl/pkg/types"
)

// 辅助函数，创建临时测试目录
func setupTestDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "go-acl-manager-test-*")
	if err != nil {
		t.Fatalf("无法创建测试目录: %v", err)
	}
	return tempDir
}

// 辅助函数，清理测试目录
func cleanupTestDir(t *testing.T, dir string) {
	err := os.RemoveAll(dir)
	if err != nil {
		t.Logf("警告: 清理测试目录失败: %v", err)
	}
}

// 辅助函数，创建测试文件
func createTestFile(t *testing.T, path, content string) {
	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
}

// TestNewManager 测试创建新的管理器
func TestNewManager(t *testing.T) {
	manager := NewManager()
	if manager == nil {
		t.Error("NewManager应返回非nil的Manager实例")
	}
}

// TestSetDomainACL 测试设置域名ACL
func TestSetDomainACL(t *testing.T) {
	manager := NewManager()
	domains := []string{"example.com", "test.org"}

	// 设置域名ACL
	manager.SetDomainACL(domains, types.Blacklist, true)

	// 验证设置成功
	gotDomains := manager.GetDomains()
	if !reflect.DeepEqual(gotDomains, domains) {
		t.Errorf("域名列表不匹配，got %v, want %v", gotDomains, domains)
	}

	listType, err := manager.GetDomainACLType()
	if err != nil {
		t.Errorf("GetDomainACLType() 返回错误: %v", err)
	}
	if listType != types.Blacklist {
		t.Errorf("列表类型不匹配，got %v, want %v", listType, types.Blacklist)
	}
}

// TestSetIPACL 测试设置IP ACL
func TestSetIPACL(t *testing.T) {
	manager := NewManager()
	ipRanges := []string{"192.168.1.1", "10.0.0.0/8"}

	// 设置IP ACL
	err := manager.SetIPACL(ipRanges, types.Blacklist)
	if err != nil {
		t.Errorf("SetIPACL() 返回错误: %v", err)
	}

	// 验证设置成功
	gotIPRanges := manager.GetIPRanges()
	if !reflect.DeepEqual(gotIPRanges, ipRanges) {
		t.Errorf("IP列表不匹配，got %v, want %v", gotIPRanges, ipRanges)
	}

	listType, err := manager.GetIPACLType()
	if err != nil {
		t.Errorf("GetIPACLType() 返回错误: %v", err)
	}
	if listType != types.Blacklist {
		t.Errorf("列表类型不匹配，got %v, want %v", listType, types.Blacklist)
	}

	// 测试无效IP
	err = manager.SetIPACL([]string{"invalid-ip"}, types.Blacklist)
	if err == nil {
		t.Error("SetIPACL() 对于无效IP应返回错误")
	}
}

// TestSetIPACLFromFile 测试从文件设置IP ACL
func TestSetIPACLFromFile(t *testing.T) {
	tempDir := setupTestDir(t)
	defer cleanupTestDir(t, tempDir)

	// 创建测试文件
	testFile := filepath.Join(tempDir, "ips.txt")
	content := "# Test IPs\n192.168.1.1\n10.0.0.0/8\n"
	createTestFile(t, testFile, content)

	manager := NewManager()

	// 从文件设置IP ACL
	err := manager.SetIPACLFromFile(testFile, types.Blacklist)
	if err != nil {
		t.Errorf("SetIPACLFromFile() 返回错误: %v", err)
	}

	// 测试不存在的文件
	err = manager.SetIPACLFromFile("/nonexistent/file.txt", types.Blacklist)
	if err == nil {
		t.Error("SetIPACLFromFile() 对于不存在的文件应返回错误")
	}
}

// TestSaveIPACLToFile 测试保存IP ACL到文件
func TestSaveIPACLToFile(t *testing.T) {
	tempDir := setupTestDir(t)
	defer cleanupTestDir(t, tempDir)

	manager := NewManager()
	ipRanges := []string{"192.168.1.1", "10.0.0.0/8"}

	// 先设置IP ACL
	err := manager.SetIPACL(ipRanges, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}

	// 保存到文件
	testFile := filepath.Join(tempDir, "saved_ips.txt")
	err = manager.SaveIPACLToFile(testFile, true)
	if err != nil {
		t.Errorf("SaveIPACLToFile() 返回错误: %v", err)
	}

	// 检查文件是否存在
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Error("保存的文件不存在")
	}

	// 测试不覆盖
	err = manager.SaveIPACLToFile(testFile, false)
	if err == nil {
		t.Error("SaveIPACLToFile() 对于已存在的文件且overwrite=false应返回错误")
	}

	// 测试无IP ACL的情况
	manager = NewManager()
	err = manager.SaveIPACLToFile(testFile, true)
	if err == nil {
		t.Error("SaveIPACLToFile() 在没有设置IP ACL时应返回错误")
	}
}

// TestSaveIPACLToFileWithOverwrite 测试带覆盖的保存IP ACL
func TestSaveIPACLToFileWithOverwrite(t *testing.T) {
	tempDir := setupTestDir(t)
	defer cleanupTestDir(t, tempDir)

	manager := NewManager()
	ipRanges := []string{"192.168.1.1"}

	// 先设置IP ACL
	err := manager.SetIPACL(ipRanges, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}

	// 保存到文件
	testFile := filepath.Join(tempDir, "overwrite_test.txt")
	createTestFile(t, testFile, "original content")

	// 使用覆盖模式保存
	err = manager.SaveIPACLToFileWithOverwrite(testFile)
	if err != nil {
		t.Errorf("SaveIPACLToFileWithOverwrite() 返回错误: %v", err)
	}

	// 检查文件内容是否被覆盖
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("读取文件失败: %v", err)
	}
	if strings.Contains(string(content), "original content") {
		t.Error("文件内容应该被覆盖")
	}
	if !strings.Contains(string(content), "192.168.1.1") {
		t.Error("文件内容应该包含IP")
	}
}

// TestAddIPFromFile 测试从文件添加IP
func TestAddIPFromFile(t *testing.T) {
	tempDir := setupTestDir(t)
	defer cleanupTestDir(t, tempDir)

	// 创建测试文件
	testFile := filepath.Join(tempDir, "add_ips.txt")
	content := "# Additional IPs\n172.16.0.1\n172.17.0.0/16\n"
	createTestFile(t, testFile, content)

	manager := NewManager()
	initialIPs := []string{"192.168.1.1"}

	// 先设置初始IP ACL
	err := manager.SetIPACL(initialIPs, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}

	// 从文件添加IP
	err = manager.AddIPFromFile(testFile)
	if err != nil {
		t.Errorf("AddIPFromFile() 返回错误: %v", err)
	}

	// 验证IP是否被添加
	gotIPs := manager.GetIPRanges()
	expectedCount := len(initialIPs) + 2 // 文件中有2个IP
	if len(gotIPs) != expectedCount {
		t.Errorf("GetIPRanges() 长度 = %d, 期望 %d", len(gotIPs), expectedCount)
	}

	// 测试无IP ACL的情况
	manager = NewManager()
	err = manager.AddIPFromFile(testFile)
	if err == nil {
		t.Error("AddIPFromFile() 在没有设置IP ACL时应返回错误")
	}

	// 测试不存在的文件
	err = manager.SetIPACL(initialIPs, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}
	err = manager.AddIPFromFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("AddIPFromFile() 对于不存在的文件应返回错误")
	}
}

// TestSetIPACLWithDefaults 测试设置带预定义集合的IP ACL
func TestSetIPACLWithDefaults(t *testing.T) {
	manager := NewManager()
	ipRanges := []string{"192.168.1.1"}
	predefinedSets := []ip.PredefinedSet{ip.PrivateNetworks, ip.LoopbackNetworks}

	// 设置带预定义集合的IP ACL
	err := manager.SetIPACLWithDefaults(ipRanges, types.Blacklist, predefinedSets, false)
	if err != nil {
		t.Errorf("SetIPACLWithDefaults() 返回错误: %v", err)
	}

	// 验证IP范围包含预定义集合
	gotIPs := manager.GetIPRanges()
	if len(gotIPs) <= len(ipRanges) {
		t.Errorf("GetIPRanges() 长度 = %d, 期望大于 %d", len(gotIPs), len(ipRanges))
	}

	// 测试无效IP
	err = manager.SetIPACLWithDefaults([]string{"invalid-ip"}, types.Blacklist, predefinedSets, false)
	if err == nil {
		t.Error("SetIPACLWithDefaults() 对于无效IP应返回错误")
	}

	// 测试无效预定义集合
	err = manager.SetIPACLWithDefaults(ipRanges, types.Blacklist, []ip.PredefinedSet{ip.PredefinedSet("invalid_set")}, false)
	if err == nil {
		t.Error("SetIPACLWithDefaults() 对于无效预定义集合应返回错误")
	}
}

// TestAddIP 测试添加IP
func TestAddIP(t *testing.T) {
	manager := NewManager()
	initialIPs := []string{"192.168.1.1", "10.0.0.1"}

	// 测试在没有设置IP ACL的情况下添加IP
	err := manager.AddIP("8.8.8.8")
	if err == nil {
		t.Error("AddIP() 在没有设置IP ACL时应返回错误")
	}

	// 测试无效IP
	err = manager.SetIPACL(initialIPs, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}

	err = manager.AddIP("invalid-ip")
	if err == nil {
		t.Error("AddIP() 对于无效IP应返回错误")
	}
}

// TestRemoveIP 测试移除IP
func TestRemoveIP(t *testing.T) {
	manager := NewManager()
	initialIPs := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"}

	// 先设置初始IP ACL
	err := manager.SetIPACL(initialIPs, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}

	// 移除IP
	err = manager.RemoveIP("10.0.0.1")
	if err != nil {
		t.Errorf("RemoveIP() 返回错误: %v", err)
	}

	// 验证IP是否被移除
	gotIPs := manager.GetIPRanges()
	expectedCount := len(initialIPs) - 1
	if len(gotIPs) != expectedCount {
		t.Errorf("GetIPRanges() 长度 = %d, 期望 %d", len(gotIPs), expectedCount)
	}

	// 测试无IP ACL的情况
	manager = NewManager()
	err = manager.RemoveIP("10.0.0.1")
	if err == nil {
		t.Error("RemoveIP() 在没有设置IP ACL时应返回错误")
	}

	// 测试不存在的IP
	err = manager.SetIPACL(initialIPs, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}
	err = manager.RemoveIP("8.8.8.8")
	if err == nil {
		t.Error("RemoveIP() 对于不存在的IP应返回错误")
	}
}

// TestAddPredefinedIPSet 测试添加预定义IP集合
func TestAddPredefinedIPSet(t *testing.T) {
	manager := NewManager()
	initialIPs := []string{"192.168.1.1"}

	// 先设置初始IP ACL
	err := manager.SetIPACL(initialIPs, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}

	// 添加预定义集合
	err = manager.AddPredefinedIPSet(ip.LoopbackNetworks, false)
	if err != nil {
		t.Errorf("AddPredefinedIPSet() 返回错误: %v", err)
	}

	// 验证集合是否被添加
	gotIPs := manager.GetIPRanges()
	if len(gotIPs) <= len(initialIPs) {
		t.Errorf("GetIPRanges() 长度 = %d, 期望大于 %d", len(gotIPs), len(initialIPs))
	}

	// 测试无IP ACL的情况
	manager = NewManager()
	err = manager.AddPredefinedIPSet(ip.LoopbackNetworks, false)
	if err == nil {
		t.Error("AddPredefinedIPSet() 在没有设置IP ACL时应返回错误")
	}

	// 测试无效预定义集合
	err = manager.SetIPACL(initialIPs, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}
	err = manager.AddPredefinedIPSet(ip.PredefinedSet("invalid_set"), false)
	if err == nil {
		t.Error("AddPredefinedIPSet() 对于无效预定义集合应返回错误")
	}
}

// TestAddAllSpecialNetworks 测试添加所有特殊网络
func TestAddAllSpecialNetworks(t *testing.T) {
	manager := NewManager()
	initialIPs := []string{"192.168.1.1"}

	// 先设置初始IP ACL
	err := manager.SetIPACL(initialIPs, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}

	// 添加所有特殊网络
	err = manager.AddAllSpecialNetworks()
	if err != nil {
		t.Errorf("AddAllSpecialNetworks() 返回错误: %v", err)
	}

	// 验证IP是否被添加
	gotIPs := manager.GetIPRanges()
	if len(gotIPs) <= len(initialIPs) {
		t.Errorf("GetIPRanges() 长度 = %d, 期望大于 %d", len(gotIPs), len(initialIPs))
	}

	// 测试无IP ACL的情况
	manager = NewManager()
	err = manager.AddAllSpecialNetworks()
	if err == nil {
		t.Error("AddAllSpecialNetworks() 在没有设置IP ACL时应返回错误")
	}
}

// TestCheckDomain 测试检查域名
func TestCheckDomain(t *testing.T) {
	manager := NewManager()
	domains := []string{"example.com"}

	// 先设置域名ACL
	manager.SetDomainACL(domains, types.Blacklist, true)

	// 检查域名
	tests := []struct {
		name     string
		domain   string
		wantPerm types.Permission
		wantErr  bool
	}{
		{
			name:     "黑名单中的域名",
			domain:   "example.com",
			wantPerm: types.Denied,
			wantErr:  false,
		},
		{
			name:     "黑名单中域名的子域名",
			domain:   "sub.example.com",
			wantPerm: types.Denied,
			wantErr:  false,
		},
		{
			name:     "不在黑名单中的域名",
			domain:   "allowed.com",
			wantPerm: types.Allowed,
			wantErr:  false,
		},
		{
			name:     "空域名",
			domain:   "",
			wantPerm: types.Denied,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPerm, err := manager.CheckDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckDomain() 错误 = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPerm != tt.wantPerm {
				t.Errorf("CheckDomain() = %v, 期望 %v", gotPerm, tt.wantPerm)
			}
		})
	}

	// 测试无域名ACL的情况
	manager = NewManager()
	_, err := manager.CheckDomain("example.com")
	if err == nil {
		t.Error("CheckDomain() 在没有设置域名ACL时应返回错误")
	}
}

// TestCheckIP 测试检查IP
func TestCheckIP(t *testing.T) {
	manager := NewManager()
	ips := []string{"192.168.1.1", "10.0.0.0/8"}

	// 先设置IP ACL
	err := manager.SetIPACL(ips, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}

	// 检查IP
	tests := []struct {
		name     string
		ip       string
		wantPerm types.Permission
		wantErr  bool
	}{
		{
			name:     "黑名单中的IP",
			ip:       "192.168.1.1",
			wantPerm: types.Denied,
			wantErr:  false,
		},
		{
			name:     "黑名单中CIDR范围内的IP",
			ip:       "10.0.0.5",
			wantPerm: types.Denied,
			wantErr:  false,
		},
		{
			name:     "不在黑名单中的IP",
			ip:       "8.8.8.8",
			wantPerm: types.Allowed,
			wantErr:  false,
		},
		{
			name:     "无效IP",
			ip:       "invalid-ip",
			wantPerm: types.Denied,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPerm, err := manager.CheckIP(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckIP() 错误 = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && gotPerm != tt.wantPerm {
				t.Errorf("CheckIP() = %v, 期望 %v", gotPerm, tt.wantPerm)
			}
		})
	}

	// 测试无IP ACL的情况
	manager = NewManager()
	_, err = manager.CheckIP("192.168.1.1")
	if err == nil {
		t.Error("CheckIP() 在没有设置IP ACL时应返回错误")
	}
}

// TestAddDomain 测试添加域名
func TestAddDomain(t *testing.T) {
	manager := NewManager()
	domains := []string{"example.com"}

	// 先设置域名ACL
	manager.SetDomainACL(domains, types.Blacklist, true)

	// 添加域名
	err := manager.AddDomain("test.org", "another.com")
	if err != nil {
		t.Errorf("AddDomain() 返回错误: %v", err)
	}

	// 验证域名是否被添加
	gotDomains := manager.GetDomains()
	expectedCount := len(domains) + 2
	if len(gotDomains) != expectedCount {
		t.Errorf("GetDomains() 长度 = %d, 期望 %d", len(gotDomains), expectedCount)
	}

	// 测试无域名ACL的情况
	manager = NewManager()
	err = manager.AddDomain("test.org")
	if err == nil {
		t.Error("AddDomain() 在没有设置域名ACL时应返回错误")
	}
}

// TestRemoveDomain 测试移除域名
func TestRemoveDomain(t *testing.T) {
	manager := NewManager()
	domains := []string{"example.com", "test.org", "another.com"}

	// 先设置域名ACL
	manager.SetDomainACL(domains, types.Blacklist, true)

	// 移除域名
	err := manager.RemoveDomain("test.org")
	if err != nil {
		t.Errorf("RemoveDomain() 返回错误: %v", err)
	}

	// 验证域名是否被移除
	gotDomains := manager.GetDomains()
	expectedCount := len(domains) - 1
	if len(gotDomains) != expectedCount {
		t.Errorf("GetDomains() 长度 = %d, 期望 %d", len(gotDomains), expectedCount)
	}

	// 测试无域名ACL的情况
	manager = NewManager()
	err = manager.RemoveDomain("test.org")
	if err == nil {
		t.Error("RemoveDomain() 在没有设置域名ACL时应返回错误")
	}

	// 测试不存在的域名
	manager.SetDomainACL(domains, types.Blacklist, true)
	err = manager.RemoveDomain("nonexistent.com")
	if err == nil {
		t.Error("RemoveDomain() 对于不存在的域名应返回错误")
	}
}

// TestReset 测试重置函数
func TestReset(t *testing.T) {
	manager := NewManager()

	// 设置域名和IP ACL
	manager.SetDomainACL([]string{"example.com"}, types.Blacklist, true)
	err := manager.SetIPACL([]string{"192.168.1.1"}, types.Blacklist)
	if err != nil {
		t.Fatalf("SetIPACL() 返回错误: %v", err)
	}

	// 重置
	manager.Reset()

	// 验证已重置
	_, err = manager.GetDomainACLType()
	if err == nil {
		t.Error("GetDomainACLType() 在重置后应返回错误")
	}

	_, err = manager.GetIPACLType()
	if err == nil {
		t.Error("GetIPACLType() 在重置后应返回错误")
	}

	if len(manager.GetDomains()) > 0 {
		t.Error("GetDomains() 在重置后应返回空列表")
	}

	if len(manager.GetIPRanges()) > 0 {
		t.Error("GetIPRanges() 在重置后应返回空列表")
	}
}
