package ip

import (
	"testing"

	"github.com/cyberspacesec/go-acl/pkg/types"
)

// TestGetPredefinedIPRanges 测试获取预定义IP范围
func TestGetPredefinedIPRanges(t *testing.T) {
	tests := []struct {
		name         string
		predefinedID PredefinedSet
		wantEmpty    bool
		wantCheck    []string // 用于检查的IP样本，应该在预定义集合中
	}{
		{
			name:         "获取私有网络IP集合",
			predefinedID: PrivateNetworks,
			wantEmpty:    false,
			wantCheck:    []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"},
		},
		{
			name:         "获取回环网络IP集合",
			predefinedID: LoopbackNetworks,
			wantEmpty:    false,
			wantCheck:    []string{"127.0.0.1", "127.0.0.2"},
		},
		{
			name:         "获取链路本地网络IP集合",
			predefinedID: LinkLocalNetworks,
			wantEmpty:    false,
			wantCheck:    []string{"169.254.0.1"},
		},
		{
			name:         "获取云服务元数据IP集合",
			predefinedID: CloudMetadata,
			wantEmpty:    false,
			wantCheck:    []string{"169.254.169.254"},
		},
		{
			name:         "获取Docker网络IP集合",
			predefinedID: DockerNetworks,
			wantEmpty:    false,
			wantCheck:    []string{"172.17.0.1"},
		},
		{
			name:         "获取所有特殊网络IP集合",
			predefinedID: AllSpecialNetworks,
			wantEmpty:    false,
			wantCheck:    []string{"127.0.0.1", "192.168.1.1", "169.254.0.1"},
		},
		{
			name:         "获取无效预定义集合",
			predefinedID: PredefinedSet("invalid_set"),
			wantEmpty:    true,
			wantCheck:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges := GetPredefinedIPRanges(tt.predefinedID)

			// 检查是否为空
			if (len(ranges) == 0) != tt.wantEmpty {
				t.Errorf("GetPredefinedIPRanges(%v) 返回 %v 个IP范围，期望为空: %v",
					tt.predefinedID, len(ranges), tt.wantEmpty)
			}

			if tt.wantEmpty {
				return
			}

			// 创建用于测试的IPAcl
			acl, err := NewIPAcl(ranges, types.Blacklist)
			if err != nil {
				t.Fatalf("无法创建测试ACL: %v", err)
			}

			// 检查样本IP是否在预定义集合中
			for _, ip := range tt.wantCheck {
				// 对于黑名单，Check返回Denied表示IP在列表中
				permission, err := acl.Check(ip)
				if err != nil {
					t.Errorf("检查IP %s 时发生错误: %v", ip, err)
					continue
				}
				if permission != types.Denied {
					t.Errorf("IP %s 应该在预定义集合 %v 中，但Check返回 %v", ip, tt.predefinedID, permission)
				}
			}
		})
	}
}

// TestAddPredefinedSetToExistingACL 测试向现有ACL添加预定义集合
func TestAddPredefinedSetToExistingACL(t *testing.T) {
	// 创建一个带有单个IP的ACL
	initialIP := "1.2.3.4"
	acl, err := NewIPAcl([]string{initialIP}, types.Blacklist)
	if err != nil {
		t.Fatalf("无法创建初始ACL: %v", err)
	}

	// 记录初始IP范围数量
	initialCount := len(acl.GetIPRanges())
	if initialCount != 1 {
		t.Fatalf("初始ACL应包含1个IP，但有 %d 个", initialCount)
	}

	// 添加预定义集合
	if err := acl.AddPredefinedSet(LoopbackNetworks, false); err != nil {
		t.Fatalf("添加预定义集合失败: %v", err)
	}

	// 验证IP范围已增加
	newRanges := acl.GetIPRanges()
	if len(newRanges) <= initialCount {
		t.Errorf("添加预定义集合后，IP范围数量应增加，从 %d 到 %d", initialCount, len(newRanges))
	}

	// 检查初始IP是否保留
	found := false
	for _, r := range newRanges {
		if r == initialIP {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("添加预定义集合后，初始IP %s 应该保留", initialIP)
	}

	// 检查特定预定义IP是否包含
	loopbackIP := "127.0.0.1"
	permission, err := acl.Check(loopbackIP)
	if err != nil {
		t.Errorf("检查回环IP时发生错误: %v", err)
	} else if permission != types.Denied {
		t.Errorf("回环IP %s 应该在黑名单中，但Check返回 %v", loopbackIP, permission)
	}
}

// TestNewIPAclWithDefaultsAndOptions 测试使用预定义集合创建新ACL
func TestNewIPAclWithDefaultsAndOptions(t *testing.T) {
	tests := []struct {
		name           string
		ipRanges       []string
		listType       types.ListType
		predefinedSets []PredefinedSet
		allowSets      bool
		wantErr        bool
		testIPs        map[string]bool // IP -> 期望能通过Check
	}{
		{
			name:           "创建包含私有网络的黑名单",
			ipRanges:       []string{},
			listType:       types.Blacklist,
			predefinedSets: []PredefinedSet{PrivateNetworks},
			allowSets:      false,
			wantErr:        false,
			testIPs: map[string]bool{
				"192.168.1.1": false, // 在黑名单中，应返回false
				"8.8.8.8":     true,  // 不在黑名单中，应返回true
			},
		},
		{
			name:           "创建包含私有网络的白名单",
			ipRanges:       []string{},
			listType:       types.Whitelist,
			predefinedSets: []PredefinedSet{PrivateNetworks},
			allowSets:      true,
			wantErr:        false,
			testIPs: map[string]bool{
				"192.168.1.1": true,  // 在白名单中，应返回true
				"8.8.8.8":     false, // 不在白名单中，应返回false
			},
		},
		{
			name:           "创建包含多个预定义集合的黑名单",
			ipRanges:       []string{},
			listType:       types.Blacklist,
			predefinedSets: []PredefinedSet{PrivateNetworks, LoopbackNetworks},
			allowSets:      false,
			wantErr:        false,
			testIPs: map[string]bool{
				"192.168.1.1": false, // 私有IP，在黑名单中
				"127.0.0.1":   false, // 回环IP，在黑名单中
				"8.8.8.8":     true,  // 公共IP，不在黑名单中
			},
		},
		{
			name:           "创建包含空预定义集合的ACL",
			ipRanges:       []string{},
			listType:       types.Blacklist,
			predefinedSets: []PredefinedSet{},
			allowSets:      false,
			wantErr:        false,
			testIPs: map[string]bool{
				"192.168.1.1": true, // 空黑名单，所有IP都允许
				"8.8.8.8":     true, // 空黑名单，所有IP都允许
			},
		},
		{
			name:           "创建包含无效预定义集合的ACL",
			ipRanges:       []string{},
			listType:       types.Blacklist,
			predefinedSets: []PredefinedSet{PredefinedSet("invalid_set")},
			allowSets:      false,
			wantErr:        true,
			testIPs:        map[string]bool{}, // 应该返回错误，不会执行测试IP
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建ACL
			acl, err := NewIPAclWithDefaults(tt.ipRanges, tt.listType, tt.predefinedSets, tt.allowSets)

			// 验证错误情况
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIPAclWithDefaults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// 如果期望出错且确实出错，则测试通过
			if tt.wantErr && err != nil {
				return
			}

			// 检查列表类型
			if acl.GetListType() != tt.listType {
				t.Errorf("ACL列表类型 = %v, 期望 %v", acl.GetListType(), tt.listType)
			}

			// 检查测试IP的结果
			for ip, expectedResult := range tt.testIPs {
				permission, err := acl.Check(ip)
				if err != nil {
					t.Errorf("检查IP %s 时发生错误: %v", ip, err)
					continue
				}

				actualResult := permission == types.Allowed
				if actualResult != expectedResult {
					t.Errorf("IP %s 的Check结果 = %v, 期望 %v", ip, actualResult, expectedResult)
				}
			}
		})
	}
}

// TestAddMultiplePredefinedSets 测试添加多个预定义集合
func TestAddMultiplePredefinedSets(t *testing.T) {
	// 创建一个空的ACL
	acl, err := NewIPAcl([]string{}, types.Blacklist)
	if err != nil {
		t.Fatalf("无法创建初始ACL: %v", err)
	}

	// 添加多个预定义集合
	predefinedSets := []PredefinedSet{
		PrivateNetworks,
		LoopbackNetworks,
		LinkLocalNetworks,
	}

	// 分别添加每个集合
	for _, set := range predefinedSets {
		if err := acl.AddPredefinedSet(set, false); err != nil {
			t.Fatalf("添加预定义集合 %v 失败: %v", set, err)
		}
	}

	// 检查测试IP
	testCases := map[string]bool{
		"192.168.1.1": false, // 私有IP，在黑名单中
		"127.0.0.1":   false, // 回环IP，在黑名单中
		"169.254.0.1": false, // 链路本地IP，在黑名单中
		"8.8.8.8":     true,  // 公共IP，不在黑名单中
	}

	for ip, expectedResult := range testCases {
		permission, err := acl.Check(ip)
		if err != nil {
			t.Errorf("检查IP %s 时发生错误: %v", ip, err)
			continue
		}

		actualResult := permission == types.Allowed
		if actualResult != expectedResult {
			t.Errorf("IP %s 的Check结果 = %v, 期望 %v", ip, actualResult, expectedResult)
		}
	}
}

// TestIPv6Support 测试ACL对IPv6的支持
func TestIPv6Support(t *testing.T) {
	// 创建一个包含IPv6相关地址的ACL
	ipRanges := []string{
		"2001:db8::/32", // IPv6文档地址
		"::1/128",       // IPv6回环地址
	}

	acl, err := NewIPAcl(ipRanges, types.Blacklist)
	if err != nil {
		t.Fatalf("无法创建ACL: %v", err)
	}

	// 测试IPv6地址
	testCases := map[string]bool{
		"2001:db8::1":          false, // 在黑名单中，应返回false
		"::1":                  false, // 在黑名单中，应返回false
		"2001:4860:4860::8888": true,  // 不在黑名单中，应返回true
	}

	for ip, expectedResult := range testCases {
		permission, err := acl.Check(ip)
		if err != nil {
			t.Errorf("检查IPv6地址 %s 时发生错误: %v", ip, err)
			continue
		}

		actualResult := permission == types.Allowed
		if actualResult != expectedResult {
			t.Errorf("IPv6地址 %s 的Check结果 = %v, 期望 %v", ip, actualResult, expectedResult)
		}
	}
}
