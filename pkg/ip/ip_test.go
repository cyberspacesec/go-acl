package ip

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/cyberspacesec/go-acl/pkg/types"
)

// TestNewIPACL 测试创建IP访问控制列表
func TestNewIPACL(t *testing.T) {
	tests := []struct {
		name      string
		ipRanges  []string
		listType  types.ListType
		wantErr   bool
		errType   error
		emptyList bool
	}{
		{
			name:      "创建有效的IPv4黑名单",
			ipRanges:  []string{"192.168.1.1", "10.0.0.0/8"},
			listType:  types.Blacklist,
			wantErr:   false,
			emptyList: false,
		},
		{
			name:      "创建有效的IPv6黑名单",
			ipRanges:  []string{"2001:db8::1", "2001:db8::/32"},
			listType:  types.Blacklist,
			wantErr:   false,
			emptyList: false,
		},
		{
			name:      "创建混合IP黑名单",
			ipRanges:  []string{"192.168.1.1", "2001:db8::/32"},
			listType:  types.Blacklist,
			wantErr:   false,
			emptyList: false,
		},
		{
			name:      "创建空白名单",
			ipRanges:  []string{},
			listType:  types.Whitelist,
			wantErr:   false,
			emptyList: true,
		},
		{
			name:      "从空字符串创建",
			ipRanges:  []string{""},
			listType:  types.Blacklist,
			wantErr:   false,
			emptyList: true,
		},
		{
			name:      "无效的IPv4地址",
			ipRanges:  []string{"300.168.1.1"},
			listType:  types.Blacklist,
			wantErr:   true,
			errType:   ErrInvalidIP,
			emptyList: false,
		},
		{
			name:      "无效的CIDR格式",
			ipRanges:  []string{"192.168.1.0/33"},
			listType:  types.Blacklist,
			wantErr:   true,
			errType:   ErrInvalidIP,
			emptyList: false,
		},
		{
			name:      "无效的IP字符串",
			ipRanges:  []string{"not-an-ip"},
			listType:  types.Blacklist,
			wantErr:   true,
			errType:   ErrInvalidIP,
			emptyList: false,
		},
		{
			name:      "包含空格的IP",
			ipRanges:  []string{" 192.168.1.1 "},
			listType:  types.Blacklist,
			wantErr:   false,
			emptyList: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := NewIPACL(tt.ipRanges, tt.listType)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIPACL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errType != nil {
				if !errors.Is(err, tt.errType) {
					t.Errorf("NewIPACL() error = %v, want error type %v", err, tt.errType)
				}
				return
			}

			if !tt.wantErr {
				// 检查列表类型是否正确
				if acl.GetListType() != tt.listType {
					t.Errorf("ACL list type = %v, want %v", acl.GetListType(), tt.listType)
				}

				// 检查IP列表是否为空
				ipRanges := acl.GetIPRanges()
				if tt.emptyList && len(ipRanges) > 0 {
					t.Errorf("Expected empty IP list, got %v", ipRanges)
				} else if !tt.emptyList && len(ipRanges) == 0 {
					t.Errorf("Expected non-empty IP list, got empty list")
				}
			}
		})
	}
}

// TestIPACL_Add 测试添加IP到访问控制列表
func TestIPACL_Add(t *testing.T) {
	// 创建一个初始ACL
	initialACL, _ := NewIPACL([]string{"192.168.1.1"}, types.Blacklist)

	tests := []struct {
		name         string
		acl          *IPACL
		ipToAdd      []string
		wantErr      bool
		errType      error
		expectedSize int // 添加后期望的IP数量
	}{
		{
			name:         "添加单个IPv4",
			acl:          initialACL,
			ipToAdd:      []string{"10.0.0.1"},
			wantErr:      false,
			expectedSize: 2,
		},
		{
			name:         "添加IPv4 CIDR",
			acl:          initialACL,
			ipToAdd:      []string{"172.16.0.0/12"},
			wantErr:      false,
			expectedSize: 3,
		},
		{
			name:         "添加IPv6",
			acl:          initialACL,
			ipToAdd:      []string{"2001:db8::1"},
			wantErr:      false,
			expectedSize: 4,
		},
		{
			name:         "添加IPv6 CIDR",
			acl:          initialACL,
			ipToAdd:      []string{"2001:db8::/32"},
			wantErr:      false,
			expectedSize: 5,
		},
		{
			name:         "添加多个IP",
			acl:          initialACL,
			ipToAdd:      []string{"8.8.8.8", "8.8.4.4"},
			wantErr:      false,
			expectedSize: 7,
		},
		{
			name:         "添加空IP",
			acl:          initialACL,
			ipToAdd:      []string{""},
			wantErr:      false,
			expectedSize: 7, // 不应该改变
		},
		{
			name:         "添加无效的IP",
			acl:          initialACL,
			ipToAdd:      []string{"999.168.1.1"},
			wantErr:      true,
			errType:      ErrInvalidIP,
			expectedSize: 7,
		},
		{
			name:         "添加无效的CIDR",
			acl:          initialACL,
			ipToAdd:      []string{"192.168.1.0/40"},
			wantErr:      true,
			errType:      ErrInvalidCIDR,
			expectedSize: 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.acl.Add(tt.ipToAdd...)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("Add() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// 检查IP数量
				ipRanges := tt.acl.GetIPRanges()
				if len(ipRanges) != tt.expectedSize {
					t.Errorf("After Add(), expected %d IPs, got %d: %v",
						tt.expectedSize, len(ipRanges), ipRanges)
				}

				// 检查是否包含添加的IP
				for _, ip := range tt.ipToAdd {
					if ip == "" {
						continue
					}
					found := false
					for _, existing := range ipRanges {
						if ip == existing {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Added IP %s not found in result %v", ip, ipRanges)
					}
				}
			}
		})
	}
}

// TestIPACL_Remove 测试从访问控制列表中移除IP
func TestIPACL_Remove(t *testing.T) {
	// 创建一个包含多个IP的ACL
	baseIPs := []string{"192.168.1.1", "10.0.0.0/8", "172.16.0.0/12", "2001:db8::1", "2001:db8::/32"}

	tests := []struct {
		name           string
		initialIPs     []string
		ipToRemove     []string
		wantErr        bool
		errType        error
		expectedRemain []string
	}{
		{
			name:           "移除单个IP",
			initialIPs:     baseIPs,
			ipToRemove:     []string{"192.168.1.1"},
			wantErr:        false,
			expectedRemain: []string{"10.0.0.0/8", "172.16.0.0/12", "2001:db8::1", "2001:db8::/32"},
		},
		{
			name:           "移除CIDR",
			initialIPs:     baseIPs,
			ipToRemove:     []string{"10.0.0.0/8"},
			wantErr:        false,
			expectedRemain: []string{"192.168.1.1", "172.16.0.0/12", "2001:db8::1", "2001:db8::/32"},
		},
		{
			name:           "移除IPv6",
			initialIPs:     baseIPs,
			ipToRemove:     []string{"2001:db8::1"},
			wantErr:        false,
			expectedRemain: []string{"192.168.1.1", "10.0.0.0/8", "172.16.0.0/12", "2001:db8::/32"},
		},
		{
			name:           "移除多个IP",
			initialIPs:     baseIPs,
			ipToRemove:     []string{"192.168.1.1", "10.0.0.0/8"},
			wantErr:        false,
			expectedRemain: []string{"172.16.0.0/12", "2001:db8::1", "2001:db8::/32"},
		},
		{
			name:           "移除空IP",
			initialIPs:     baseIPs,
			ipToRemove:     []string{""},
			wantErr:        false,
			expectedRemain: baseIPs,
		},
		{
			name:           "移除不存在的IP",
			initialIPs:     baseIPs,
			ipToRemove:     []string{"8.8.8.8"},
			wantErr:        true,
			errType:        ErrIPNotFound,
			expectedRemain: baseIPs,
		},
		{
			name:           "移除全部IP",
			initialIPs:     baseIPs,
			ipToRemove:     baseIPs,
			wantErr:        false,
			expectedRemain: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl, _ := NewIPACL(tt.initialIPs, types.Blacklist)
			err := acl.Remove(tt.ipToRemove...)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("Remove() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// 校验错误类型
			if tt.wantErr && tt.errType != nil {
				if err != tt.errType {
					t.Errorf("Remove() error = %v, want error type %v", err, tt.errType)
				}
				return
			}

			if !tt.wantErr {
				// 检查剩余的IP
				ipRanges := acl.GetIPRanges()
				if !reflect.DeepEqual(ipRanges, tt.expectedRemain) {
					t.Errorf("After Remove(), expected %v, got %v", tt.expectedRemain, ipRanges)
				}
			}
		})
	}
}

// TestIPACL_Check 测试检查IP的访问权限
func TestIPACL_Check(t *testing.T) {
	// 创建黑名单ACL
	blacklistACL, _ := NewIPACL([]string{"192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"}, types.Blacklist)

	// 创建白名单ACL
	whitelistACL, _ := NewIPACL([]string{"192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"}, types.Whitelist)

	tests := []struct {
		name      string
		acl       *IPACL
		ipToCheck string
		want      types.Permission
		wantErr   bool
		errType   error
	}{
		// 黑名单测试
		{
			name:      "黑名单 - 被拒绝的IPv4",
			acl:       blacklistACL,
			ipToCheck: "192.168.1.100",
			want:      types.Denied,
			wantErr:   false,
		},
		{
			name:      "黑名单 - 被拒绝的CIDR范围",
			acl:       blacklistACL,
			ipToCheck: "10.1.2.3",
			want:      types.Denied,
			wantErr:   false,
		},
		{
			name:      "黑名单 - 被拒绝的IPv6",
			acl:       blacklistACL,
			ipToCheck: "2001:db8::1",
			want:      types.Denied,
			wantErr:   false,
		},
		{
			name:      "黑名单 - 允许的IP",
			acl:       blacklistACL,
			ipToCheck: "8.8.8.8",
			want:      types.Allowed,
			wantErr:   false,
		},
		{
			name:      "黑名单 - 无效的IP",
			acl:       blacklistACL,
			ipToCheck: "invalid-ip",
			want:      types.Denied,
			wantErr:   true,
			errType:   ErrInvalidIP,
		},

		// 白名单测试
		{
			name:      "白名单 - 允许的IPv4",
			acl:       whitelistACL,
			ipToCheck: "192.168.1.100",
			want:      types.Allowed,
			wantErr:   false,
		},
		{
			name:      "白名单 - 允许的CIDR范围",
			acl:       whitelistACL,
			ipToCheck: "10.1.2.3",
			want:      types.Allowed,
			wantErr:   false,
		},
		{
			name:      "白名单 - 允许的IPv6",
			acl:       whitelistACL,
			ipToCheck: "2001:db8::1",
			want:      types.Allowed,
			wantErr:   false,
		},
		{
			name:      "白名单 - 拒绝的IP",
			acl:       whitelistACL,
			ipToCheck: "8.8.8.8",
			want:      types.Denied,
			wantErr:   false,
		},
		{
			name:      "白名单 - 无效的IP",
			acl:       whitelistACL,
			ipToCheck: "invalid-ip",
			want:      types.Denied,
			wantErr:   true,
			errType:   ErrInvalidIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.acl.Check(tt.ipToCheck)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// 校验错误类型
			if tt.wantErr && tt.errType != nil {
				if err != tt.errType {
					t.Errorf("Check() error = %v, want error type %v", err, tt.errType)
				}
				return
			}

			// 检查权限结果
			if got != tt.want {
				t.Errorf("Check() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewIPACLWithDefaults 测试创建带预定义集合的ACL
func TestNewIPACLWithDefaults(t *testing.T) {
	tests := []struct {
		name             string
		ipRanges         []string
		listType         types.ListType
		predefinedSets   []PredefinedSet
		allowDefaultSets bool
		wantErr          bool
		minExpectedSize  int // 最小期望的IP数量
	}{
		{
			name:             "创建黑名单加入一个预定义集",
			ipRanges:         []string{"192.168.1.1"},
			listType:         types.Blacklist,
			predefinedSets:   []PredefinedSet{PrivateNetworks},
			allowDefaultSets: false,
			wantErr:          false,
			minExpectedSize:  4, // 原IP + 预定义集中的IP
		},
		{
			name:             "创建黑名单但允许预定义集",
			ipRanges:         []string{"192.168.1.1"},
			listType:         types.Blacklist,
			predefinedSets:   []PredefinedSet{PrivateNetworks},
			allowDefaultSets: true,
			wantErr:          false,
			minExpectedSize:  1, // 只有原IP
		},
		{
			name:             "创建白名单禁止预定义集",
			ipRanges:         []string{"192.168.1.1"},
			listType:         types.Whitelist,
			predefinedSets:   []PredefinedSet{PrivateNetworks},
			allowDefaultSets: false,
			wantErr:          false,
			minExpectedSize:  1, // 只有原IP
		},
		{
			name:             "创建白名单允许预定义集",
			ipRanges:         []string{"8.8.8.8"},
			listType:         types.Whitelist,
			predefinedSets:   []PredefinedSet{PrivateNetworks},
			allowDefaultSets: true,
			wantErr:          false,
			minExpectedSize:  4, // 原IP + 预定义集中的IP
		},
		{
			name:             "使用无效的预定义集",
			ipRanges:         []string{"192.168.1.1"},
			listType:         types.Blacklist,
			predefinedSets:   []PredefinedSet{"invalid_set"},
			allowDefaultSets: false,
			wantErr:          true,
			minExpectedSize:  0,
		},
		{
			name:             "使用多个预定义集",
			ipRanges:         []string{"192.168.1.1"},
			listType:         types.Blacklist,
			predefinedSets:   []PredefinedSet{PrivateNetworks, LoopbackNetworks},
			allowDefaultSets: false,
			wantErr:          false,
			minExpectedSize:  5, // 原IP + 两个预定义集中的IP
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := NewIPACLWithDefaults(tt.ipRanges, tt.listType, tt.predefinedSets, tt.allowDefaultSets)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("NewIPACLWithDefaults() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// 检查IP数量
				ipRanges := acl.GetIPRanges()
				if len(ipRanges) < tt.minExpectedSize {
					t.Errorf("Expected at least %d IPs, got %d: %v",
						tt.minExpectedSize, len(ipRanges), ipRanges)
				}

				// 检查列表类型
				if acl.GetListType() != tt.listType {
					t.Errorf("ACL list type = %v, want %v", acl.GetListType(), tt.listType)
				}
			}
		})
	}
}

// TestNewIPACLWithDefaultsErrorCases 测试NewIPACLWithDefaults函数的错误处理
func TestNewIPACLWithDefaultsErrorCases(t *testing.T) {
	// 测试无效的IP范围导致的错误
	_, err := NewIPACLWithDefaults([]string{"invalid-ip"}, types.Blacklist, []PredefinedSet{PrivateNetworks}, false)
	if err == nil {
		t.Errorf("对于无效的IP范围，应该返回错误")
	}
}

// TestIPACL_AddPredefinedSet 测试添加预定义集合
func TestIPACL_AddPredefinedSet(t *testing.T) {
	tests := []struct {
		name           string
		initialIPs     []string
		listType       types.ListType
		setToAdd       PredefinedSet
		allowSet       bool
		wantErr        bool
		errType        error
		expectIncrease bool // 是否期望IP数量增加
	}{
		{
			name:           "黑名单添加集合不允许",
			initialIPs:     []string{"8.8.8.8"},
			listType:       types.Blacklist,
			setToAdd:       PrivateNetworks,
			allowSet:       false,
			wantErr:        false,
			expectIncrease: true,
		},
		{
			name:           "黑名单添加集合但允许",
			initialIPs:     []string{"8.8.8.8"},
			listType:       types.Blacklist,
			setToAdd:       PrivateNetworks,
			allowSet:       true,
			wantErr:        false,
			expectIncrease: false,
		},
		{
			name:           "白名单添加集合不允许",
			initialIPs:     []string{"8.8.8.8"},
			listType:       types.Whitelist,
			setToAdd:       PrivateNetworks,
			allowSet:       false,
			wantErr:        false,
			expectIncrease: false,
		},
		{
			name:           "白名单添加集合并允许",
			initialIPs:     []string{"8.8.8.8"},
			listType:       types.Whitelist,
			setToAdd:       PrivateNetworks,
			allowSet:       true,
			wantErr:        false,
			expectIncrease: true,
		},
		{
			name:           "添加无效的集合",
			initialIPs:     []string{"8.8.8.8"},
			listType:       types.Blacklist,
			setToAdd:       "invalid_set",
			allowSet:       false,
			wantErr:        true,
			errType:        ErrInvalidPredefinedSet,
			expectIncrease: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl, _ := NewIPACL(tt.initialIPs, tt.listType)
			initialCount := len(acl.GetIPRanges())

			err := acl.AddPredefinedSet(tt.setToAdd, tt.allowSet)

			// 检查错误
			if (err != nil) != tt.wantErr {
				t.Errorf("AddPredefinedSet() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// 校验错误类型
			if tt.wantErr && tt.errType != nil {
				if err != tt.errType {
					t.Errorf("AddPredefinedSet() error = %v, want error type %v", err, tt.errType)
				}
				return
			}

			// 检查IP数量变化
			finalCount := len(acl.GetIPRanges())
			if tt.expectIncrease && finalCount <= initialCount {
				t.Errorf("Expected IP count to increase from %d, but got %d",
					initialCount, finalCount)
			} else if !tt.expectIncrease && finalCount > initialCount {
				t.Errorf("Expected IP count to stay at %d, but got %d",
					initialCount, finalCount)
			}
		})
	}
}

// TestIPACL_AddPredefinedSetEdgeCases 测试AddPredefinedSet函数的边缘情况
func TestIPACL_AddPredefinedSetEdgeCases(t *testing.T) {
	// 测试白名单模式且allowSet=false的情况（不应添加预定义集合）
	acl, err := NewIPACL([]string{"8.8.8.8"}, types.Whitelist)
	if err != nil {
		t.Fatalf("创建ACL失败: %v", err)
	}

	initialCount := len(acl.GetIPRanges())
	err = acl.AddPredefinedSet(PrivateNetworks, false)
	if err != nil {
		t.Fatalf("AddPredefinedSet失败: %v", err)
	}

	// 检查IP范围数量是否保持不变（不应该添加）
	if len(acl.GetIPRanges()) != initialCount {
		t.Errorf("白名单模式且allowSet=false时不应添加IP，期望 %d 个IP，实际有 %d 个",
			initialCount, len(acl.GetIPRanges()))
	}

	// 测试黑名单模式且allowSet=true的情况（不应添加预定义集合）
	acl, err = NewIPACL([]string{"8.8.8.8"}, types.Blacklist)
	if err != nil {
		t.Fatalf("创建ACL失败: %v", err)
	}

	initialCount = len(acl.GetIPRanges())
	err = acl.AddPredefinedSet(PrivateNetworks, true)
	if err != nil {
		t.Fatalf("AddPredefinedSet失败: %v", err)
	}

	// 检查IP范围数量是否保持不变（不应该添加）
	if len(acl.GetIPRanges()) != initialCount {
		t.Errorf("黑名单模式且allowSet=true时不应添加IP，期望 %d 个IP，实际有 %d 个",
			initialCount, len(acl.GetIPRanges()))
	}
}

// TestIPACL_RemoveEmptyList 测试从空列表中移除IP的情况
func TestIPACL_RemoveEmptyList(t *testing.T) {
	// 创建一个空的ACL
	acl, err := NewIPACL([]string{}, types.Blacklist)
	if err != nil {
		t.Fatalf("创建ACL失败: %v", err)
	}

	// 尝试移除IP
	err = acl.Remove("192.168.1.1")
	if err == nil || err != ErrIPNotFound {
		t.Errorf("从空列表移除不存在的IP应返回ErrIPNotFound，但得到 %v", err)
	}
}

// TestIPACL_matchIP 测试IP匹配功能
func TestIPACL_matchIP(t *testing.T) {
	// 创建测试用ACL
	acl, _ := NewIPACL([]string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"2001:db8::/32",
	}, types.Blacklist)

	tests := []struct {
		name      string
		ipToMatch string
		want      bool
	}{
		{
			name:      "IPv4精确匹配",
			ipToMatch: "192.168.1.1",
			want:      true,
		},
		{
			name:      "IPv4 CIDR匹配",
			ipToMatch: "10.1.2.3",
			want:      true,
		},
		{
			name:      "IPv6匹配",
			ipToMatch: "2001:db8::1",
			want:      true,
		},
		{
			name:      "不匹配的IPv4",
			ipToMatch: "8.8.8.8",
			want:      false,
		},
		{
			name:      "不匹配的IPv6",
			ipToMatch: "2001:db9::1",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipToMatch)
			if ip == nil {
				t.Fatalf("Invalid IP for test: %s", tt.ipToMatch)
			}

			got := acl.matchIP(ip)
			if got != tt.want {
				t.Errorf("matchIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
