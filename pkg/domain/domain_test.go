package domain

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cyberspacesec/go-acl/pkg/types"
)

// TestNewDomainAcl 测试创建域名访问控制列表
func TestNewDomainAcl(t *testing.T) {
	tests := []struct {
		name              string
		domains           []string
		listType          types.ListType
		includeSubdomains bool
		want              *DomainAcl
	}{
		{
			name:              "创建空黑名单",
			domains:           []string{},
			listType:          types.Blacklist,
			includeSubdomains: false,
			want: &DomainAcl{
				domains:           []string{},
				listType:          types.Blacklist,
				includeSubdomains: false,
			},
		},
		{
			name:              "创建空白名单",
			domains:           []string{},
			listType:          types.Whitelist,
			includeSubdomains: true,
			want: &DomainAcl{
				domains:           []string{},
				listType:          types.Whitelist,
				includeSubdomains: true,
			},
		},
		{
			name:              "创建包含有效域名的黑名单",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			want: &DomainAcl{
				domains:           []string{"example.com", "test.org"},
				listType:          types.Blacklist,
				includeSubdomains: false,
			},
		},
		{
			name:              "创建包含有效域名的白名单",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Whitelist,
			includeSubdomains: true,
			want: &DomainAcl{
				domains:           []string{"example.com", "test.org"},
				listType:          types.Whitelist,
				includeSubdomains: true,
			},
		},
		{
			name:              "创建包含协议前缀域名的列表",
			domains:           []string{"http://example.com", "https://test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			want: &DomainAcl{
				domains:           []string{"example.com", "test.org"},
				listType:          types.Blacklist,
				includeSubdomains: false,
			},
		},
		{
			name:              "创建包含www前缀域名的列表",
			domains:           []string{"www.example.com", "www.test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			want: &DomainAcl{
				domains:           []string{"example.com", "test.org"},
				listType:          types.Blacklist,
				includeSubdomains: false,
			},
		},
		{
			name:              "创建包含路径的域名列表",
			domains:           []string{"example.com/path", "test.org/index.html"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			want: &DomainAcl{
				domains:           []string{"example.com", "test.org"},
				listType:          types.Blacklist,
				includeSubdomains: false,
			},
		},
		{
			name:              "创建包含空域名的列表",
			domains:           []string{"example.com", "", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			want: &DomainAcl{
				domains:           []string{"example.com", "test.org"},
				listType:          types.Blacklist,
				includeSubdomains: false,
			},
		},
		{
			name:              "创建包含混合情况域名的列表",
			domains:           []string{"http://www.example.com/path", "https://test.org/index.html", "sub.domain.com"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			want: &DomainAcl{
				domains:           []string{"example.com", "test.org", "sub.domain.com"},
				listType:          types.Blacklist,
				includeSubdomains: false,
			},
		},
		{
			name:              "创建包含大写域名的列表",
			domains:           []string{"EXAMPLE.COM", "Test.Org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			want: &DomainAcl{
				domains:           []string{"example.com", "test.org"},
				listType:          types.Blacklist,
				includeSubdomains: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewDomainAcl(tt.domains, tt.listType, tt.includeSubdomains)

			// 检查列表类型
			if got.listType != tt.want.listType {
				t.Errorf("列表类型不匹配 = %v, 期望 %v", got.listType, tt.want.listType)
			}

			// 检查子域名标志
			if got.includeSubdomains != tt.want.includeSubdomains {
				t.Errorf("子域名标志不匹配 = %v, 期望 %v", got.includeSubdomains, tt.want.includeSubdomains)
			}

			// 检查域名列表内容
			if !reflect.DeepEqual(got.domains, tt.want.domains) {
				t.Errorf("域名列表不匹配 = %v, 期望 %v", got.domains, tt.want.domains)
			}
		})
	}
}

// TestDomainAcl_Add 测试添加域名到访问控制列表
func TestDomainAcl_Add(t *testing.T) {
	tests := []struct {
		name              string
		initialDomains    []string
		domainsToAdd      []string
		expectDomains     []string
		includeSubdomains bool
	}{
		{
			name:              "向空列表添加域名",
			initialDomains:    []string{},
			domainsToAdd:      []string{"example.com", "test.org"},
			expectDomains:     []string{"example.com", "test.org"},
			includeSubdomains: false,
		},
		{
			name:              "向现有列表添加新域名",
			initialDomains:    []string{"example.com"},
			domainsToAdd:      []string{"test.org", "domain.net"},
			expectDomains:     []string{"example.com", "test.org", "domain.net"},
			includeSubdomains: false,
		},
		{
			name:              "添加已存在的域名",
			initialDomains:    []string{"example.com", "test.org"},
			domainsToAdd:      []string{"example.com", "domain.net"},
			expectDomains:     []string{"example.com", "test.org", "domain.net"},
			includeSubdomains: false,
		},
		{
			name:              "添加需要规范化的域名",
			initialDomains:    []string{"example.com"},
			domainsToAdd:      []string{"http://test.org", "www.domain.net"},
			expectDomains:     []string{"example.com", "test.org", "domain.net"},
			includeSubdomains: false,
		},
		{
			name:              "添加空域名",
			initialDomains:    []string{"example.com"},
			domainsToAdd:      []string{""},
			expectDomains:     []string{"example.com"},
			includeSubdomains: false,
		},
		{
			name:              "添加空域名列表",
			initialDomains:    []string{"example.com", "test.org"},
			domainsToAdd:      []string{},
			expectDomains:     []string{"example.com", "test.org"},
			includeSubdomains: false,
		},
		{
			name:              "添加混合情况的域名",
			initialDomains:    []string{"example.com"},
			domainsToAdd:      []string{"HTTP://www.Test.Org/path", "https://Domain.Net/index.html"},
			expectDomains:     []string{"example.com", "test.org", "domain.net"},
			includeSubdomains: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := NewDomainAcl(tt.initialDomains, types.Blacklist, tt.includeSubdomains)
			acl.Add(tt.domainsToAdd...)

			// 验证域名列表
			if !reflect.DeepEqual(acl.domains, tt.expectDomains) {
				t.Errorf("添加后域名列表不匹配 = %v, 期望 %v", acl.domains, tt.expectDomains)
			}
		})
	}
}

// TestDomainAcl_Remove 测试从访问控制列表移除域名
func TestDomainAcl_Remove(t *testing.T) {
	tests := []struct {
		name              string
		initialDomains    []string
		domainsToRemove   []string
		expectDomains     []string
		expectErr         error
		includeSubdomains bool
	}{
		{
			name:              "从列表中移除存在的域名",
			initialDomains:    []string{"example.com", "test.org", "domain.net"},
			domainsToRemove:   []string{"test.org"},
			expectDomains:     []string{"example.com", "domain.net"},
			expectErr:         nil,
			includeSubdomains: false,
		},
		{
			name:              "移除多个存在的域名",
			initialDomains:    []string{"example.com", "test.org", "domain.net", "other.io"},
			domainsToRemove:   []string{"example.com", "domain.net"},
			expectDomains:     []string{"test.org", "other.io"},
			expectErr:         nil,
			includeSubdomains: false,
		},
		{
			name:              "移除不存在的域名",
			initialDomains:    []string{"example.com", "test.org"},
			domainsToRemove:   []string{"domain.net"},
			expectDomains:     []string{"example.com", "test.org"},
			expectErr:         ErrDomainNotFound,
			includeSubdomains: false,
		},
		{
			name:              "移除存在和不存在的混合域名",
			initialDomains:    []string{"example.com", "test.org", "domain.net"},
			domainsToRemove:   []string{"example.com", "nonexistent.com"},
			expectDomains:     []string{"test.org", "domain.net"},
			expectErr:         ErrDomainNotFound,
			includeSubdomains: false,
		},
		{
			name:              "移除需要规范化的域名",
			initialDomains:    []string{"example.com", "test.org"},
			domainsToRemove:   []string{"http://example.com", "www.test.org"},
			expectDomains:     []string{},
			expectErr:         nil,
			includeSubdomains: false,
		},
		{
			name:              "移除空域名",
			initialDomains:    []string{"example.com", "test.org"},
			domainsToRemove:   []string{""},
			expectDomains:     []string{"example.com", "test.org"},
			expectErr:         nil,
			includeSubdomains: false,
		},
		{
			name:              "移除空域名列表",
			initialDomains:    []string{"example.com", "test.org"},
			domainsToRemove:   []string{},
			expectDomains:     []string{"example.com", "test.org"},
			expectErr:         nil,
			includeSubdomains: false,
		},
		{
			name:              "移除多个混合情况的域名",
			initialDomains:    []string{"example.com", "test.org", "domain.net"},
			domainsToRemove:   []string{"HTTP://www.Example.Com/path", "https://Test.Org/index.html"},
			expectDomains:     []string{"domain.net"},
			expectErr:         nil,
			includeSubdomains: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := NewDomainAcl(tt.initialDomains, types.Blacklist, tt.includeSubdomains)
			err := acl.Remove(tt.domainsToRemove...)

			// 检查错误
			if !errors.Is(err, tt.expectErr) {
				t.Errorf("错误不匹配 = %v, 期望 %v", err, tt.expectErr)
			}

			// 检查域名列表
			if !reflect.DeepEqual(acl.domains, tt.expectDomains) {
				t.Errorf("移除后域名列表不匹配 = %v, 期望 %v", acl.domains, tt.expectDomains)
			}
		})
	}
}

// TestDomainAcl_GetDomains 测试获取域名列表
func TestDomainAcl_GetDomains(t *testing.T) {
	tests := []struct {
		name           string
		domains        []string
		expectedReturn []string
	}{
		{
			name:           "获取空域名列表",
			domains:        []string{},
			expectedReturn: []string{},
		},
		{
			name:           "获取非空域名列表",
			domains:        []string{"example.com", "test.org"},
			expectedReturn: []string{"example.com", "test.org"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := NewDomainAcl(tt.domains, types.Blacklist, false)
			got := acl.GetDomains()

			// 检查返回的域名列表
			if !reflect.DeepEqual(got, tt.expectedReturn) {
				t.Errorf("GetDomains() = %v, 期望 %v", got, tt.expectedReturn)
			}

			// 确保返回的是副本，而非引用
			if len(got) > 0 {
				got[0] = "modified.com"
				if reflect.DeepEqual(acl.domains, got) {
					t.Errorf("GetDomains() 返回的不是副本: %v == %v", acl.domains, got)
				}
			}
		})
	}
}

// TestDomainAcl_GetListType 测试获取列表类型
func TestDomainAcl_GetListType(t *testing.T) {
	tests := []struct {
		name           string
		listType       types.ListType
		expectedReturn types.ListType
	}{
		{
			name:           "获取黑名单类型",
			listType:       types.Blacklist,
			expectedReturn: types.Blacklist,
		},
		{
			name:           "获取白名单类型",
			listType:       types.Whitelist,
			expectedReturn: types.Whitelist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := NewDomainAcl([]string{}, tt.listType, false)
			got := acl.GetListType()

			if got != tt.expectedReturn {
				t.Errorf("GetListType() = %v, 期望 %v", got, tt.expectedReturn)
			}
		})
	}
}

// TestDomainAcl_Check 测试检查域名访问权限
func TestDomainAcl_Check(t *testing.T) {
	tests := []struct {
		name              string
		domains           []string
		listType          types.ListType
		includeSubdomains bool
		domainToCheck     string
		expectedPerm      types.Permission
		expectErr         error
	}{
		// 黑名单测试
		{
			name:              "黑名单-精确匹配的禁止域名",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "example.com",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
		{
			name:              "黑名单-精确匹配的允许域名",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "allowed.com",
			expectedPerm:      types.Allowed,
			expectErr:         nil,
		},
		{
			name:              "黑名单-匹配子域名(启用子域名检查)",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: true,
			domainToCheck:     "sub.example.com",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
		{
			name:              "黑名单-匹配子域名(禁用子域名检查)",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "sub.example.com",
			expectedPerm:      types.Allowed,
			expectErr:         nil,
		},

		// 白名单测试
		{
			name:              "白名单-精确匹配的允许域名",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Whitelist,
			includeSubdomains: false,
			domainToCheck:     "example.com",
			expectedPerm:      types.Allowed,
			expectErr:         nil,
		},
		{
			name:              "白名单-精确匹配的禁止域名",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Whitelist,
			includeSubdomains: false,
			domainToCheck:     "blocked.com",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
		{
			name:              "白名单-匹配子域名(启用子域名检查)",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Whitelist,
			includeSubdomains: true,
			domainToCheck:     "sub.example.com",
			expectedPerm:      types.Allowed,
			expectErr:         nil,
		},
		{
			name:              "白名单-匹配子域名(禁用子域名检查)",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Whitelist,
			includeSubdomains: false,
			domainToCheck:     "sub.example.com",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},

		// 规范化和边缘情况测试
		{
			name:              "检查需要规范化的域名",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "http://www.example.com/path",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
		{
			name:              "检查空域名",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "",
			expectedPerm:      types.Denied,
			expectErr:         ErrInvalidDomain,
		},
		{
			name:              "检查无效域名(全空格)",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "   ",
			expectedPerm:      types.Denied,
			expectErr:         ErrInvalidDomain,
		},
		{
			name:              "检查大小写域名(黑名单)",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "EXAMPLE.COM",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
		{
			name:              "检查大小写域名(白名单)",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Whitelist,
			includeSubdomains: false,
			domainToCheck:     "EXAMPLE.COM",
			expectedPerm:      types.Allowed,
			expectErr:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := NewDomainAcl(tt.domains, tt.listType, tt.includeSubdomains)
			perm, err := acl.Check(tt.domainToCheck)

			// 检查错误
			if !errors.Is(err, tt.expectErr) {
				t.Errorf("错误不匹配 = %v, 期望 %v", err, tt.expectErr)
			}

			// 检查权限
			if perm != tt.expectedPerm {
				t.Errorf("权限不匹配 = %v, 期望 %v", perm, tt.expectedPerm)
			}
		})
	}
}

// TestDomainAcl_matchDomain 测试内部域名匹配功能
func TestDomainAcl_matchDomain(t *testing.T) {
	tests := []struct {
		name              string
		domains           []string
		includeSubdomains bool
		domainToMatch     string
		expected          bool
	}{
		{
			name:              "精确匹配",
			domains:           []string{"example.com", "test.org"},
			includeSubdomains: false,
			domainToMatch:     "example.com",
			expected:          true,
		},
		{
			name:              "子域名匹配(启用子域名检查)",
			domains:           []string{"example.com", "test.org"},
			includeSubdomains: true,
			domainToMatch:     "sub.example.com",
			expected:          true,
		},
		{
			name:              "子域名匹配(禁用子域名检查)",
			domains:           []string{"example.com", "test.org"},
			includeSubdomains: false,
			domainToMatch:     "sub.example.com",
			expected:          false,
		},
		{
			name:              "多层子域名匹配",
			domains:           []string{"example.com", "test.org"},
			includeSubdomains: true,
			domainToMatch:     "deep.sub.example.com",
			expected:          true,
		},
		{
			name:              "不匹配的域名",
			domains:           []string{"example.com", "test.org"},
			includeSubdomains: true,
			domainToMatch:     "other.com",
			expected:          false,
		},
		{
			name:              "部分匹配但不是子域名",
			domains:           []string{"example.com", "test.org"},
			includeSubdomains: true,
			domainToMatch:     "myexample.com",
			expected:          false,
		},
		{
			name:              "空域名列表",
			domains:           []string{},
			includeSubdomains: true,
			domainToMatch:     "example.com",
			expected:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := &DomainAcl{
				domains:           tt.domains,
				listType:          types.Blacklist, // 列表类型对匹配功能没有影响
				includeSubdomains: tt.includeSubdomains,
			}

			got := acl.matchDomain(tt.domainToMatch)
			if got != tt.expected {
				t.Errorf("matchDomain() = %v, 期望 %v", got, tt.expected)
			}
		})
	}
}

// TestNormalizeDomain 测试域名规范化功能
func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "基本域名",
			domain:   "example.com",
			expected: "example.com",
		},
		{
			name:     "带HTTP前缀",
			domain:   "http://example.com",
			expected: "example.com",
		},
		{
			name:     "带HTTPS前缀",
			domain:   "https://example.com",
			expected: "example.com",
		},
		{
			name:     "带WWW前缀",
			domain:   "www.example.com",
			expected: "example.com",
		},
		{
			name:     "带路径",
			domain:   "example.com/path",
			expected: "example.com",
		},
		{
			name:     "带路径和查询参数",
			domain:   "example.com/path?query=value",
			expected: "example.com",
		},
		{
			name:     "HTTP+WWW+路径",
			domain:   "http://www.example.com/path",
			expected: "example.com",
		},
		{
			name:     "HTTPS+WWW+路径",
			domain:   "https://www.example.com/path",
			expected: "example.com",
		},
		{
			name:     "大写域名",
			domain:   "EXAMPLE.COM",
			expected: "example.com",
		},
		{
			name:     "混合大小写域名",
			domain:   "ExAmPlE.CoM",
			expected: "example.com",
		},
		{
			name:     "带空格域名",
			domain:   " example.com ",
			expected: "example.com",
		},
		{
			name:     "空域名",
			domain:   "",
			expected: "",
		},
		{
			name:     "只有空格",
			domain:   "   ",
			expected: "",
		},
		{
			name:     "只有协议",
			domain:   "http://",
			expected: "",
		},
		{
			name:     "只有www",
			domain:   "www.",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeDomain(tt.domain)
			if got != tt.expected {
				t.Errorf("normalizeDomain() = %v, 期望 %v", got, tt.expected)
			}
		})
	}
}

// TestDebugNormalizeDomain 测试调试域名规范化函数的具体行为
func TestDebugNormalizeDomain(t *testing.T) {
	inputs := []string{
		"HTTP://www.Test.Org/path",
		"https://Domain.Net/index.html",
		"HTTP://www.Example.Com/path",
		"https://Test.Org/index.html",
	}

	for _, input := range inputs {
		result := normalizeDomain(input)
		t.Logf("Input: %s, Normalized: %s", input, result)
	}
}
