package domain

import (
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// TestNewDomainACL 测试创建域名访问控制列表
func TestNewDomainACL(t *testing.T) {
	tests := []struct {
		name              string
		domains           []string
		listType          types.ListType
		includeSubdomains bool
		wantErr           bool
		wantDomains       []string
	}{
		{
			name:              "创建空黑名单",
			domains:           []string{},
			listType:          types.Blacklist,
			includeSubdomains: false,
			wantErr:           false,
			wantDomains:       []string{},
		},
		{
			name:              "创建空白名单",
			domains:           []string{},
			listType:          types.Whitelist,
			includeSubdomains: true,
			wantErr:           false,
			wantDomains:       []string{},
		},
		{
			name:              "创建包含有效域名的黑名单",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			wantErr:           false,
			wantDomains:       []string{"example.com", "test.org"},
		},
		{
			name:              "创建包含有效域名的白名单",
			domains:           []string{"example.com", "test.org"},
			listType:          types.Whitelist,
			includeSubdomains: true,
			wantErr:           false,
			wantDomains:       []string{"example.com", "test.org"},
		},
		{
			name:              "创建包含协议前缀域名的列表",
			domains:           []string{"http://example.com", "https://test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			wantErr:           false,
			wantDomains:       []string{"example.com", "test.org"},
		},
		{
			name:              "创建包含www前缀域名的列表",
			domains:           []string{"www.example.com", "www.test.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			wantErr:           false,
			wantDomains:       []string{"example.com", "test.org"},
		},
		{
			name:              "创建包含路径的域名列表",
			domains:           []string{"example.com/path", "test.org/index.html"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			wantErr:           false,
			wantDomains:       []string{"example.com", "test.org"},
		},
		{
			name:              "创建包含空域名的列表",
			domains:           []string{"", "example.com"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			wantErr:           false,
			wantDomains:       []string{"example.com"},
		},
		{
			name:              "创建包含混合情况域名的列表",
			domains:           []string{"http://www.example.com/path", "https://test.org/index.html"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			wantErr:           false,
			wantDomains:       []string{"example.com", "test.org"},
		},
		{
			name:              "创建包含大写域名的列表",
			domains:           []string{"EXAMPLE.COM", "TEST.ORG"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			wantErr:           false,
			wantDomains:       []string{"example.com", "test.org"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := NewDomainACL(tt.domains, tt.listType, tt.includeSubdomains)

			// 检查列表类型是否正确
			if acl.GetListType() != tt.listType {
				t.Errorf("列表类型不匹配 = %v, 期望 %v", acl.GetListType(), tt.listType)
			}

			// 检查域名列表是否匹配
			domains := acl.GetDomains()
			sort.Strings(domains)
			expectedDomains := tt.wantDomains
			sort.Strings(expectedDomains)
			if !reflect.DeepEqual(domains, expectedDomains) {
				t.Errorf("域名列表不匹配 = %v, 期望 %v", domains, expectedDomains)
			}
		})
	}
}

// TestDomainACL_Add 测试添加域名到访问控制列表
func TestDomainACL_Add(t *testing.T) {
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
			acl := NewDomainACL(tt.initialDomains, types.Blacklist, tt.includeSubdomains)
			if err := acl.Add(tt.domainsToAdd...); err != nil {
				t.Fatalf("Add 返回错误: %v", err)
			}

			// 验证域名列表
			if !reflect.DeepEqual(acl.domains, tt.expectDomains) {
				t.Errorf("添加后域名列表不匹配 = %v, 期望 %v", acl.domains, tt.expectDomains)
			}
		})
	}
}

// TestDomainACL_Remove 测试从访问控制列表移除域名
func TestDomainACL_Remove(t *testing.T) {
	tests := []struct {
		name           string
		initialDomains []string
		removeList     []string
		listType       types.ListType
		wantDomains    []string
		wantErr        bool
		checkAllErrs   bool // 是否检查所有移除操作是否都返回错误
	}{
		{
			name:           "从列表中移除存在的域名",
			initialDomains: []string{"example.com", "test.org", "example.net"},
			removeList:     []string{"example.com"},
			listType:       types.Blacklist,
			wantDomains:    []string{"test.org", "example.net"},
			wantErr:        false,
		},
		{
			name:           "移除多个存在的域名",
			initialDomains: []string{"example.com", "test.org", "example.net"},
			removeList:     []string{"example.com", "test.org"},
			listType:       types.Blacklist,
			wantDomains:    []string{"example.net"},
			wantErr:        false,
		},
		{
			name:           "移除不存在的域名",
			initialDomains: []string{"example.com", "test.org"},
			removeList:     []string{"notexist.com"},
			listType:       types.Blacklist,
			wantDomains:    []string{"example.com", "test.org"},
			wantErr:        true,
		},
		{
			name:           "移除存在和不存在的混合域名",
			initialDomains: []string{"example.com", "test.org", "domain.net"},
			removeList:     []string{"example.com", "notexist.com"},
			listType:       types.Blacklist,
			wantDomains:    []string{"test.org", "domain.net"},
			wantErr:        true,  // 由于某些域名不存在，期望有错误
			checkAllErrs:   false, // 我们只期望某些域名删除会出错
		},
		{
			name:           "移除需要规范化的域名",
			initialDomains: []string{"example.com", "test.org"},
			removeList:     []string{"http://example.com", "https://test.org"},
			listType:       types.Blacklist,
			wantDomains:    []string{},
			wantErr:        false,
		},
		{
			name:           "移除空域名",
			initialDomains: []string{"example.com", "test.org"},
			removeList:     []string{""},
			listType:       types.Blacklist,
			wantDomains:    []string{"example.com", "test.org"},
			wantErr:        true,
		},
		{
			name:           "移除空域名列表",
			initialDomains: []string{"example.com", "test.org"},
			removeList:     []string{},
			listType:       types.Blacklist,
			wantDomains:    []string{"example.com", "test.org"},
			wantErr:        false, // 移除空列表不应该返回错误
		},
		{
			name:           "移除多个混合情况的域名",
			initialDomains: []string{"example.com", "test.org", "domain.net"},
			removeList:     []string{"HTTP://example.com", "www.TEST.org"},
			listType:       types.Blacklist,
			wantDomains:    []string{"domain.net"},
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 创建 ACL 实例并添加初始域名
			acl := NewDomainACL(tt.initialDomains, tt.listType, true)

			// 执行测试的操作
			var lastErr error
			for _, domain := range tt.removeList {
				err := acl.Remove(domain)
				if err != nil {
					lastErr = err
				}
			}

			// 检查错误结果是否符合预期
			if tt.checkAllErrs {
				// 检查是否所有删除操作都返回预期结果
				if (lastErr != nil) != tt.wantErr {
					t.Errorf("错误不匹配 = %v, 期望 %v", lastErr, tt.wantErr)
				}
			} else if len(tt.removeList) > 0 {
				// 至少有一个域名需要删除，检查最后一个错误
				if (lastErr != nil) != tt.wantErr {
					t.Errorf("错误不匹配 = %v, 期望 %v", lastErr, tt.wantErr)
				}
			}

			// 检查移除后的域名列表是否符合预期
			domains := acl.GetDomains()
			sort.Strings(domains)
			expectedDomains := tt.wantDomains
			sort.Strings(expectedDomains)
			if !reflect.DeepEqual(domains, expectedDomains) {
				t.Errorf("移除后域名列表不匹配 = %v, 期望 %v", domains, expectedDomains)
			}
		})
	}
}

// TestDomainACL_GetDomains 测试获取域名列表
func TestDomainACL_GetDomains(t *testing.T) {
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
			acl := NewDomainACL(tt.domains, types.Blacklist, false)
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

// TestDomainACL_GetListType 测试获取列表类型
func TestDomainACL_GetListType(t *testing.T) {
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
			acl := NewDomainACL([]string{}, tt.listType, false)
			got := acl.GetListType()

			if got != tt.expectedReturn {
				t.Errorf("GetListType() = %v, 期望 %v", got, tt.expectedReturn)
			}
		})
	}
}

// TestDomainACL_Check 测试检查域名访问权限
func TestDomainACL_Check(t *testing.T) {
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
		{
			name:              "黑名单-末尾点FQDN匹配普通规则",
			domains:           []string{"blocked.com"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "blocked.com.",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := NewDomainACL(tt.domains, tt.listType, tt.includeSubdomains)
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

// TestDomainACL_matchDomain 测试内部域名匹配功能
func TestDomainACL_matchDomain(t *testing.T) {
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
			acl := &DomainACL{
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
		{name: "末尾点-FQDN", domain: "example.com.", expected: "example.com"},
		{name: "末尾点-多重点", domain: "sub.example.com.", expected: "sub.example.com"},
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

// TestInternationalizedDomainNames 测试国际化域名(IDN)处理
func TestInternationalizedDomainNames(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		normalized string
	}{
		{
			name:       "普通IDN域名",
			domain:     "xn--80akhbyknj4f.xn--p1ai", // пример.рф的Punycode编码
			normalized: "xn--80akhbyknj4f.xn--p1ai",
		},
		{
			name:       "带HTTP的IDN域名",
			domain:     "http://xn--80akhbyknj4f.xn--p1ai",
			normalized: "xn--80akhbyknj4f.xn--p1ai",
		},
		{
			name:       "带www的IDN域名",
			domain:     "www.xn--80akhbyknj4f.xn--p1ai",
			normalized: "xn--80akhbyknj4f.xn--p1ai",
		},
		{
			name:       "带路径的IDN域名",
			domain:     "xn--80akhbyknj4f.xn--p1ai/path",
			normalized: "xn--80akhbyknj4f.xn--p1ai",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeDomain(tt.domain)
			if got != tt.normalized {
				t.Errorf("normalizeDomain() = %v, 期望 %v", got, tt.normalized)
			}
		})
	}
}

// TestDomainsWithPort 测试带端口号的域名处理
func TestDomainsWithPort(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		normalized string
	}{
		{
			name:       "普通带端口域名",
			domain:     "example.com:8080",
			normalized: "example.com",
		},
		{
			name:       "带HTTP和端口的域名",
			domain:     "http://example.com:8080",
			normalized: "example.com",
		},
		{
			name:       "带HTTPS和端口的域名",
			domain:     "https://example.com:443",
			normalized: "example.com",
		},
		{
			name:       "带www和端口的域名",
			domain:     "www.example.com:8080",
			normalized: "example.com",
		},
		{
			name:       "带路径和端口的域名",
			domain:     "example.com:8080/path",
			normalized: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeDomain(tt.domain)
			if got != tt.normalized {
				t.Errorf("normalizeDomain() = %v, 期望 %v", got, tt.normalized)
			}
		})
	}
}

// TestDomainsWithCredentials 测试带用户名和密码的URL处理
func TestDomainsWithCredentials(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		normalized string
	}{
		{
			name:       "带用户名的URL",
			domain:     "http://user@example.com",
			normalized: "example.com",
		},
		{
			name:       "带用户名和密码的URL",
			domain:     "http://user:password@example.com",
			normalized: "example.com",
		},
		{
			name:       "HTTPS带用户名和密码的URL",
			domain:     "https://user:password@example.com",
			normalized: "example.com",
		},
		{
			name:       "带用户名、密码和端口的URL",
			domain:     "http://user:password@example.com:8080",
			normalized: "example.com",
		},
		{
			name:       "带用户名、密码、端口和路径的URL",
			domain:     "http://user:password@example.com:8080/path",
			normalized: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeDomain(tt.domain)
			if got != tt.normalized {
				t.Errorf("normalizeDomain() = %v, 期望 %v", got, tt.normalized)
			}
		})
	}
}

// TestComplexSubdomainMatching 测试复杂的子域名层级匹配
func TestComplexSubdomainMatching(t *testing.T) {
	tests := []struct {
		name              string
		domains           []string
		includeSubdomains bool
		domainToMatch     string
		expected          bool
	}{
		{
			name:              "多层级子域名匹配",
			domains:           []string{"example.com"},
			includeSubdomains: true,
			domainToMatch:     "a.b.c.d.example.com",
			expected:          true,
		},
		{
			name:              "多层级子域名精确匹配",
			domains:           []string{"a.b.c.example.com"},
			includeSubdomains: true,
			domainToMatch:     "a.b.c.example.com",
			expected:          true,
		},
		{
			name:              "多层级子域名的子域名匹配",
			domains:           []string{"a.b.c.example.com"},
			includeSubdomains: true,
			domainToMatch:     "x.y.a.b.c.example.com",
			expected:          true,
		},
		{
			name:              "多层级子域名，禁用子域名匹配",
			domains:           []string{"a.b.c.example.com"},
			includeSubdomains: false,
			domainToMatch:     "x.a.b.c.example.com",
			expected:          false,
		},
		{
			name:              "相邻域名不匹配",
			domains:           []string{"abc.example.com"},
			includeSubdomains: true,
			domainToMatch:     "def.example.com",
			expected:          false,
		},
		{
			name:              "相似域名不匹配",
			domains:           []string{"example.com"},
			includeSubdomains: true,
			domainToMatch:     "example.org",
			expected:          false,
		},
		{
			name:              "只有子域名包含目标域名",
			domains:           []string{"sub.example.com"},
			includeSubdomains: false,
			domainToMatch:     "example.com",
			expected:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := &DomainACL{
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

// TestEdgeCaseDomains 测试边缘情况域名
func TestEdgeCaseDomains(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		normalized string
	}{
		{
			name:       "极长域名",
			domain:     "this.is.a.very.very.very.very.very.very.very.very.long.domain.example.com",
			normalized: "this.is.a.very.very.very.very.very.very.very.very.long.domain.example.com",
		},
		{
			name:       "带查询参数的域名",
			domain:     "example.com?param1=value1&param2=value2",
			normalized: "example.com",
		},
		{
			name:       "带锚点的域名",
			domain:     "example.com#section1",
			normalized: "example.com",
		},
		{
			name:       "带查询参数和锚点的域名",
			domain:     "example.com?param=value#section1",
			normalized: "example.com",
		},
		{
			name:       "带特殊字符的域名",
			domain:     "exam_ple.com",
			normalized: "exam_ple.com",
		},
		{
			name:       "单标签域名",
			domain:     "localhost",
			normalized: "localhost",
		},
		{
			name:       "带HTTP和查询参数的域名",
			domain:     "http://example.com?param=value",
			normalized: "example.com",
		},
		{
			name:       "带双斜杠但无协议的域名",
			domain:     "//example.com/path",
			normalized: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeDomain(tt.domain)
			if got != tt.normalized {
				t.Errorf("normalizeDomain() = %v, 期望 %v", got, tt.normalized)
			}
		})
	}
}

// TestDomainACL_CheckEdgeCases 测试Check方法的边缘情况
func TestDomainACL_CheckEdgeCases(t *testing.T) {
	tests := []struct {
		name              string
		domains           []string
		listType          types.ListType
		includeSubdomains bool
		domainToCheck     string
		expectedPerm      types.Permission
		expectErr         error
	}{
		{
			name:              "特殊字符域名",
			domains:           []string{"example.com", "test-domain.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "test-domain.org",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
		{
			name:              "包含下划线的域名",
			domains:           []string{"example.com", "test_domain.org"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "test_domain.org",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
		{
			name:              "只有一个字符的域名",
			domains:           []string{"example.com"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "a",
			expectedPerm:      types.Allowed,
			expectErr:         nil,
		},
		{
			name:              "只有TLD的域名",
			domains:           []string{"com", "org", "net"},
			listType:          types.Blacklist,
			includeSubdomains: true,
			domainToCheck:     "example.com",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
		{
			name:              "带双斜杠但无协议的域名",
			domains:           []string{"example.com"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "//example.com/path",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
		{
			name:              "极长路径的域名",
			domains:           []string{"example.com"},
			listType:          types.Blacklist,
			includeSubdomains: false,
			domainToCheck:     "example.com/this/is/a/very/very/very/very/long/path",
			expectedPerm:      types.Denied,
			expectErr:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := NewDomainACL(tt.domains, tt.listType, tt.includeSubdomains)
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

// TestPortParsingEdgeCases 测试端口解析的边缘情况
func TestPortParsingEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "端口后带问号",
			domain:   "example.com:8080?query=value",
			expected: "example.com",
		},
		{
			name:     "端口后带锚点",
			domain:   "example.com:8080#section",
			expected: "example.com",
		},
		{
			name:     "端口包含非数字字符",
			domain:   "example.com:80ab",
			expected: "example.com",
		},
		{
			name:     "端口带斜杠带问号",
			domain:   "example.com:8080/path?query=value",
			expected: "example.com",
		},
		{
			name:     "端口带斜杠带锚点",
			domain:   "example.com:8080/path#section",
			expected: "example.com",
		},
		{
			name:     "复杂URL:带协议、用户名密码、端口、路径、问号和锚点",
			domain:   "https://user:pass@example.com:8080/path?query=value#section",
			expected: "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("normalizeDomain() = %v, 期望 %v", result, tt.expected)
			}
		})
	}
}

// TestAddPredefinedSet 测试向 DomainACL 添加预定义域名集合
func TestAddPredefinedSet(t *testing.T) {
	tests := []struct {
		name            string
		setName         PredefinedSet
		allowSet        bool
		listType        types.ListType
		wantErr         bool
		wantErrIs       error
		wantSampleMatch bool // 添加后是否应命中集合中的样本域名
		sampleDomain    string
		includeSubs     bool
	}{
		{
			name:            "黑名单添加短链集合（阻止）",
			setName:         Shorteners,
			allowSet:        false,
			listType:        types.Blacklist,
			wantErr:         false,
			wantSampleMatch: true,
			sampleDomain:    "bit.ly",
			includeSubs:     true,
		},
		{
			name:            "白名单添加可信CDN集合（允许）",
			setName:         TrustedCDN,
			allowSet:        true,
			listType:        types.Whitelist,
			wantErr:         false,
			wantSampleMatch: true,
			sampleDomain:    "jsdelivr.net",
			includeSubs:     false,
		},
		{
			name:            "黑名单+allowSet=true 不实际添加（no-op）",
			setName:         Shorteners,
			allowSet:        true,
			listType:        types.Blacklist,
			wantErr:         false,
			wantSampleMatch: false,
			sampleDomain:    "bit.ly",
			includeSubs:     true,
		},
		{
			name:      "无效集合名返回错误",
			setName:   PredefinedSet("nonexistent_set"),
			allowSet:  false,
			listType:  types.Blacklist,
			wantErr:   true,
			wantErrIs: ErrInvalidPredefinedSet,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := NewDomainACL([]string{}, tt.listType, tt.includeSubs)
			err := acl.AddPredefinedSet(tt.setName, tt.allowSet)
			if tt.wantErr {
				if err == nil {
					t.Fatal("期望错误，得到 nil")
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("期望错误 %v，得到 %v", tt.wantErrIs, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("非期望错误: %v", err)
			}
			perm, _ := acl.Check(tt.sampleDomain)
			if tt.wantSampleMatch {
				// 命中应被拒（黑名单）/ 被允许（白名单）
				wantPerm := types.Allowed
				if tt.listType == types.Blacklist {
					wantPerm = types.Denied
				}
				if perm != wantPerm {
					t.Fatalf("期望 %s，得到 %s", wantPerm, perm)
				}
			} else {
				// no-op：未添加，黑名单默认 Allowed
				if tt.listType == types.Blacklist && perm != types.Allowed {
					t.Fatalf("no-op 后黑名单应 Allowed，得到 %s", perm)
				}
			}
		})
	}
}

// TestNewDomainACLWithDefaults 测试带预定义集合的构造函数
func TestNewDomainACLWithDefaults(t *testing.T) {
	t.Run("黑名单阻止短链与一次性邮箱", func(t *testing.T) {
		acl, err := NewDomainACLWithDefaults(
			[]string{"malware.example.com"},
			types.Blacklist,
			true,
			[]PredefinedSet{Shorteners, DisposableEmail},
			false,
		)
		if err != nil {
			t.Fatalf("非期望错误: %v", err)
		}
		for _, d := range []string{"bit.ly", "mailinator.com", "malware.example.com"} {
			if perm, _ := acl.Check(d); perm != types.Denied {
				t.Fatalf("期望 %s 被 Denied，得到 %s", d, perm)
			}
		}
		// 不在列表中的域名应 Allowed
		if perm, _ := acl.Check("innocent.example.org"); perm != types.Allowed {
			t.Fatalf("期望 innocent 域 Allowed，得到 %s", perm)
		}
	})
	t.Run("无效预定义集合名返回错误", func(t *testing.T) {
		_, err := NewDomainACLWithDefaults(
			[]string{},
			types.Blacklist,
			false,
			[]PredefinedSet{PredefinedSet("nonexistent_set")},
			false,
		)
		if err == nil || !errors.Is(err, ErrInvalidPredefinedSet) {
			t.Fatalf("期望 ErrInvalidPredefinedSet，得到 %v", err)
		}
	})
}

// TestDomainACL_Wildcard 验证 *.example.com 仅匹配子域不含主域
func TestDomainACL_Wildcard(t *testing.T) {
	acl := NewDomainACL([]string{"*.evil.com"}, types.Blacklist, false)
	// 子域命中
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Denied {
		t.Errorf("sub.evil.com 应 Denied，得到 %s", perm)
	}
	// 多层子域命中
	if perm, _ := acl.Check("a.b.evil.com"); perm != types.Denied {
		t.Errorf("a.b.evil.com 应 Denied，得到 %s", perm)
	}
	// 主域本身不命中（仅子域语义）
	if perm, _ := acl.Check("evil.com"); perm != types.Allowed {
		t.Errorf("evil.com 主域应 Allowed（仅子域），得到 %s", perm)
	}
	// 相邻域名不误匹配
	if perm, _ := acl.Check("notevil.com"); perm != types.Allowed {
		t.Errorf("notevil.com 应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_WildcardAndExactCoexist 验证通配与精确规则共存
func TestDomainACL_WildcardAndExactCoexist(t *testing.T) {
	acl := NewDomainACL([]string{"*.evil.com", "evil.com"}, types.Blacklist, false)
	// 主域被精确规则阻止
	if perm, _ := acl.Check("evil.com"); perm != types.Denied {
		t.Errorf("evil.com 精确规则应 Denied，得到 %s", perm)
	}
	// 子域被通配规则阻止
	if perm, _ := acl.Check("x.evil.com"); perm != types.Denied {
		t.Errorf("x.evil.com 通配应 Denied，得到 %s", perm)
	}
	// GetDomains 返回两类规则
	domains := acl.GetDomains()
	if len(domains) != 2 {
		t.Errorf("应返回 2 条规则，得到 %d: %v", len(domains), domains)
	}
}

// TestDomainACL_RemoveWildcard 验证移除通配规则
func TestDomainACL_RemoveWildcard(t *testing.T) {
	acl := NewDomainACL([]string{"*.evil.com"}, types.Blacklist, false)
	if err := acl.Remove("*.evil.com"); err != nil {
		t.Fatalf("移除失败: %v", err)
	}
	// 移除后子域不再命中
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Allowed {
		t.Errorf("移除后 sub.evil.com 应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_WildcardWithSubdomainsFlag 验证通配在 includeSubdomains=true 下仍仅匹配子域
func TestDomainACL_WildcardWithSubdomainsFlag(t *testing.T) {
	acl := NewDomainACL([]string{"*.evil.com"}, types.Blacklist, true)
	// 即使 includeSubdomains=true，通配 *. 仍不含主域本身
	if perm, _ := acl.Check("evil.com"); perm != types.Allowed {
		t.Errorf("通配 *.evil.com 不应命中主域 evil.com，得到 %s", perm)
	}
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Denied {
		t.Errorf("sub.evil.com 应 Denied，得到 %s", perm)
	}
}

// TestDomainACL_RemoveNonexistentWildcard 验证移除不存在的通配规则返回 ErrDomainNotFound
func TestDomainACL_RemoveNonexistentWildcard(t *testing.T) {
	acl := NewDomainACL([]string{"*.evil.com"}, types.Blacklist, false)
	err := acl.Remove("*.notevil.com")
	if !errors.Is(err, ErrDomainNotFound) {
		t.Fatalf("移除不存在的通配应返回 ErrDomainNotFound，得到 %v", err)
	}
	// 原有通配规则不受影响
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Denied {
		t.Errorf("原有 *.evil.com 仍应命中 sub.evil.com，得到 %s", perm)
	}
}

// TestDomainACL_MultipleWildcards 验证多条通配规则互不误匹配
func TestDomainACL_MultipleWildcards(t *testing.T) {
	acl := NewDomainACL([]string{"*.evil.com", "*.bad.org"}, types.Blacklist, false)
	// 各自子域命中
	if perm, _ := acl.Check("x.evil.com"); perm != types.Denied {
		t.Errorf("x.evil.com 应 Denied，得到 %s", perm)
	}
	if perm, _ := acl.Check("y.bad.org"); perm != types.Denied {
		t.Errorf("y.bad.org 应 Denied，得到 %s", perm)
	}
	// 相邻域名不误匹配任一通配
	if perm, _ := acl.Check("notevil.com"); perm != types.Allowed {
		t.Errorf("notevil.com 应 Allowed，得到 %s", perm)
	}
	if perm, _ := acl.Check("notbad.org"); perm != types.Allowed {
		t.Errorf("notbad.org 应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_Prefix 验证 api.* 仅匹配以 api. 开头的域名
func TestDomainACL_Prefix(t *testing.T) {
	acl := NewDomainACL([]string{"api.*"}, types.Blacklist, false)
	// 前缀子域命中
	if perm, _ := acl.Check("api.example.com"); perm != types.Denied {
		t.Errorf("api.example.com 应 Denied，得到 %s", perm)
	}
	// 多层命中
	if perm, _ := acl.Check("api.sub.example.com"); perm != types.Denied {
		t.Errorf("api.sub.example.com 应 Denied，得到 %s", perm)
	}
	// 非该前缀不命中
	if perm, _ := acl.Check("example.com"); perm != types.Allowed {
		t.Errorf("example.com 应 Allowed，得到 %s", perm)
	}
	if perm, _ := acl.Check("web.example.com"); perm != types.Allowed {
		t.Errorf("web.example.com 应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_LooseSuffix 验证 *example.com 宽松后缀含主域
func TestDomainACL_LooseSuffix(t *testing.T) {
	acl := NewDomainACL([]string{"*evil.com"}, types.Blacklist, false)
	// 主域本身命中（与 *.evil.com 的关键区别）
	if perm, _ := acl.Check("evil.com"); perm != types.Denied {
		t.Errorf("evil.com 主域应 Denied（宽松后缀含主域），得到 %s", perm)
	}
	// 子域命中
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Denied {
		t.Errorf("sub.evil.com 应 Denied，得到 %s", perm)
	}
	// 相邻域名不误匹配
	if perm, _ := acl.Check("notevil.com"); perm != types.Allowed {
		t.Errorf("notevil.com 应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_LooseSuffixVsWildcard 验证 *x 与 *.x 语义可区分且可共存
func TestDomainACL_LooseSuffixVsWildcard(t *testing.T) {
	// *evil.com 含主域；*.evil.com 仅子域
	acl := NewDomainACL([]string{"*evil.com"}, types.Blacklist, false)
	if perm, _ := acl.Check("evil.com"); perm != types.Denied {
		t.Errorf("*evil.com 应命中主域 evil.com，得到 %s", perm)
	}
	wcl := NewDomainACL([]string{"*.evil.com"}, types.Blacklist, false)
	if perm, _ := wcl.Check("evil.com"); perm != types.Allowed {
		t.Errorf("*.evil.com 不应命中主域 evil.com，得到 %s", perm)
	}
}

// TestDomainACL_RemovePrefixAndLooseSuffix 验证移除前缀与宽松后缀规则
func TestDomainACL_RemovePrefixAndLooseSuffix(t *testing.T) {
	acl := NewDomainACL([]string{"api.*", "*evil.com"}, types.Blacklist, false)
	if err := acl.Remove("api.*"); err != nil {
		t.Fatalf("移除前缀失败: %v", err)
	}
	if perm, _ := acl.Check("api.example.com"); perm != types.Allowed {
		t.Errorf("移除 api.* 后应 Allowed，得到 %s", perm)
	}
	// 宽松后缀仍在
	if perm, _ := acl.Check("evil.com"); perm != types.Denied {
		t.Errorf("evil.com 应仍 Denied，得到 %s", perm)
	}
	if err := acl.Remove("*evil.com"); err != nil {
		t.Fatalf("移除宽松后缀失败: %v", err)
	}
	if perm, _ := acl.Check("sub.evil.com"); perm != types.Allowed {
		t.Errorf("移除 *evil.com 后应 Allowed，得到 %s", perm)
	}
}

// TestDomainACL_GetDomainsRoundTrip 验证 GetDomains 输出可作为 Add 输入重建等价 ACL
//
// 构造覆盖全部匹配维度的 ACL（精确 / 通配 *.x / 前缀 api.* / 宽松后缀 *safe.com），
// 取 GetDomains() 输出重建新 ACL，断言两者对一组测试域名 Check 结果完全一致。
// 关键用例：原 ACL 含 *.evil.com（仅子域）但不含 *evil.com，故 evil.com 主域在
// blacklist 下应 Allowed——重建 ACL 必须与此一致，不可把 *.evil.com 升格为 *evil.com。
func TestDomainACL_GetDomainsRoundTrip(t *testing.T) {
	domains := []string{"example.com", "*.evil.com", "api.*", "*safe.com"}
	original := NewDomainACL(domains, types.Blacklist, false)

	// 取 GetDomains 输出重建等价 ACL（同 listType、同 includeSubdomains）
	rebuilt := NewDomainACL(original.GetDomains(), types.Blacklist, false)

	// 重建后的规则集应逐字还原（顺序无关，排序后比对）
	want := append([]string{}, domains...)
	sort.Strings(want)
	got := append([]string{}, rebuilt.GetDomains()...)
	sort.Strings(got)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("GetDomains 往返后规则集不一致:\nwant=%v\ngot =%v", want, got)
	}

	// 对覆盖各匹配维度的测试域名，两个 ACL 的 Check 结果必须逐一致
	cases := []struct {
		domain string
	}{
		{"example.com"},  // 精确命中
		{"sub.evil.com"}, // 通配 *.evil.com 命中子域
		{"evil.com"},     // *.evil.com 不含主域 → blacklist 下 Allowed
		{"api.foo.com"},  // 前缀 api.* 命中
		{"sub.safe.com"}, // 宽松后缀 *safe.com 命中子域
		{"other.org"},    // 无任何规则命中 → blacklist 下 Allowed
	}
	for _, c := range cases {
		origPerm, origErr := original.Check(c.domain)
		newPerm, newErr := rebuilt.Check(c.domain)
		if origErr != nil || newErr != nil {
			t.Fatalf("Check(%s) 出现非预期错误: orig=%v new=%v", c.domain, origErr, newErr)
		}
		if origPerm != newPerm {
			t.Errorf("往返不一致: Check(%s) 原=%s 重建=%s", c.domain, origPerm, newPerm)
		}
	}
}
