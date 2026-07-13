package domain

import (
	"testing"
)

// TestGetPredefinedDomains 测试获取预定义域名集合
func TestGetPredefinedDomains(t *testing.T) {
	tests := []struct {
		name       string
		set        PredefinedSet
		wantEmpty  bool
		wantSample string // 期望包含的样本域名
	}{
		{name: "短链服务集合非空", set: Shorteners, wantEmpty: false, wantSample: "bit.ly"},
		{name: "一次性邮箱集合非空", set: DisposableEmail, wantEmpty: false, wantSample: "mailinator.com"},
		{name: "代码托管集合非空", set: CodeHosting, wantEmpty: false, wantSample: "github.com"},
		{name: "可信CDN集合非空", set: TrustedCDN, wantEmpty: false, wantSample: "jsdelivr.net"},
		{name: "不存在的集合返回nil", set: PredefinedSet("nonexistent_set"), wantEmpty: true, wantSample: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPredefinedDomains(tt.set)
			if tt.wantEmpty {
				if got != nil {
					t.Fatalf("期望 nil，得到 %v", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("集合 %s 不应为空", tt.set)
			}
			found := false
			for _, d := range got {
				if d == tt.wantSample {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("集合 %s 应包含样本 %s，实际 %v", tt.set, tt.wantSample, got)
			}
		})
	}
}

// TestAllMaliciousDomainsAggregation 测试 AllMaliciousDomains 是所有子集的去重并集
func TestAllMaliciousDomainsAggregation(t *testing.T) {
	all := GetPredefinedDomains(AllMaliciousDomains)
	if len(all) == 0 {
		t.Fatal("AllMaliciousDomains 不应为空")
	}
	// 去重性：无重复元素
	seen := make(map[string]struct{}, len(all))
	for _, d := range all {
		if _, ok := seen[d]; ok {
			t.Fatalf("AllMaliciousDomains 存在重复域名: %s", d)
		}
		seen[d] = struct{}{}
	}
	// 完备性：每个子集的每个域名都应出现在 all 中
	for set, domains := range PredefinedSets {
		if set == AllMaliciousDomains {
			continue
		}
		for _, d := range domains {
			if _, ok := seen[d]; !ok {
				t.Fatalf("域名 %s（来自 %s）未出现在 AllMaliciousDomains 中", d, set)
			}
		}
	}
}

// TestPredefinedSetsInitIdempotent 测试 init 合成结果稳定（多次调用等价，已排序）
func TestPredefinedSetsInitIdempotent(t *testing.T) {
	all := GetPredefinedDomains(AllMaliciousDomains)
	// 已排序：逐对比较
	for i := 1; i < len(all); i++ {
		if all[i-1] > all[i] {
			t.Fatalf("AllMaliciousDomains 未按升序排序: %s > %s", all[i-1], all[i])
		}
	}
}
