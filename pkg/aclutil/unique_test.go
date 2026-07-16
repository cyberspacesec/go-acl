package aclutil

import (
	"reflect"
	"sort"
	"testing"
)

func TestAppendUnique_NewAndExisting(t *testing.T) {
	rules := []string{"a", "b"}
	got := AppendUnique(rules, []string{"b", "c"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AppendUnique 去重追加 = %v, want %v", got, want)
	}
}

func TestAppendUnique_EmptyInputs(t *testing.T) {
	got := AppendUnique(nil, nil)
	if len(got) != 0 {
		t.Errorf("空输入应返回空切片，got %v", got)
	}
	got = AppendUnique([]string{"x"}, []string{})
	if !reflect.DeepEqual(got, []string{"x"}) {
		t.Errorf("空候选应原样返回，got %v", got)
	}
}

func TestAppendUnique_CandidateDedupSelf(t *testing.T) {
	// candidates 内部自身重复也只追加一次
	got := AppendUnique([]string{"a"}, []string{"b", "b", "b"})
	want := []string{"a", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("candidates 自身去重 = %v, want %v", got, want)
	}
}

func TestAppendUnique_DoesNotMutateInput(t *testing.T) {
	rules := []string{"a", "b"}
	_ = AppendUnique(rules, []string{"c"})
	// 原 rules 切片不应被修改
	if !reflect.DeepEqual(rules, []string{"a", "b"}) {
		t.Errorf("AppendUnique 不应修改输入切片，got %v", rules)
	}
}

func TestRemoveMatching_AllFound(t *testing.T) {
	rules := []string{"a", "b", "c"}
	newRules, missing := RemoveMatching(rules, []string{"a", "c"})
	if !reflect.DeepEqual(newRules, []string{"b"}) {
		t.Errorf("移除后剩余 = %v, want [b]", newRules)
	}
	if len(missing) != 0 {
		t.Errorf("全部命中不应有 missing，got %v", missing)
	}
}

func TestRemoveMatching_PartialMissing(t *testing.T) {
	rules := []string{"a", "b"}
	newRules, missing := RemoveMatching(rules, []string{"b", "z"})
	if !reflect.DeepEqual(newRules, []string{"a"}) {
		t.Errorf("移除后剩余 = %v, want [a]", newRules)
	}
	// missing 来自 map 遍历，顺序不定，排序后比较
	sort.Strings(missing)
	if !reflect.DeepEqual(missing, []string{"z"}) {
		t.Errorf("未命中应记录 = %v, want [z]", missing)
	}
}

func TestRemoveMatching_EmptyStringIgnored(t *testing.T) {
	rules := []string{"a", "b"}
	newRules, missing := RemoveMatching(rules, []string{"", "a"})
	if !reflect.DeepEqual(newRules, []string{"b"}) {
		t.Errorf("空串应被忽略，移除后剩余 = %v, want [b]", newRules)
	}
	// 空串被忽略，不应出现在 missing
	for _, m := range missing {
		if m == "" {
			t.Error("空串不应出现在 missing 中")
		}
	}
}
