// Package aclutil 提供访问控制列表实现共用的通用辅助函数
package aclutil

// AppendUnique 将 candidates 中不存在于 rules 的元素去重追加到 rules
//
// 该函数用于消除各 ACL 实现中 Add 方法的去重样板代码。
// 它基于一个临时 set 判重，保持 rules 中已有元素的顺序不变，
// candidates 中后续重复的元素也只追加一次。
//
// 参数:
//   - rules: 已有的规则列表（不会被原地修改，函数返回新切片）
//   - candidates: 待追加的候选规则
//
// 返回:
//   - []string: 追加去重后的新列表
func AppendUnique(rules []string, candidates []string) []string {
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		seen[r] = struct{}{}
	}

	result := make([]string, len(rules), len(rules)+len(candidates))
	copy(result, rules)

	for _, c := range candidates {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		result = append(result, c)
	}

	return result
}

// RemoveMatching 从 rules 中移除所有命中 toRemove 的元素，并返回缺失项
//
// 返回:
//   - newRules: 移除后的新列表
//   - missing: 在 toRemove 中但未在 rules 中找到的元素
//
// 调用方可据此决定是否返回「未找到」错误。toRemove 中的空串被忽略。
func RemoveMatching(rules []string, toRemove []string) (newRules []string, missing []string) {
	removeSet := make(map[string]struct{}, len(toRemove))
	for _, r := range toRemove {
		if r == "" {
			continue
		}
		removeSet[r] = struct{}{}
	}

	result := make([]string, 0, len(rules))
	for _, r := range rules {
		if _, drop := removeSet[r]; drop {
			continue
		}
		result = append(result, r)
	}

	// 计算 missing：toRemove 中未在 rules 出现的项
	ruleSet := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		ruleSet[r] = struct{}{}
	}
	for r := range removeSet {
		if _, ok := ruleSet[r]; !ok {
			missing = append(missing, r)
		}
	}

	return result, missing
}
