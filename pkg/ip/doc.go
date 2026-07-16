// Package ip 实现 IP 维度的访问控制列表。
//
// IPACL 基于 IPv4/IPv6 双前缀 trie（ipTrie）实现 O(prefixLen) 匹配，
// 与规则数无关，支持 IPv4/IPv6/CIDR/区间/zone id 剥离。
//
// 区间语法 a-b 用 math/big 展开为覆盖 [a,b] 的最少不重叠 CIDR，
// 彻底避免 IPv6 巨区间下 int/uint64 溢出。
//
// Lookup 返回最长前缀匹配 CIDR，便于规则反查与审计。
package ip
