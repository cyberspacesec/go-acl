package ip

import (
	"net"
	"testing"
)

func TestTrieLookup_LongestPrefix(t *testing.T) {
	tr := newIPTrie()
	// 插入 10.0.0.0/8 与 10.1.0.0/16，10.1.2.3 应匹配更具体的 /16
	tr.Insert(parseCIDR(t, "10.0.0.0/8"))
	tr.Insert(parseCIDR(t, "10.1.0.0/16"))

	got := tr.Lookup(net.ParseIP("10.1.2.3"))
	if got == nil || got.String() != "10.1.0.0/16" {
		t.Fatalf("期望 10.1.0.0/16，得到 %v", got)
	}
	// 10.2.0.1 仅匹配 /8
	got = tr.Lookup(net.ParseIP("10.2.0.1"))
	if got == nil || got.String() != "10.0.0.0/8" {
		t.Fatalf("期望 10.0.0.0/8，得到 %v", got)
	}
	// 192.168.0.1 无匹配
	got = tr.Lookup(net.ParseIP("192.168.0.1"))
	if got != nil {
		t.Fatalf("期望 nil，得到 %v", got)
	}
}

func TestTrieLookup_IPv6(t *testing.T) {
	tr := newIPTrie()
	tr.Insert(parseCIDR(t, "2001:db8::/32"))
	got := tr.Lookup(net.ParseIP("2001:db8::1"))
	if got == nil || got.String() != "2001:db8::/32" {
		t.Fatalf("期望 2001:db8::/32，得到 %v", got)
	}
}

// TestTrieLookup_IPv6LongestPrefix 验证 IPv6 重叠 CIDR 的最长前缀选择
func TestTrieLookup_IPv6LongestPrefix(t *testing.T) {
	tr := newIPTrie()
	tr.Insert(parseCIDR(t, "2001:db8::/32"))
	tr.Insert(parseCIDR(t, "2001:db8:1::/48"))
	// 2001:db8:1::1 同时落在 /32 与 /48 内，应返回更具体的 /48
	got := tr.Lookup(net.ParseIP("2001:db8:1::1"))
	if got == nil || got.String() != "2001:db8:1::/48" {
		t.Fatalf("期望 2001:db8:1::/48，得到 %v", got)
	}
	// 2001:db8:2::1 仅落在 /32 内
	got = tr.Lookup(net.ParseIP("2001:db8:2::1"))
	if got == nil || got.String() != "2001:db8::/32" {
		t.Fatalf("期望 2001:db8::/32，得到 %v", got)
	}
}

// TestTrieLookup_Boundaries 验证空 trie、/0、/32 精确命中等边界
func TestTrieLookup_Boundaries(t *testing.T) {
	// 空 trie 任何 IP 都返回 nil
	empty := newIPTrie()
	if got := empty.Lookup(net.ParseIP("10.0.0.1")); got != nil {
		t.Fatalf("空 trie 应返回 nil，得到 %v", got)
	}

	// /0 匹配任意 IPv4
	tr0 := newIPTrie()
	tr0.Insert(parseCIDR(t, "0.0.0.0/0"))
	got := tr0.Lookup(net.ParseIP("203.0.113.5"))
	if got == nil || got.String() != "0.0.0.0/0" {
		t.Fatalf("期望 0.0.0.0/0，得到 %v", got)
	}

	// /32 精确命中
	tr32 := newIPTrie()
	tr32.Insert(parseCIDR(t, "10.1.2.3/32"))
	got = tr32.Lookup(net.ParseIP("10.1.2.3"))
	if got == nil || got.String() != "10.1.2.3/32" {
		t.Fatalf("期望 10.1.2.3/32，得到 %v", got)
	}
	// 相邻地址不命中
	got = tr32.Lookup(net.ParseIP("10.1.2.4"))
	if got != nil {
		t.Fatalf("10.1.2.4 不应命中 /32，得到 %v", got)
	}
}

func parseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%s): %v", s, err)
	}
	return n
}
