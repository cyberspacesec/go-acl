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

func parseCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%s): %v", s, err)
	}
	return n
}
