package acl

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/ip"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func newBenchManager(n int) *Manager {
	r := rand.New(rand.NewSource(7))
	ranges := make([]string, n)
	for i := 0; i < n; i++ {
		ranges[i] = fmt.Sprintf("%d.%d.%d.%d/%d", r.Intn(223)+1, r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(8)+24)
	}
	m := NewManager()
	m.SetDomainACL([]string{"example.com"}, types.Blacklist, true)
	_ = m.SetIPACL(ranges, types.Blacklist)
	return m
}

func BenchmarkManager_CheckIP(b *testing.B) {
	m := newBenchManager(10000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = m.CheckIP("8.8.8.8")
	}
}

func BenchmarkManager_CheckDomain(b *testing.B) {
	m := newBenchManager(1000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = m.CheckDomain("sub.example.com")
	}
}

// BenchmarkManager_MixedCheck 混合查询 IP 和域名
func BenchmarkManager_MixedCheck(b *testing.B) {
	m := newBenchManager(10000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			_, _ = m.CheckIP("8.8.8.8")
		} else {
			_, _ = m.CheckDomain("sub.example.com")
		}
	}
}

// BenchmarkManager_ConcurrentReadWrite 并发读写混合
func BenchmarkManager_ConcurrentReadWrite(b *testing.B) {
	m := newBenchManager(1000)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%10 == 0 {
				_ = m.AddIP(fmt.Sprintf("203.0.113.%d", i%256))
				_ = m.RemoveIP(fmt.Sprintf("203.0.113.%d", i%256))
			} else {
				_, _ = m.CheckIP("8.8.8.8")
				_, _ = m.CheckDomain("sub.example.com")
			}
			i++
		}
	})
}

// 编译期确保 ip 包仍可用（避免未使用 import）
var _ = ip.PrivateNetworks
