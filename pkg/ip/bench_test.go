package ip

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// genIPv4Ranges 生成 n 个随机 IPv4 CIDR 用于基准测试
func genIPv4Ranges(n int) []string {
	r := rand.New(rand.NewSource(42))
	ranges := make([]string, n)
	for i := 0; i < n; i++ {
		ranges[i] = fmt.Sprintf("%d.%d.%d.%d/%d", r.Intn(223)+1, r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(8)+24)
	}
	return ranges
}

func benchIPACLCheck(b *testing.B, n int) {
	ranges := genIPv4Ranges(n)
	a, err := NewIPACL(ranges, types.Blacklist)
	if err != nil {
		b.Fatalf("NewIPACL 失败: %v", err)
	}
	// 一个确定命中的 IP（落在第一个 /24 内）
	probe := incIP(ranges[0])

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = a.Check(probe)
	}
}

func BenchmarkIPACL_Check_Scale100(b *testing.B)   { benchIPACLCheck(b, 100) }
func BenchmarkIPACL_Check_Scale1000(b *testing.B)  { benchIPACLCheck(b, 1000) }
func BenchmarkIPACL_Check_Scale10000(b *testing.B) { benchIPACLCheck(b, 10000) }

// BenchmarkIPACL_CheckParallel 并发 Check 吞吐
func BenchmarkIPACL_CheckParallel(b *testing.B) {
	ranges := genIPv4Ranges(10000)
	a, err := NewIPACL(ranges, types.Blacklist)
	if err != nil {
		b.Fatalf("NewIPACL 失败: %v", err)
	}
	probe := incIP(ranges[0])

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = a.Check(probe)
		}
	})
}

// BenchmarkIPACL_Add 单次 Add 一个新 CIDR
func BenchmarkIPACL_Add(b *testing.B) {
	ranges := genIPv4Ranges(b.N + 10)
	a, _ := NewIPACL(nil, types.Blacklist)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = a.Add(ranges[i])
	}
}

// BenchmarkIPACL_Remove 单次 Remove
func BenchmarkIPACL_Remove(b *testing.B) {
	ranges := genIPv4Ranges(b.N + 10)
	a, _ := NewIPACL(ranges, types.Blacklist)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = a.Remove(ranges[i])
	}
}

// incIP 返回 CIDR 内的下一个 IP 字符串，用于构造命中探针
func incIP(cidr string) string {
	ip, _, _ := net.ParseCIDR(cidr)
	next := ip.To4()
	next[3]++
	return next.String()
}
