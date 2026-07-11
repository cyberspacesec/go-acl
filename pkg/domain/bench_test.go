package domain

import (
	"fmt"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/types"
)

func genDomains(n int) []string {
	domains := make([]string, n)
	for i := 0; i < n; i++ {
		domains[i] = fmt.Sprintf("site-%d.example.com", i)
	}
	return domains
}

func benchDomainCheck(b *testing.B, n int, subdomains bool) {
	domains := genDomains(n)
	d := NewDomainACL(domains, types.Blacklist, subdomains)
	probe := domains[n/2]

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = d.Check(probe)
	}
}

func BenchmarkDomainACL_Check_Exact_Scale100(b *testing.B)   { benchDomainCheck(b, 100, false) }
func BenchmarkDomainACL_Check_Exact_Scale1000(b *testing.B)  { benchDomainCheck(b, 1000, false) }
func BenchmarkDomainACL_Check_Exact_Scale10000(b *testing.B) { benchDomainCheck(b, 10000, false) }

func BenchmarkDomainACL_Check_Sub_Scale100(b *testing.B)   { benchDomainCheck(b, 100, true) }
func BenchmarkDomainACL_Check_Sub_Scale1000(b *testing.B)  { benchDomainCheck(b, 1000, true) }
func BenchmarkDomainACL_Check_Sub_Scale10000(b *testing.B) { benchDomainCheck(b, 10000, true) }

func BenchmarkDomainACL_CheckParallel(b *testing.B) {
	domains := genDomains(10000)
	d := NewDomainACL(domains, types.Blacklist, false)
	probe := domains[0]

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = d.Check(probe)
		}
	})
}

func BenchmarkDomainACL_Add(b *testing.B) {
	domains := genDomains(b.N + 10)
	d := NewDomainACL(nil, types.Blacklist, false)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = d.Add(domains[i])
	}
}

func BenchmarkDomainACL_Remove(b *testing.B) {
	domains := genDomains(b.N + 10)
	d := NewDomainACL(domains, types.Blacklist, false)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = d.Remove(domains[i])
	}
}
