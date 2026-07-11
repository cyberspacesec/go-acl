package domain

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// TestConcurrentReadWrite 验证 DomainACL 在并发读写下的正确性
func TestConcurrentReadWrite(t *testing.T) {
	d := NewDomainACL([]string{"example.com", "test.org"}, types.Blacklist, true)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				dom := fmt.Sprintf("sub%d.example.com", n)
				_, _ = d.Check(dom)
				_ = d.GetDomains()
				_ = d.GetListType()
			}
		}(i)
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				dom := fmt.Sprintf("dynamic%d-%d.com", n, j)
				_ = d.Add(dom)
				_ = d.Remove(dom)
			}
		}(i)
	}
	wg.Wait()
}

func TestConcurrentCheckConsistency(t *testing.T) {
	d := NewDomainACL([]string{"example.com"}, types.Blacklist, true)

	const goroutines = 50
	const iterations = 200
	var wg sync.WaitGroup
	results := make([]types.Permission, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				perm, err := d.Check("api.sub.example.com")
				if err != nil {
					t.Errorf("Check 返回错误: %v", err)
					return
				}
				results[idx] = perm
			}
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		if r != types.Denied {
			t.Errorf("goroutine %d 结果不一致: 期望 Denied, 实际 %s", i, r)
		}
	}
}
