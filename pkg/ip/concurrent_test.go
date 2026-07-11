package ip

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// TestConcurrentReadWrite 验证 IPACL 在并发读写下的正确性
// 配合 -race 检测数据竞争；底层加锁后应无竞争且结果一致。
func TestConcurrentReadWrite(t *testing.T) {
	a, err := NewIPACL([]string{"10.0.0.0/8", "192.168.1.1"}, types.Blacklist)
	if err != nil {
		t.Fatalf("NewIPACL 失败: %v", err)
	}

	var wg sync.WaitGroup
	// 10 个并发读 + 5 个并发写
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				ipStr := fmt.Sprintf("10.%d.%d.%d", n%256, j%256, (j*2)%256)
				_, _ = a.Check(ipStr)
				_ = a.GetIPRanges()
				_ = a.GetListType()
			}
		}(i)
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = a.Add(fmt.Sprintf("172.16.%d.%d", n, j))
				_ = a.Remove(fmt.Sprintf("172.16.%d.%d", n, j))
			}
		}(i)
	}
	wg.Wait()
}

// TestConcurrentCheckConsistency 并发 Check 同一 IP，结果应稳定一致
func TestConcurrentCheckConsistency(t *testing.T) {
	a, err := NewIPACL([]string{"10.0.0.0/8"}, types.Blacklist)
	if err != nil {
		t.Fatalf("NewIPACL 失败: %v", err)
	}

	const goroutines = 50
	const iterations = 200
	var wg sync.WaitGroup
	results := make([]types.Permission, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				perm, err := a.Check("10.1.2.3")
				if err != nil {
					t.Errorf("Check 返回错误: %v", err)
					return
				}
				results[idx] = perm
			}
		}(i)
	}
	wg.Wait()

	// 10.1.2.3 始终命中 10.0.0.0/8，黑名单应始终 Denied
	for i, r := range results {
		if r != types.Denied {
			t.Errorf("goroutine %d 结果不一致: 期望 Denied, 实际 %s", i, r)
		}
	}
}
