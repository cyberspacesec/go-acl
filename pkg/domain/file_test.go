package domain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberspacesec/acl-skills/pkg/config"
	"github.com/cyberspacesec/acl-skills/pkg/types"
)

// writeTempFile 在临时目录写入内容并返回路径，测试结束自动清理
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	return p
}

func TestNewDomainACLFromFile(t *testing.T) {
	p := writeTempFile(t, "blacklist.txt", "# 域名黑名单\nbad.com\nphish.org # 钓鱼\n\nbad.com\n")
	acl, err := NewDomainACLFromFile(p, types.Blacklist, true)
	if err != nil {
		t.Fatalf("从文件创建域名 ACL 失败: %v", err)
	}
	got := acl.GetDomains()
	// 重复 bad.com 应被去重，注释与空行应被忽略
	if len(got) != 2 {
		t.Fatalf("期望 2 个域名，得到 %d: %v", len(got), got)
	}
	// 子域名应命中
	perm, err := acl.Check("sub.bad.com")
	if err != nil {
		t.Fatalf("Check 失败: %v", err)
	}
	if perm != types.Denied {
		t.Errorf("黑名单子域名应被 Denied，得到 %s", perm)
	}
}

func TestNewDomainACLFromFile_NotExist(t *testing.T) {
	_, err := NewDomainACLFromFile("/no/such/file.txt", types.Blacklist, false)
	if !errors.Is(err, config.ErrFileNotFound) {
		t.Errorf("期望 ErrFileNotFound，得到 %v", err)
	}
}

func TestNewDomainACLFromFile_Empty(t *testing.T) {
	p := writeTempFile(t, "empty.txt", "# 只有注释\n\n")
	_, err := NewDomainACLFromFile(p, types.Blacklist, false)
	if !errors.Is(err, config.ErrEmptyFile) {
		t.Errorf("期望 ErrEmptyFile，得到 %v", err)
	}
}

func TestDomainACL_SaveToFile(t *testing.T) {
	acl := NewDomainACL([]string{"save.com", "keep.org"}, types.Blacklist, true)
	p := filepath.Join(t.TempDir(), "out.txt")
	if err := acl.SaveToFile(p, true); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	// 重新加载应得到等价规则
	loaded, err := NewDomainACLFromFile(p, types.Blacklist, true)
	if err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if len(loaded.GetDomains()) != 2 {
		t.Errorf("回读后规则数期望 2，得到 %d", len(loaded.GetDomains()))
	}
	perm, _ := loaded.Check("x.save.com")
	if perm != types.Denied {
		t.Errorf("回读后子域名应 Denied，得到 %s", perm)
	}
}

func TestDomainACL_SaveToFile_NoOverwrite(t *testing.T) {
	acl := NewDomainACL([]string{"a.com"}, types.Blacklist, false)
	p := writeTempFile(t, "exists.txt", "existing\n")
	err := acl.SaveToFile(p, false) // 不覆盖
	if !errors.Is(err, config.ErrFileExists) {
		t.Errorf("期望 ErrFileExists，得到 %v", err)
	}
}

func TestDomainACL_AddFromFile(t *testing.T) {
	acl := NewDomainACL([]string{"base.com"}, types.Blacklist, false)
	p := writeTempFile(t, "more.txt", "more.com\n# 注释\n")
	if err := acl.AddFromFile(p); err != nil {
		t.Fatalf("AddFromFile 失败: %v", err)
	}
	got := acl.GetDomains()
	if len(got) != 2 {
		t.Fatalf("期望 2 个域名，得到 %d: %v", len(got), got)
	}
}
