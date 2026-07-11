package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicyFromBytes_Both(t *testing.T) {
	data := []byte(`{
		"domain": {
			"domains": ["bad.com", "phish.org"],
			"listType": "blacklist",
			"includeSubdomains": true
		},
		"ip": {
			"ranges": ["10.0.0.0/8"],
			"listType": "blacklist",
			"predefinedSets": ["private_networks"],
			"allowPredefined": false
		}
	}`)
	p, err := LoadPolicyFromBytes(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.Domain == nil || len(p.Domain.Domains) != 2 {
		t.Fatalf("域名解析异常: %+v", p.Domain)
	}
	if p.Domain.ListType != "blacklist" || !p.Domain.IncludeSubdomains {
		t.Errorf("域名字段解析错误: %+v", p.Domain)
	}
	if p.IP == nil || len(p.IP.Ranges) != 1 || p.IP.ListType != "blacklist" {
		t.Fatalf("IP 解析异常: %+v", p.IP)
	}
	if len(p.IP.PredefinedSets) != 1 || p.IP.PredefinedSets[0] != "private_networks" {
		t.Errorf("预定义集合解析错误: %+v", p.IP)
	}
}

func TestLoadPolicyFromBytes_DomainOnly(t *testing.T) {
	data := []byte(`{"domain":{"domains":["a.com"],"listType":"whitelist"}}`)
	p, err := LoadPolicyFromBytes(data)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if p.Domain == nil || p.IP != nil {
		t.Errorf("应只配置域名，得到 domain=%v ip=%v", p.Domain, p.IP)
	}
}

func TestLoadPolicyFromBytes_InvalidJSON(t *testing.T) {
	_, err := LoadPolicyFromBytes([]byte(`{not json`))
	if err == nil {
		t.Fatal("非法 JSON 应返回错误")
	}
}

func TestLoadPolicyFromFile_NotExist(t *testing.T) {
	_, err := LoadPolicyFromFile("/no/such/policy.json")
	if !errors.Is(err, ErrFileNotFound) {
		t.Errorf("期望 ErrFileNotFound，得到 %v", err)
	}
}

func TestLoadPolicyFromFile_OK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.json")
	content := `{"ip":{"ranges":["8.8.8.8"],"listType":"whitelist"}}`
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	pol, err := LoadPolicyFromFile(p)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if pol.IP == nil || len(pol.IP.Ranges) != 1 || pol.IP.Ranges[0] != "8.8.8.8" {
		t.Errorf("IP 解析异常: %+v", pol.IP)
	}
}
