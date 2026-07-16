package types

import (
	"errors"
	"testing"
)

func TestSentinelErrors_Identity(t *testing.T) {
	// 确保哨兵错误可被 errors.Is 识别
	if !errors.Is(ErrNoACL, ErrNoACL) {
		t.Error("ErrNoACL 应可被 errors.Is 识别")
	}
	if !errors.Is(ErrACLAlreadyRegistered, ErrACLAlreadyRegistered) {
		t.Error("ErrACLAlreadyRegistered 应可被 errors.Is 识别")
	}
	if errors.Is(ErrNoACL, ErrACLAlreadyRegistered) {
		t.Error("不同哨兵错误不应互等")
	}
}

func TestDecideByListType(t *testing.T) {
	// 黑名单：命中→拒绝，未命中→允许
	if got := DecideByListType(Blacklist, true); got != Denied {
		t.Errorf("黑名单命中应拒绝，got %v", got)
	}
	if got := DecideByListType(Blacklist, false); got != Allowed {
		t.Errorf("黑名单未命中应允许，got %v", got)
	}
	// 白名单：命中→允许，未命中→拒绝
	if got := DecideByListType(Whitelist, true); got != Allowed {
		t.Errorf("白名单命中应允许，got %v", got)
	}
	if got := DecideByListType(Whitelist, false); got != Denied {
		t.Errorf("白名单未命中应拒绝，got %v", got)
	}
}
