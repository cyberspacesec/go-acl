package types

import "testing"

// TestListType_String 测试ListType的String方法
func TestListType_String(t *testing.T) {
	tests := []struct {
		name     string
		listType ListType
		want     string
	}{
		{
			name:     "黑名单",
			listType: Blacklist,
			want:     "blacklist",
		},
		{
			name:     "白名单",
			listType: Whitelist,
			want:     "whitelist",
		},
		{
			name:     "未知列表类型",
			listType: 99, // 无效的列表类型
			want:     "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.listType.String()
			if got != tt.want {
				t.Errorf("ListType(%d).String() = %v, want %v", tt.listType, got, tt.want)
			}
		})
	}
}

// TestPermission_String 测试Permission的String方法
func TestPermission_String(t *testing.T) {
	tests := []struct {
		name       string
		permission Permission
		want       string
	}{
		{
			name:       "拒绝访问",
			permission: Denied,
			want:       "denied",
		},
		{
			name:       "允许访问",
			permission: Allowed,
			want:       "allowed",
		},
		{
			name:       "未知权限",
			permission: 99, // 无效的权限类型
			want:       "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.permission.String()
			if got != tt.want {
				t.Errorf("Permission(%d).String() = %v, want %v", tt.permission, got, tt.want)
			}
		})
	}
}
