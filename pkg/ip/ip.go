package ip

import (
	"errors"
	"net"
	"strings"

	"github.com/cyberspacesec/go-acl/pkg/types"
)

var (
	// ErrInvalidIP 表示提供的IP地址格式无效
	ErrInvalidIP = errors.New("invalid IP format")
	// ErrInvalidCIDR 表示提供的CIDR格式无效
	ErrInvalidCIDR = errors.New("invalid CIDR format")
	// ErrInvalidPredefinedSet 表示提供的预定义集合名称无效
	ErrInvalidPredefinedSet = errors.New("invalid predefined IP set name")
	// ErrIPNotFound 表示要移除的IP或CIDR不在ACL中
	ErrIPNotFound = errors.New("IP or CIDR not found in ACL")
)

// IPRange 表示IP地址范围
type IPRange struct {
	// 网络和掩码
	Network *net.IPNet
	// 原始表示，用于展示
	Original string
}

// IPAcl 实现了对IP地址的访问控制
type IPAcl struct {
	// ipRanges 存储控制的IP范围列表
	ipRanges []*IPRange
	// listType 标识这是黑名单还是白名单
	listType types.ListType
}

// NewIPAcl 创建一个新的IP访问控制列表
func NewIPAcl(ipRanges []string, listType types.ListType) (*IPAcl, error) {
	acl := &IPAcl{
		ipRanges: make([]*IPRange, 0, len(ipRanges)),
		listType: listType,
	}

	// 解析每个IP范围
	for _, ipRange := range ipRanges {
		ipRange = strings.TrimSpace(ipRange)
		if ipRange == "" {
			continue
		}

		// 如果是CIDR格式
		if strings.Contains(ipRange, "/") {
			_, network, err := net.ParseCIDR(ipRange)
			if err != nil {
				return nil, errors.Join(ErrInvalidCIDR, err)
			}
			acl.ipRanges = append(acl.ipRanges, &IPRange{
				Network:  network,
				Original: ipRange,
			})
		} else {
			// 单个IP地址需要转换为CIDR格式
			ip := net.ParseIP(ipRange)
			if ip == nil {
				return nil, ErrInvalidIP
			}

			var mask net.IPMask
			if ip.To4() != nil {
				// IPv4: /32
				mask = net.CIDRMask(32, 32)
			} else {
				// IPv6: /128
				mask = net.CIDRMask(128, 128)
			}

			network := &net.IPNet{
				IP:   ip,
				Mask: mask,
			}
			acl.ipRanges = append(acl.ipRanges, &IPRange{
				Network:  network,
				Original: ipRange,
			})
		}
	}

	return acl, nil
}

// NewIPAclWithDefaults 创建一个新的IP访问控制列表，同时加入预定义的安全IP集合
// 预定义集合将被加入到黑名单中以增强安全性，除非指定为allowDefaultSets=true
func NewIPAclWithDefaults(ipRanges []string, listType types.ListType, predefinedSets []PredefinedSet, allowDefaultSets bool) (*IPAcl, error) {
	// 首先创建基本的ACL
	acl, err := NewIPAcl(ipRanges, listType)
	if err != nil {
		return nil, err
	}

	// 添加指定的预定义集合
	for _, setName := range predefinedSets {
		if err := acl.AddPredefinedSet(setName, allowDefaultSets); err != nil {
			return nil, err
		}
	}

	return acl, nil
}

// AddPredefinedSet 添加一个预定义的IP集合到访问控制列表中
// allowSet参数决定是将集合添加为允许的范围还是拒绝的范围
// 如果ACL是黑名单模式，且allowSet=false，则集合会被添加到黑名单中
// 如果ACL是白名单模式，且allowSet=true，则集合会被添加到白名单中
func (i *IPAcl) AddPredefinedSet(setName PredefinedSet, allowSet bool) error {
	// 获取预定义集合
	ranges := GetPredefinedIPRanges(setName)
	if ranges == nil {
		return ErrInvalidPredefinedSet
	}

	// 如果当前ACL是黑名单模式且不允许这些IP，或者当前是白名单模式且允许这些IP，才添加
	// 这确保了集合的添加符合ACL的类型和预期行为
	shouldAdd := (i.listType == types.Blacklist && !allowSet) || (i.listType == types.Whitelist && allowSet)

	if shouldAdd {
		// 添加每个IP范围
		for _, ipRange := range ranges {
			_, network, err := net.ParseCIDR(ipRange)
			if err != nil {
				return errors.Join(ErrInvalidCIDR, err)
			}
			i.ipRanges = append(i.ipRanges, &IPRange{
				Network:  network,
				Original: ipRange,
			})
		}
	}

	return nil
}

// Add 添加一个或多个IP或CIDR到访问控制列表
func (i *IPAcl) Add(ipRanges ...string) error {
	for _, ipRange := range ipRanges {
		ipRange = strings.TrimSpace(ipRange)
		if ipRange == "" {
			continue
		}

		// 如果是CIDR格式
		if strings.Contains(ipRange, "/") {
			_, network, err := net.ParseCIDR(ipRange)
			if err != nil {
				return errors.Join(ErrInvalidCIDR, err)
			}
			i.ipRanges = append(i.ipRanges, &IPRange{
				Network:  network,
				Original: ipRange,
			})
		} else {
			// 单个IP地址需要转换为CIDR格式
			ip := net.ParseIP(ipRange)
			if ip == nil {
				return ErrInvalidIP
			}

			var mask net.IPMask
			if ip.To4() != nil {
				// IPv4: /32
				mask = net.CIDRMask(32, 32)
			} else {
				// IPv6: /128
				mask = net.CIDRMask(128, 128)
			}

			network := &net.IPNet{
				IP:   ip,
				Mask: mask,
			}
			i.ipRanges = append(i.ipRanges, &IPRange{
				Network:  network,
				Original: ipRange,
			})
		}
	}

	return nil
}

// Remove 从访问控制列表中移除一个或多个IP或CIDR
// 如果指定的IP或CIDR不在列表中，将返回ErrIPNotFound错误
func (i *IPAcl) Remove(ipRanges ...string) error {
	if len(ipRanges) == 0 {
		return nil
	}

	for _, ipRange := range ipRanges {
		ipRange = strings.TrimSpace(ipRange)
		if ipRange == "" {
			continue
		}

		// 标记是否找到并移除了条目
		found := false

		// 遍历现有规则，找到匹配项并移除
		for idx, existing := range i.ipRanges {
			if existing.Original == ipRange {
				// 找到匹配，移除该元素
				i.ipRanges = append(i.ipRanges[:idx], i.ipRanges[idx+1:]...)
				found = true
				break
			}
		}

		// 如果没有找到匹配项，则返回错误
		if !found {
			return ErrIPNotFound
		}
	}

	return nil
}

// Check 检查给定的IP地址是否允许访问
func (i *IPAcl) Check(ipStr string) (types.Permission, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return types.Denied, ErrInvalidIP
	}

	// 检查IP是否在任何范围内
	found := i.matchIP(ip)

	// 根据列表类型和匹配结果确定权限
	if i.listType == types.Blacklist {
		if found {
			return types.Denied, nil
		}
		return types.Allowed, nil
	} else { // 白名单
		if found {
			return types.Allowed, nil
		}
		return types.Denied, nil
	}
}

// matchIP 检查IP是否匹配任何IP范围
func (i *IPAcl) matchIP(ip net.IP) bool {
	for _, ipRange := range i.ipRanges {
		if ipRange.Network.Contains(ip) {
			return true
		}
	}
	return false
}

// GetIPRanges 返回当前ACL中的所有IP范围
func (i *IPAcl) GetIPRanges() []string {
	ranges := make([]string, 0, len(i.ipRanges))
	for _, r := range i.ipRanges {
		ranges = append(ranges, r.Original)
	}
	return ranges
}

// GetListType 返回当前ACL的列表类型（黑名单或白名单）
func (i *IPAcl) GetListType() types.ListType {
	return i.listType
}
