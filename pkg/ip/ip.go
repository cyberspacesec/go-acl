package ip

import (
	"errors"
	"net"
	"strings"

	"github.com/cyberspacesec/go-acl/pkg/types"
)

// 错误定义
var (
	// ErrInvalidIP 表示提供的IP格式无效
	ErrInvalidIP = errors.New("无效的IP地址格式")
	// ErrInvalidCIDR 表示提供的CIDR格式无效
	ErrInvalidCIDR = errors.New("无效的CIDR格式")
	// ErrIPNotFound 表示要操作的IP不在访问控制列表中
	ErrIPNotFound = errors.New("IP不在列表中")
	// ErrInvalidPredefinedSet 表示请求的预定义IP集合不存在
	ErrInvalidPredefinedSet = errors.New("无效的预定义IP集合")
)

// IPRange 表示一个IP范围，可以是单个IP或CIDR
//
// IPRange 包含:
//   - Original: 原始输入的IP/CIDR字符串
//   - IP: 解析后的IP地址
//   - IPNet: 对于CIDR，表示网络范围；对于单个IP，表示包含单个IP的网络
//
// 该结构体支持IPv4和IPv6地址。
type IPRange struct {
	Original string     // 原始输入的IP/CIDR字符串
	IP       net.IP     // 解析后的IP地址
	IPNet    *net.IPNet // 网络范围
}

// IPAcl 实现了IP访问控制列表
//
// 支持黑名单和白名单两种模式，可以控制单个IP和CIDR网段。
// 支持IPv4和IPv6地址，以及预定义的IP集合（如私有网络、云元数据等）。
//
// 用法示例:
//
//	// 创建一个IP黑名单
//	blacklist, err := ip.NewIPAcl(
//	    []string{"192.168.1.0/24", "10.0.0.1"},
//	    types.Blacklist
//	)
//
//	// 创建一个IP白名单
//	whitelist, err := ip.NewIPAcl(
//	    []string{"8.8.8.8", "1.1.1.1"},
//	    types.Whitelist
//	)
//
//	// 检查IP访问权限
//	perm, err := blacklist.Check("192.168.1.5") // 返回 types.Denied
//	perm, err := whitelist.Check("8.8.8.8")     // 返回 types.Allowed
type IPAcl struct {
	ranges   []IPRange
	listType types.ListType
}

// NewIPAcl 创建一个新的IP访问控制列表
//
// 参数:
//   - ipRanges: 要控制的IP或CIDR列表
//     例如: []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
//   - listType: 列表类型（黑名单或白名单）
//     可用值: types.Blacklist（黑名单）或 types.Whitelist（白名单）
//
// 返回:
//   - *IPAcl: 创建的IP访问控制列表，成功时非nil
//   - error: 可能的错误:
//   - ErrInvalidIP: 提供了无效的IP地址格式
//   - ErrInvalidCIDR: 提供了无效的CIDR格式
//
// 该函数会验证所有输入的IP/CIDR格式。如果任何一个输入无效，将返回相应的错误。
// 空字符串和空参数列表将被忽略，不会导致错误。
//
// 示例:
//
//	// 创建IP黑名单
//	blacklist, err := ip.NewIPAcl(
//	    []string{
//	        "192.168.1.1",    // 单个IPv4地址
//	        "10.0.0.0/8",     // IPv4 CIDR
//	        "2001:db8::/32",  // IPv6 CIDR
//	    },
//	    types.Blacklist
//	)
//	if err != nil {
//	    log.Printf("创建IP ACL失败: %v", err)
//	    return
//	}
//
//	// 创建IP白名单
//	whitelist, err := ip.NewIPAcl(
//	    []string{"8.8.8.8", "1.1.1.1"},
//	    types.Whitelist
//	)
func NewIPAcl(ipRanges []string, listType types.ListType) (*IPAcl, error) {
	acl := &IPAcl{
		listType: listType,
	}

	// 如果没有输入IP，返回空ACL
	if len(ipRanges) == 0 {
		return acl, nil
	}

	// 解析和验证每个IP或CIDR
	for _, ipStr := range ipRanges {
		// 忽略空字符串
		if strings.TrimSpace(ipStr) == "" {
			continue
		}

		ipRange, err := parseIPRange(ipStr)
		if err != nil {
			return nil, err
		}

		acl.ranges = append(acl.ranges, *ipRange)
	}

	return acl, nil
}

// Add 添加一个或多个IP或CIDR到访问控制列表
//
// 参数:
//   - ipRanges: 要添加的一个或多个IP或CIDR
//     例如: "192.168.1.1", "10.0.0.0/8", "2001:db8::/32"
//
// 返回:
//   - error: 可能的错误:
//   - ErrInvalidIP: 提供了无效的IP地址格式
//   - ErrInvalidCIDR: 提供了无效的CIDR格式
//
// 该方法允许向现有访问控制列表添加更多IP或CIDR。空字符串将被忽略，不会导致错误。
// 重复添加相同的IP/CIDR不会产生错误，但IP只会被添加一次。
//
// 示例:
//
//	// 创建IP黑名单
//	acl, _ := ip.NewIPAcl([]string{"192.168.1.1"}, types.Blacklist)
//
//	// 添加单个IP
//	err := acl.Add("10.0.0.1")
//	if err != nil {
//	    log.Printf("添加IP失败: %v", err)
//	}
//
//	// 添加多个IP和CIDR
//	err = acl.Add("172.16.0.0/12", "8.8.8.8", "2001:db8::/32")
//	if err != nil {
//	    log.Printf("添加多个IP失败: %v", err)
//	}
func (a *IPAcl) Add(ipRanges ...string) error {
	// 如果没有输入IP，直接返回
	if len(ipRanges) == 0 {
		return nil
	}

	// 解析和验证每个IP或CIDR
	for _, ipStr := range ipRanges {
		// 忽略空字符串
		if strings.TrimSpace(ipStr) == "" {
			continue
		}

		// 解析IP/CIDR
		ipRange, err := parseIPRange(ipStr)
		if err != nil {
			return err
		}

		// 检查是否已存在
		exists := false
		for _, existingRange := range a.ranges {
			if existingRange.Original == ipRange.Original {
				exists = true
				break
			}
		}

		// 添加新的IP/CIDR
		if !exists {
			a.ranges = append(a.ranges, *ipRange)
		}
	}

	return nil
}

// Remove 从访问控制列表移除一个或多个IP或CIDR
//
// 参数:
//   - ipRanges: 要移除的一个或多个IP或CIDR
//     例如: "192.168.1.1", "10.0.0.0/8", "2001:db8::/32"
//
// 返回:
//   - error: 可能的错误:
//   - ErrIPNotFound: 要移除的IP不在列表中
//
// 该方法使用原始字符串进行匹配，因此要确保使用与添加时完全相同的格式。
// 如果任何一个IP不在列表中，将返回ErrIPNotFound错误，但在列表中的部分仍然会被移除。
//
// 示例:
//
//	// 创建包含多个IP的黑名单
//	acl, _ := ip.NewIPAcl(
//	    []string{"192.168.1.1", "10.0.0.0/8", "8.8.8.8"},
//	    types.Blacklist
//	)
//
//	// 移除单个IP
//	err := acl.Remove("8.8.8.8")
//	if err != nil {
//	    log.Printf("移除IP失败: %v", err)
//	}
//
//	// 移除多个IP
//	err = acl.Remove("192.168.1.1", "10.0.0.0/8")
//	if err != nil {
//	    log.Printf("移除多个IP失败: %v", err)
//	}
//
//	// 尝试移除不存在的IP
//	err = acl.Remove("1.1.1.1")
//	if errors.Is(err, ip.ErrIPNotFound) {
//	    log.Println("IP不在列表中")
//	}
func (a *IPAcl) Remove(ipRanges ...string) error {
	if len(ipRanges) == 0 || len(a.ranges) == 0 {
		return ErrIPNotFound
	}

	// 跟踪是否找到所有要移除的IP
	found := make(map[string]bool, len(ipRanges))
	for _, ipStr := range ipRanges {
		found[ipStr] = false
	}

	// 创建新的IP范围列表，排除要移除的
	var newRanges []IPRange
	for _, existingRange := range a.ranges {
		keep := true
		for ipStr := range found {
			if existingRange.Original == ipStr {
				found[ipStr] = true
				keep = false
				break
			}
		}
		if keep {
			newRanges = append(newRanges, existingRange)
		}
	}

	// 检查是否所有IP都找到了
	for ipStr, wasFound := range found {
		if !wasFound && strings.TrimSpace(ipStr) != "" {
			// 虽然有未找到的IP，但仍更新列表
			a.ranges = newRanges
			return ErrIPNotFound
		}
	}

	// 更新IPAcl使用新的范围
	a.ranges = newRanges
	return nil
}

// Check 检查指定的IP是否允许访问
//
// 参数:
//   - ip: 要检查的IP地址
//     例如: "192.168.1.1", "8.8.8.8", "2001:db8::1"
//
// 返回:
//   - types.Permission: 访问权限
//   - types.Allowed: 允许访问
//   - types.Denied: 拒绝访问
//   - error: 可能的错误:
//   - ErrInvalidIP: 提供了无效的IP地址格式
//
// 检查逻辑:
// - 对于黑名单: 如果IP匹配列表中的任何IP或CIDR范围，返回types.Denied，否则返回types.Allowed
// - 对于白名单: 如果IP匹配列表中的任何IP或CIDR范围，返回types.Allowed，否则返回types.Denied
//
// 示例:
//
//	// 创建IP黑名单
//	blacklist, _ := ip.NewIPAcl(
//	    []string{"192.168.1.0/24", "10.0.0.0/8"},
//	    types.Blacklist
//	)
//
//	// 检查IP是否被黑名单阻止
//	perm, err := blacklist.Check("192.168.1.5")
//	if err != nil {
//	    log.Printf("检查IP错误: %v", err)
//	} else if perm == types.Denied {
//	    log.Println("IP被黑名单阻止")
//	} else {
//	    log.Println("IP不在黑名单中，允许访问")
//	}
//
//	// 创建IP白名单
//	whitelist, _ := ip.NewIPAcl(
//	    []string{"8.8.8.8", "1.1.1.1"},
//	    types.Whitelist
//	)
//
//	// 检查IP是否在白名单中
//	perm, err = whitelist.Check("8.8.8.8")
//	if err != nil {
//	    log.Printf("检查IP错误: %v", err)
//	} else if perm == types.Allowed {
//	    log.Println("IP在白名单中，允许访问")
//	} else {
//	    log.Println("IP不在白名单中，拒绝访问")
//	}
func (a *IPAcl) Check(ip string) (types.Permission, error) {
	// 解析IP地址
	parsedIP := net.ParseIP(strings.TrimSpace(ip))
	if parsedIP == nil {
		return types.Denied, ErrInvalidIP
	}

	// 检查IP是否匹配列表中的任何范围
	matched := a.matchIP(parsedIP)

	// 根据列表类型确定权限
	if a.listType == types.Blacklist {
		if matched {
			return types.Denied, nil
		}
		return types.Allowed, nil
	} else { // 白名单
		if matched {
			return types.Allowed, nil
		}
		return types.Denied, nil
	}
}

// GetIPRanges 获取当前访问控制列表中的所有IP/CIDR
//
// 返回:
//   - []string: IP/CIDR列表
//     例如: []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
//
// 返回的是原始输入的字符串形式，而不是标准化后的形式。
//
// 示例:
//
//	// 获取所有IP/CIDR
//	acl, _ := ip.NewIPAcl(
//	    []string{"192.168.1.1", "10.0.0.0/8"},
//	    types.Blacklist
//	)
//	ipRanges := acl.GetIPRanges()
//
//	fmt.Printf("当前包含 %d 个IP/CIDR:\n", len(ipRanges))
//	for i, ipRange := range ipRanges {
//	    fmt.Printf("%d. %s\n", i+1, ipRange)
//	}
func (a *IPAcl) GetIPRanges() []string {
	ipRanges := make([]string, len(a.ranges))
	for i, ipRange := range a.ranges {
		ipRanges[i] = ipRange.Original
	}
	return ipRanges
}

// GetListType 获取访问控制列表的类型（黑名单或白名单）
//
// 返回:
//   - types.ListType: 列表类型
//   - types.Blacklist: 黑名单（默认允许，列表中的IP被拒绝）
//   - types.Whitelist: 白名单（默认拒绝，只有列表中的IP被允许）
//
// 示例:
//
//	// 获取列表类型
//	acl, _ := ip.NewIPAcl([]string{"192.168.1.1"}, types.Blacklist)
//	listType := acl.GetListType()
//
//	if listType == types.Blacklist {
//	    fmt.Println("这是一个IP黑名单")
//	} else {
//	    fmt.Println("这是一个IP白名单")
//	}
func (a *IPAcl) GetListType() types.ListType {
	return a.listType
}

// AddPredefinedSet 添加预定义的IP集合到访问控制列表
//
// 参数:
//   - setName: 预定义集合名称
//     例如: ip.PrivateNetworks, ip.LoopbackNetworks, ip.CloudMetadata等
//   - allowSet: 预定义集合的处理方式
//     true: 允许访问这些IP (添加到白名单/从黑名单排除)
//     false: 拒绝访问这些IP (添加到黑名单/从白名单排除)
//
// 返回:
//   - error: 可能的错误:
//   - ErrInvalidPredefinedSet: 指定的预定义集合不存在
//
// 调用逻辑:
// - 如果是黑名单且allowSet=false: 将预定义集合中的IP添加到黑名单（阻止这些IP）
// - 如果是白名单且allowSet=true: 将预定义集合中的IP添加到白名单（允许这些IP）
// - 其他情况不执行任何操作
//
// 示例:
//
//	// 创建IP黑名单，然后添加私有网络范围（阻止内网访问）
//	blacklist, _ := ip.NewIPAcl([]string{}, types.Blacklist)
//	err := blacklist.AddPredefinedSet(ip.PrivateNetworks, false)
//	if err != nil {
//	    log.Printf("添加预定义集合失败: %v", err)
//	    return
//	}
//
//	// 检查是否成功添加
//	ranges := blacklist.GetIPRanges()
//	fmt.Printf("黑名单现在包含 %d 个IP范围\n", len(ranges))
//
//	// 创建IP白名单，然后添加公共DNS服务器（允许访问公共DNS）
//	whitelist, _ := ip.NewIPAcl([]string{}, types.Whitelist)
//	err = whitelist.AddPredefinedSet(ip.PublicDNS, true)
func (a *IPAcl) AddPredefinedSet(setName PredefinedSet, allowSet bool) error {
	// 获取预定义集合的IP范围
	ipRanges, err := getPredefinedSet(setName)
	if err != nil {
		return err
	}

	// 根据列表类型和allowSet参数决定是否添加
	if (a.listType == types.Blacklist && !allowSet) || (a.listType == types.Whitelist && allowSet) {
		return a.Add(ipRanges...)
	}

	return nil
}

// matchIP 检查指定的IP是否匹配访问控制列表中的任何范围
//
// 参数:
//   - ip: 要检查的IP地址（已解析的net.IP对象）
//
// 返回:
//   - bool: 如果IP匹配列表中的任何IP或CIDR范围，返回true
//
// 这是一个内部辅助方法，用于检查IP是否在控制列表的任何范围内。
func (a *IPAcl) matchIP(ip net.IP) bool {
	for _, ipRange := range a.ranges {
		// 对于单个IP地址的精确匹配
		if ipRange.IP != nil && ipRange.IPNet == nil && ipRange.IP.Equal(ip) {
			return true
		}

		// 对于CIDR范围的匹配
		if ipRange.IPNet != nil && ipRange.IPNet.Contains(ip) {
			return true
		}
	}
	return false
}

// parseIPRange 解析IP字符串为IPRange对象
//
// 参数:
//   - ipStr: 要解析的IP或CIDR字符串
//     例如: "192.168.1.1", "10.0.0.0/8", "2001:db8::/32"
//
// 返回:
//   - *IPRange: 解析后的IPRange对象，包含原始字符串、IP和IPNet
//   - error: 可能的错误:
//   - ErrInvalidIP: 提供了无效的IP地址格式
//   - ErrInvalidCIDR: 提供了无效的CIDR格式
//
// 解析逻辑:
// 1. 首先尝试作为CIDR解析
// 2. 如果不是CIDR，则尝试作为单个IP解析
// 3. 对于单个IP，创建一个只包含该IP的IPNet
//
// 这是一个内部辅助方法，用于解析和验证IP和CIDR格式。
func parseIPRange(ipStr string) (*IPRange, error) {
	ipStr = strings.TrimSpace(ipStr)

	// 首先尝试作为CIDR解析
	ip, ipNet, err := net.ParseCIDR(ipStr)
	if err == nil {
		return &IPRange{
			Original: ipStr,
			IP:       ip,
			IPNet:    ipNet,
		}, nil
	}

	// 然后尝试作为单个IP解析
	ip = net.ParseIP(ipStr)
	if ip == nil {
		return nil, ErrInvalidIP
	}

	// 创建一个只包含该IP的IPNet
	var mask net.IPMask
	if ip.To4() != nil {
		// IPv4使用/32掩码
		mask = net.CIDRMask(32, 32)
	} else {
		// IPv6使用/128掩码
		mask = net.CIDRMask(128, 128)
	}
	ipNet = &net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	return &IPRange{
		Original: ipStr,
		IP:       ip,
		IPNet:    ipNet,
	}, nil
}

// getPredefinedSet 获取预定义的IP集合
//
// 参数:
//   - setName: 预定义集合名称
//     例如: ip.PrivateNetworks, ip.LoopbackNetworks, ip.CloudMetadata等
//
// 返回:
//   - []string: IP/CIDR列表
//   - error: 可能的错误:
//   - ErrInvalidPredefinedSet: 指定的预定义集合不存在
//
// 这是一个内部辅助方法，用于获取预定义IP集合的内容。
func getPredefinedSet(setName PredefinedSet) ([]string, error) {
	ranges := GetPredefinedIPRanges(setName)
	if ranges == nil {
		return nil, ErrInvalidPredefinedSet
	}
	return ranges, nil
}
