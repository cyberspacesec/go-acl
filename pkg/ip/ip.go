package ip

import (
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/cyberspacesec/acl-skills/pkg/types"
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
//   - Original: 规范化后的IP/CIDR字符串（剥除 zone id，等价形式统一）
//   - IP: 解析后的IP地址
//   - IPNet: 对于CIDR，表示网络范围；对于单个IP，表示包含单个IP的网络
//
// 该结构体支持IPv4和IPv6地址。
type IPRange struct {
	Original string     // 规范化后的IP/CIDR字符串（用于去重与匹配）
	IP       net.IP     // 解析后的IP地址
	IPNet    *net.IPNet // 网络范围
}

// IPACL 实现了IP访问控制列表
//
// 支持黑名单和白名单两种模式，可以控制单个IP和CIDR网段。
// 支持IPv4和IPv6地址，以及预定义的IP集合（如私有网络、云元数据等）。
//
// 用法示例:
//
//	// 创建一个IP黑名单
//	blacklist, err := ip.NewIPACL(
//	    []string{"192.168.1.0/24", "10.0.0.1"},
//	    types.Blacklist
//	)
//
//	// 创建一个IP白名单
//	whitelist, err := ip.NewIPACL(
//	    []string{"8.8.8.8", "1.1.1.1"},
//	    types.Whitelist
//	)
//
//	// 检查IP访问权限
//	perm, err := blacklist.Check("192.168.1.5") // 返回 types.Denied
//	perm, err := whitelist.Check("8.8.8.8")     // 返回 types.Allowed
type IPACL struct {
	mu       sync.RWMutex
	ranges   []IPRange
	listType types.ListType
	// trie 用于 O(prefixLen) 的 IP 匹配，与规则数无关
	trie *ipTrie
}

// NewIPACL 创建一个新的IP访问控制列表
//
// 参数:
//   - ipRanges: 要控制的IP或CIDR列表
//     例如: []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
//   - listType: 列表类型（黑名单或白名单）
//     可用值: types.Blacklist（黑名单）或 types.Whitelist（白名单）
//
// 返回:
//   - *IPACL: 创建的IP访问控制列表，成功时非nil
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
//	blacklist, err := ip.NewIPACL(
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
//	whitelist, err := ip.NewIPACL(
//	    []string{"8.8.8.8", "1.1.1.1"},
//	    types.Whitelist
//	)
func NewIPACL(ipRanges []string, listType types.ListType) (*IPACL, error) {
	acl := &IPACL{
		listType: listType,
		trie:     newIPTrie(),
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

		// 去重：规范化后相同的等价形式（如 IPv6 全写/压缩写法）只保留一条
		if existsInRanges(acl.ranges, ipRange.Original) {
			continue
		}

		acl.ranges = append(acl.ranges, *ipRange)
		acl.trie.Insert(ipRange.IPNet)
	}

	return acl, nil
}

// existsInRanges 判断规范化后的 Original 是否已存在于 ranges 中。
// 与 Add 的 seen 去重逻辑保持一致，确保等价形式不重复添加。
func existsInRanges(ranges []IPRange, original string) bool {
	for _, r := range ranges {
		if r.Original == original {
			return true
		}
	}
	return false
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
//	acl, _ := ip.NewIPACL([]string{"192.168.1.1"}, types.Blacklist)
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
func (a *IPACL) Add(ipRanges ...string) error {
	// 如果没有输入IP，直接返回
	if len(ipRanges) == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// 收集已存在的原始串，用于去重
	existing := make([]string, len(a.ranges))
	for i, r := range a.ranges {
		existing[i] = r.Original
	}
	seen := make(map[string]struct{}, len(existing))
	for _, e := range existing {
		seen[e] = struct{}{}
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

		// 去重：已存在则跳过
		if _, ok := seen[ipRange.Original]; ok {
			continue
		}
		seen[ipRange.Original] = struct{}{}
		a.ranges = append(a.ranges, *ipRange)
		a.trie.Insert(ipRange.IPNet)
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
// 该方法使用规范化字符串进行匹配，因此等价表示形式（如 IPv6 全写与压缩写法）
// 可互相匹配。如果任何一个IP不在列表中，将返回ErrIPNotFound错误，但在列表中的部分仍然会被移除。
//
// 示例:
//
//	// 创建包含多个IP的黑名单
//	acl, _ := ip.NewIPACL(
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
func (a *IPACL) Remove(ipRanges ...string) error {
	if len(ipRanges) == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.ranges) == 0 {
		return ErrIPNotFound
	}

	// 跟踪是否找到所有要移除的IP（用规范化形式作 key，等价形式视为同一条）
	found := make(map[string]bool, len(ipRanges))
	for _, ipStr := range ipRanges {
		if strings.TrimSpace(ipStr) == "" {
			continue
		}
		found[normalizeIPString(ipStr)] = false
	}

	// 创建新的IP范围列表，排除要移除的
	var newRanges []IPRange
	for _, existingRange := range a.ranges {
		keep := true
		for normKey := range found {
			if existingRange.Original == normKey {
				found[normKey] = true
				keep = false
				break
			}
		}
		if keep {
			newRanges = append(newRanges, existingRange)
		}
	}

	// 检查是否所有IP都找到了
	for normKey, wasFound := range found {
		if !wasFound && strings.TrimSpace(normKey) != "" {
			// 虽然有未找到的IP，但仍更新列表
			a.ranges = newRanges
			a.rebuildTrie()
			return ErrIPNotFound
		}
	}

	// 更新IPACL使用新的范围
	a.ranges = newRanges
	a.rebuildTrie()
	return nil
}

// rebuildTrie 根据当前 ranges 重建前缀树
// 在 Remove 改变 ranges 后调用，保证 trie 与 ranges 一致。
// 调用方必须已持有写锁。
func (a *IPACL) rebuildTrie() {
	a.trie = newIPTrie()
	for _, r := range a.ranges {
		a.trie.Insert(r.IPNet)
	}
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
//	blacklist, _ := ip.NewIPACL(
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
//	whitelist, _ := ip.NewIPACL(
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
func (a *IPACL) Check(ip string) (types.Permission, error) {
	// 解析IP地址（剥除 zone id，如 fe80::1%eth0 → fe80::1，net.ParseIP 不支持 zone）
	parsedIP := net.ParseIP(stripZone(strings.TrimSpace(ip)))
	if parsedIP == nil {
		return types.Denied, ErrInvalidIP
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	// 检查IP是否匹配列表中的任何范围
	matched := a.matchIP(parsedIP)

	// 根据列表类型确定权限（黑名单命中→拒绝；白名单未命中→拒绝）
	return types.DecideByListType(a.listType, matched), nil
}

// GetIPRanges 获取当前访问控制列表中的所有IP/CIDR
//
// 返回:
//   - []string: IP/CIDR列表
//     例如: []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
//
// 返回的是规范化后的字符串形式（net.IP.String() / ipNet.String()），
// 等价表示形式会被归一为同一条。
//
// 示例:
//
//	// 获取所有IP/CIDR
//	acl, _ := ip.NewIPACL(
//	    []string{"192.168.1.1", "10.0.0.0/8"},
//	    types.Blacklist
//	)
//	ipRanges := acl.GetIPRanges()
//
//	fmt.Printf("当前包含 %d 个IP/CIDR:\n", len(ipRanges))
//	for i, ipRange := range ipRanges {
//	    fmt.Printf("%d. %s\n", i+1, ipRange)
//	}
func (a *IPACL) GetIPRanges() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()

	ipRanges := make([]string, len(a.ranges))
	for i, ipRange := range a.ranges {
		ipRanges[i] = ipRange.Original
	}
	return ipRanges
}

// GetRules 返回当前IP/CIDR规则列表的副本
//
// 这是 MutableACL 接口要求的统一命名方法，等同于 GetIPRanges。
// 旧代码可继续使用 GetIPRanges，二者行为一致。
func (a *IPACL) GetRules() []string {
	return a.GetIPRanges()
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
//	acl, _ := ip.NewIPACL([]string{"192.168.1.1"}, types.Blacklist)
//	listType := acl.GetListType()
//
//	if listType == types.Blacklist {
//	    fmt.Println("这是一个IP黑名单")
//	} else {
//	    fmt.Println("这是一个IP白名单")
//	}
func (a *IPACL) GetListType() types.ListType {
	a.mu.RLock()
	defer a.mu.RUnlock()

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
//	blacklist, _ := ip.NewIPACL([]string{}, types.Blacklist)
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
//	whitelist, _ := ip.NewIPACL([]string{}, types.Whitelist)
//	err = whitelist.AddPredefinedSet(ip.PublicDNS, true)
func (a *IPACL) AddPredefinedSet(setName PredefinedSet, allowSet bool) error {
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
func (a *IPACL) matchIP(ip net.IP) bool {
	return a.trie.Contains(ip)
}

// parseIPRange 解析IP字符串为IPRange对象
//
// 参数:
//   - ipStr: 要解析的IP或CIDR字符串
//     例如: "192.168.1.1", "10.0.0.0/8", "2001:db8::/32"
//
// 返回:
//   - *IPRange: 解析后的IPRange对象，包含规范化字符串、IP和IPNet
//   - error: 可能的错误:
//   - ErrInvalidIP: 提供了无效的IP地址格式
//   - ErrInvalidCIDR: 提供了无效的CIDR格式
//
// 解析逻辑:
// 1. 先用 normalizeIPString 规范化（剥除 zone id，等价形式统一），作为 Original
// 2. 含 "/" 视为 CIDR：Original 用 ipNet.String()（网络地址/掩码）
// 3. 否则作为单个 IP 解析：Original 用 ip.String()（规范形式）
// 4. 对于单个IP，创建一个只包含该IP的IPNet
//
// Original 采用规范化形式，使等价表示（如 2001:db8::1 与
// 2001:0db8::0000:0000:0000:0000:0001）在 Add 去重与 Remove 匹配时被视为同一条。
//
// 这是一个内部辅助方法，用于解析和验证IP和CIDR格式。
func parseIPRange(ipStr string) (*IPRange, error) {
	normalized := normalizeIPString(ipStr)

	// 含 "/" 视为 CIDR：解析失败一律返回 ErrInvalidCIDR，不回退到单 IP 解析
	if strings.Contains(normalized, "/") {
		ip, ipNet, err := net.ParseCIDR(normalized)
		if err != nil {
			return nil, ErrInvalidCIDR
		}
		return &IPRange{
			Original: ipNet.String(),
			IP:       ip,
			IPNet:    ipNet,
		}, nil
	}

	// 否则作为单个 IP 解析
	ip := net.ParseIP(normalized)
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
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: mask,
	}

	return &IPRange{
		Original: ip.String(),
		IP:       ip,
		IPNet:    ipNet,
	}, nil
}

// normalizeIPString 将 IP/CIDR 字符串规范化为稳定形式，
// 用于 Add 去重与 Remove 匹配，避免 2001:db8::1 与 2001:0db8::0001 被视为不同条目。
//
// 规则：剥除 zone id（如 %eth0），单 IP 用 net.IP.String() 规范化，
// CIDR 用 "网络地址/掩码" 形式。解析失败时原样返回（交由调用方报错）。
func normalizeIPString(s string) string {
	s = strings.TrimSpace(s)
	// 剥离 zone id：net.ParseIP 不支持 zone，fe80::1%eth0 → fe80::1
	s = stripZone(s)
	if strings.Contains(s, "/") {
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return s
		}
		_ = ip
		return ipNet.String()
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	return ip.String()
}

// stripZone 剥离 IPv6 zone id（如 fe80::1%eth0 → fe80::1）。
// net.ParseIP 与 net.ParseCIDR 均不支持 zone id，需调用前剥除。
func stripZone(s string) string {
	if idx := strings.Index(s, "%"); idx != -1 {
		return s[:idx]
	}
	return s
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
