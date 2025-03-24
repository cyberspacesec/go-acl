package ip

import "github.com/cyberspacesec/go-acl/pkg/types"

// PredefinedSet 表示预定义IP集合的类型
//
// 预定义集合是一组相关的IP地址或CIDR范围，用于简化常见网络组的访问控制。
// 例如可以轻松地阻止对内网地址、云元数据服务或特殊用途网络的访问。
type PredefinedSet string

// 预定义IP集合常量，用于参数传递
const (
	// PrivateNetworks 包含所有私有网络地址范围
	// RFC1918定义的私有地址: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	// 通常用于阻止内网访问，防止SSRF攻击
	PrivateNetworks PredefinedSet = "private_networks"

	// LoopbackNetworks 包含本地回环地址范围
	// 包括 127.0.0.0/8 和 ::1/128
	// 通常用于阻止对本地服务的访问
	LoopbackNetworks PredefinedSet = "loopback_networks"

	// LinkLocalNetworks 包含链路本地地址范围
	// 包括 169.254.0.0/16 (IPv4) 和 fe80::/10 (IPv6)
	// 这些地址用于同一网段内的通信，没有路由器参与
	LinkLocalNetworks PredefinedSet = "link_local_networks"

	// CloudMetadata 包含各大云服务商的元数据服务地址
	// 包括AWS, GCP, Azure, DigitalOcean等云平台的元数据IP
	// 阻止对这些地址的访问可以防止云环境中的SSRF攻击
	CloudMetadata PredefinedSet = "cloud_metadata"

	// DockerNetworks 代表Docker默认网络
	DockerNetworks PredefinedSet = "docker_networks"

	// PublicDNS 包含常用的公共DNS服务器IP
	// 包括Google DNS (8.8.8.8, 8.8.4.4), Cloudflare DNS (1.1.1.1, 1.0.0.1)等
	// 适用于需要显式允许这些DNS服务的白名单场景
	PublicDNS PredefinedSet = "public_dns"

	// BroadcastAddresses 包含广播地址范围
	// 包括 255.255.255.255/32（IPv4广播）
	// 这些地址用于向整个网络广播消息
	BroadcastAddresses PredefinedSet = "broadcast_addresses"

	// MulticastAddresses 包含组播地址范围
	// 包括 224.0.0.0/4 (IPv4) 和 ff00::/8 (IPv6)
	// 这些地址用于将消息发送到订阅特定组播组的多个主机
	MulticastAddresses PredefinedSet = "multicast_addresses"

	// ReservedAddresses 代表IANA保留的特殊用途地址
	ReservedAddresses PredefinedSet = "reserved_addresses"

	// TestNetworks 代表用于测试和文档的网络范围
	TestNetworks PredefinedSet = "test_networks"

	// K8sServiceAddresses 代表Kubernetes服务默认地址范围
	K8sServiceAddresses PredefinedSet = "k8s_service_addresses"

	// CarrierGradeNAT 代表运营商级NAT地址
	CarrierGradeNAT PredefinedSet = "carrier_grade_nat"

	// UniqueLocalAddresses 代表IPv6的唯一本地地址
	UniqueLocalAddresses PredefinedSet = "unique_local_addresses"

	// AllSpecialNetworks 包含所有特殊用途的网络
	// 这是一个便捷集合，包含上述所有网络，提供最全面的保护
	// 适用于需要最高安全级别的场景
	AllSpecialNetworks PredefinedSet = "all_special_networks"
)

// PredefinedSets 存储所有可用的预定义IP集合
var PredefinedSets = map[PredefinedSet][]string{
	// RFC1918私有网络地址
	PrivateNetworks: {
		"10.0.0.0/8",     // 10.0.0.0 - 10.255.255.255
		"172.16.0.0/12",  // 172.16.0.0 - 172.31.255.255
		"192.168.0.0/16", // 192.168.0.0 - 192.168.255.255
	},

	// 本地回环地址
	LoopbackNetworks: {
		"127.0.0.0/8", // 127.0.0.0 - 127.255.255.255
		"::1/128",     // IPv6回环地址
	},

	// 链路本地地址
	LinkLocalNetworks: {
		"169.254.0.0/16", // IPv4链路本地地址
		"fe80::/10",      // IPv6链路本地地址
	},

	// 云服务商元数据服务地址
	CloudMetadata: {
		"169.254.169.254/32", // AWS/GCP/OpenStack 元数据服务
		"169.254.170.2/32",   // Azure IMDS 服务主要地址
		"fd00:ec2::254/128",  // AWS IPv6 元数据服务
		"192.0.0.192/32",     // Oracle Cloud 元数据服务
		"100.100.100.200/32", // 阿里云 元数据服务
	},

	// Docker默认网络
	DockerNetworks: {
		"172.17.0.0/16", // Docker默认网桥
	},

	// 常用公共DNS服务器
	PublicDNS: {
		"8.8.8.8/32",               // Google DNS
		"8.8.4.4/32",               // Google DNS
		"1.1.1.1/32",               // Cloudflare DNS
		"1.0.0.1/32",               // Cloudflare DNS
		"9.9.9.9/32",               // Quad9 DNS
		"149.112.112.112/32",       // Quad9 DNS
		"208.67.222.222/32",        // OpenDNS
		"208.67.220.220/32",        // OpenDNS
		"2001:4860:4860::8888/128", // Google DNS IPv6
		"2001:4860:4860::8844/128", // Google DNS IPv6
		"2606:4700:4700::1111/128", // Cloudflare DNS IPv6
		"2606:4700:4700::1001/128", // Cloudflare DNS IPv6
	},

	// 广播地址
	BroadcastAddresses: {
		"255.255.255.255/32", // IPv4 限制广播地址
		"224.0.0.1/32",       // 所有主机组播地址
	},

	// 多播地址范围
	MulticastAddresses: {
		"224.0.0.0/4", // IPv4 多播地址范围
		"ff00::/8",    // IPv6 多播地址范围
	},

	// IANA保留的特殊用途地址
	ReservedAddresses: {
		"0.0.0.0/8",       // 当前网络 (RFC1122)
		"192.0.0.0/24",    // IETF协议分配 (RFC6890)
		"192.0.2.0/24",    // TEST-NET-1 (RFC5737)
		"192.88.99.0/24",  // IPv6转IPv4中继 (RFC3068)
		"198.18.0.0/15",   // 网络设备基准测试 (RFC2544)
		"198.51.100.0/24", // TEST-NET-2 (RFC5737)
		"203.0.113.0/24",  // TEST-NET-3 (RFC5737)
		"240.0.0.0/4",     // 保留用于未来使用 (RFC1112)
	},

	// 用于测试和文档的网络范围
	TestNetworks: {
		"192.0.2.0/24",    // TEST-NET-1 (RFC5737)
		"198.51.100.0/24", // TEST-NET-2 (RFC5737)
		"203.0.113.0/24",  // TEST-NET-3 (RFC5737)
		"2001:db8::/32",   // IPv6文档前缀 (RFC3849)
	},

	// Kubernetes服务默认地址范围
	K8sServiceAddresses: {
		"10.96.0.0/12",   // Kubernetes默认服务CIDR
		"10.244.0.0/16",  // Flannel默认pod CIDR
		"192.168.0.0/16", // Calico默认pod CIDR
	},

	// 运营商级NAT地址
	CarrierGradeNAT: {
		"100.64.0.0/10", // RFC6598定义的共享地址空间
	},

	// IPv6的唯一本地地址
	UniqueLocalAddresses: {
		"fc00::/7", // IPv6唯一本地地址 (RFC4193)
	},
}

// 初始化AllSpecialNetworks集合
func init() {
	// 创建所有特殊网络的集合
	var allNetworks []string

	for set, networks := range PredefinedSets {
		if set != AllSpecialNetworks { // 避免自引用
			allNetworks = append(allNetworks, networks...)
		}
	}

	// 去重
	PredefinedSets[AllSpecialNetworks] = removeDuplicates(allNetworks)
}

// removeDuplicates 移除切片中的重复元素
func removeDuplicates(elements []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(elements))

	for _, element := range elements {
		if !seen[element] {
			seen[element] = true
			result = append(result, element)
		}
	}

	return result
}

// GetPredefinedIPRanges 获取指定预定义集合中的IP范围
//
// 参数:
//   - setName: 预定义集合名称
//     例如: ip.PrivateNetworks, ip.LoopbackNetworks, ip.CloudMetadata等
//
// 返回:
//   - []string: 预定义集合中的IP/CIDR列表
//     如果指定的集合不存在，返回nil
//
// 示例:
//
//	// 获取私有网络IP范围
//	privateIPs := ip.GetPredefinedIPRanges(ip.PrivateNetworks)
//	fmt.Printf("私有网络包含 %d 个IP范围:\n", len(privateIPs))
//	for _, cidr := range privateIPs {
//	    fmt.Println(cidr)
//	}
//
//	// 获取所有特殊网络IP范围
//	allSpecialIPs := ip.GetPredefinedIPRanges(ip.AllSpecialNetworks)
//	fmt.Printf("所有特殊网络共包含 %d 个IP范围\n", len(allSpecialIPs))
//
//	// 使用预定义集合创建ACL
//	blacklist, _ := ip.NewIPAcl([]string{}, types.Blacklist)
//	blacklist.AddPredefinedSet(ip.PrivateNetworks, false) // 阻止访问内网
func GetPredefinedIPRanges(setName PredefinedSet) []string {
	if ranges, ok := PredefinedSets[setName]; ok {
		return ranges
	}
	return nil
}

// NewIPACLWithDefaults 创建一个新的IP访问控制列表，同时加入预定义的IP集合
//
// 参数:
//   - ipRanges: 基础IP/CIDR列表
//     例如: []string{"192.168.1.1", "10.0.0.0/8", "2001:db8::/32"}
//   - listType: 列表类型（黑名单或白名单）
//     可用值: types.Blacklist（黑名单）或 types.Whitelist（白名单）
//   - predefinedSets: 要包含的预定义IP集合列表
//     例如: []PredefinedSet{PrivateNetworks, CloudMetadata}
//   - allowDefaultSets: 预定义集合的处理方式
//   - 对于黑名单，false表示阻止这些IP（添加到黑名单）
//   - 对于白名单，true表示允许这些IP（添加到白名单）
//
// 返回:
//   - *IPAcl: 创建的IP访问控制列表，成功时非nil
//   - error: 可能的错误:
//   - ErrInvalidIP: 提供了无效的IP地址格式
//   - ErrInvalidCIDR: 提供了无效的CIDR格式
//   - ErrInvalidPredefinedSet: 指定的预定义集合不存在
//
// 此函数是创建具有安全防护功能的ACL的便捷方法，特别适用于防止SSRF等攻击。
//
// 示例:
//
//	// 创建防SSRF的IP黑名单，阻止内网和云元数据访问
//	blacklist, err := ip.NewIPAclWithDefaults(
//	    []string{"203.0.113.1"}, // 自定义IP
//	    types.Blacklist,
//	    []ip.PredefinedSet{
//	        ip.PrivateNetworks,  // 内网地址
//	        ip.CloudMetadata,    // 云服务商元数据地址
//	    },
//	    false // 设为false将阻止这些预定义集合中的IP
//	)
//	if err != nil {
//	    log.Printf("创建IP黑名单失败: %v", err)
//	    return
//	}
//
//	// 创建IP白名单，只允许特定IP和公共DNS服务器
//	whitelist, err := ip.NewIPAclWithDefaults(
//	    []string{"203.0.113.1"}, // 自定义IP
//	    types.Whitelist,
//	    []ip.PredefinedSet{
//	        ip.PublicDNS, // 公共DNS服务器
//	    },
//	    true // 设为true将允许这些预定义集合中的IP
//	)
func NewIPACLWithDefaults(ipRanges []string, listType types.ListType, predefinedSets []PredefinedSet, allowDefaultSets bool) (*IPACL, error) {
	// 首先创建基本的ACL
	acl, err := NewIPACL(ipRanges, listType)
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
