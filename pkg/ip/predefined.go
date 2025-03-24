package ip

// PredefinedSet 代表预定义的IP地址集合类型
type PredefinedSet string

const (
	// PrivateNetworks 代表RFC1918中定义的私有网络地址
	PrivateNetworks PredefinedSet = "private_networks"

	// LoopbackNetworks 代表本地回环地址
	LoopbackNetworks PredefinedSet = "loopback_networks"

	// LinkLocalNetworks 代表链路本地地址
	LinkLocalNetworks PredefinedSet = "link_local_networks"

	// CloudMetadata 代表各大云服务提供商的元数据服务地址
	CloudMetadata PredefinedSet = "cloud_metadata"

	// DockerNetworks 代表Docker默认网络
	DockerNetworks PredefinedSet = "docker_networks"

	// PublicDNS 代表常用的公共DNS服务器地址
	PublicDNS PredefinedSet = "public_dns"

	// BroadcastAddresses 代表广播地址
	BroadcastAddresses PredefinedSet = "broadcast_addresses"

	// MulticastAddresses 代表多播地址范围
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

	// AllSpecialNetworks 代表所有特殊网络的集合
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

// GetPredefinedIPRanges 返回指定预定义集合中的IP地址范围
func GetPredefinedIPRanges(setName PredefinedSet) []string {
	if ranges, ok := PredefinedSets[setName]; ok {
		return ranges
	}
	return nil
}
