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
	},

	// Docker默认网络
	DockerNetworks: {
		"172.17.0.0/16", // Docker默认网桥
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
