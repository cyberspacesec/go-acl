package ip

import (
	"net"
)

// ipTrie 是一个按位二叉前缀树，用于高效判断一个 IP 是否落在任意已注册 CIDR 内。
//
// 为避免 IPv4-in-IPv6 映射前缀（::ffff:0:0/96）造成的地址族串扰，
// IPv4 与 IPv6 各维护一棵独立子树，按地址族分流。
//
// 复杂度：插入与查询均为 O(prefixLen)，即 O(32) for IPv4 / O(128) for IPv6，
// 与已注册规则数量无关。
//
// 非并发安全，调用方（IPACL）需自行加锁。
type ipTrie struct {
	v4Root *trieNode
	v6Root *trieNode
}

type trieNode struct {
	left     *trieNode  // bit 0
	right    *trieNode  // bit 1
	terminal bool       // 某 CIDR 前缀在此节点结束
	payload  *net.IPNet // 命中时对应的 CIDR（仅 terminal 为 true 时有效）
}

func newIPTrie() *ipTrie {
	return &ipTrie{v4Root: &trieNode{}, v6Root: &trieNode{}}
}

// Insert 插入一个 IP 网段（单个 IP 视为 /32 或 /128）
func (t *ipTrie) Insert(ipNet *net.IPNet) {
	if ipNet == nil {
		return
	}

	ip4 := ipNet.IP.To4()
	if ip4 != nil {
		// IPv4：仅遍历掩码覆盖的前缀 bit
		ones, bits := ipNet.Mask.Size()
		if bits != 32 {
			// 异常掩码，回退为完整 32 bit
			ones = 32
		}
		insertPath(t.v4Root, ip4, ones, ipNet)
		return
	}

	// IPv6
	ones, bits := ipNet.Mask.Size()
	if bits != 128 {
		ones = 128
	}
	insertPath(t.v6Root, ipNet.IP.To16(), ones, ipNet)
}

// insertPath 从 root 沿 ip 的前 ones 位下沉，末节点置 terminal 并存 payload
func insertPath(root *trieNode, ip []byte, ones int, ipNet *net.IPNet) {
	node := root
	for i := 0; i < ones; i++ {
		if getBit(ip, i) == 0 {
			if node.left == nil {
				node.left = &trieNode{}
			}
			node = node.left
		} else {
			if node.right == nil {
				node.right = &trieNode{}
			}
			node = node.right
		}
	}
	node.terminal = true
	node.payload = ipNet
}

// Contains 判断 ip 是否被任意已插入的网段覆盖
func (t *ipTrie) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip4 := ip.To4(); ip4 != nil {
		return containsPath(t.v4Root, ip4, 32)
	}
	return containsPath(t.v6Root, ip.To16(), 128)
}

// Lookup 返回包含该 IP 的最长前缀匹配 CIDR；无匹配返回 nil
func (t *ipTrie) Lookup(ip net.IP) *net.IPNet {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return lookupPath(t.v4Root, ip4, 32)
	}
	return lookupPath(t.v6Root, ip.To16(), 128)
}

// lookupPath 沿 IP 位下沉，记录最后一个 terminal 节点的 payload 作为最长匹配
func lookupPath(root *trieNode, ip []byte, maxBits int) *net.IPNet {
	if root == nil {
		return nil
	}
	node := root
	var match *net.IPNet
	for i := 0; i < maxBits && node != nil; i++ {
		if node.terminal {
			match = node.payload
		}
		if getBit(ip, i) == 0 {
			node = node.left
		} else {
			node = node.right
		}
	}
	// 检查末节点本身（/32 或 /128 精确命中）
	if node != nil && node.terminal {
		match = node.payload
	}
	return match
}

func containsPath(root *trieNode, ip []byte, maxBits int) bool {
	if root == nil {
		return false
	}
	node := root
	for i := 0; i < maxBits; i++ {
		if node.terminal {
			return true
		}
		if getBit(ip, i) == 0 {
			node = node.left
		} else {
			node = node.right
		}
		if node == nil {
			return false
		}
	}
	return node.terminal
}

// getBit 取 ip 第 i 个 bit（从最高位起，i=0 为最左 bit）
func getBit(ip []byte, i int) byte {
	byteIndex := i / 8
	bitIndex := uint(7 - i%8)
	return (ip[byteIndex] >> bitIndex) & 1
}
