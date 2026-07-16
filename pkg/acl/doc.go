// Package acl 提供统一的访问控制列表（ACL）管理器。
//
// Manager 是核心入口，通过注册不同 kind 的 MutableACL 实现统一管理。
// 内置 KindDomain（域名 ACL）与 KindIP（IP ACL）两种 kind，亦可通过
// RegisterACL 注册自定义 ACL。
//
// Manager 自身并发安全：内置 sync.RWMutex 仅保护 kind→ACL 映射的增删查，
// 各子 ACL 自带锁保护自身规则，查询不同 kind 互不阻塞。
//
// 主要能力：
//   - 域名/IP 双维度增删改查
//   - 文件读写（持久化）
//   - 预定义集合（私有网络、云元数据、短链等）
//   - JSON Policy 注入（ApplyPolicy）
//   - 统一 kind 入口（CheckKind/AddRule/RemoveRule）
//   - IP 最长前缀反查（LookupIP）
package acl
