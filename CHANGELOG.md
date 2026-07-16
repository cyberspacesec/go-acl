# Changelog

本项目所有重要变更均记录于此文件。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added
- 新增 `Manager.SetDomainACLStrict` 方法，返回无效域名错误，与 `SetIPACL` 对称。
- 为 `pkg/acl`、`pkg/domain`、`pkg/ip`、`pkg/config` 补齐 godoc 包注释。

### Changed
- README 覆盖率徽章改为动态 shields.io/codecov，不再写死。
- CI Go 版本矩阵扩展至 1.18–1.24。
- 升级 GitHub Actions 至 checkout@v5、setup-go@v5、codecov-action@v5。

### Fixed
- 修复 README 中 CONTRIBUTING.md 死链。

## [1.0.0] - 2026-07-17

### Added
- 三层 ACL 接口：`ACL` → `ListTypeACL` → `MutableACL`。
- 域名 ACL 五维匹配：精确、通配 `*.x`、前缀 `api.*`、宽松后缀 `*x`、正则 `/re/`。
- IP ACL 全语法：IPv4/IPv6、CIDR、区间 `a-b`、zone id 剥离、最长前缀反查 `Lookup`。
- 基于 math/big 的区间→CIDR 展开，避免 IPv6 巨区间溢出。
- 统一 Manager：构造、注册、双维度增删改查、文件读写、预定义集合、统一 kind 入口。
- JSON Policy 注入（`ApplyPolicy`），失败不半应用。
- HTTP 中间件，支持代理头信任、自定义拒绝响应，白名单 fail-closed。
- 预定义集合：域名（短链/一次性邮箱/恶意域名等）、IP（私有网络/云元数据/特殊网络等）。
- 并发安全（各子 ACL 自锁），race 测试覆盖。
- benchmark 测试套件。

### Security
- 白名单语义 fail-closed：空值输入在白名单下拒绝。
