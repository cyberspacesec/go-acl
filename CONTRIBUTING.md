# 贡献指南

感谢您关注 acl-skills！欢迎贡献代码、文档或问题反馈。

## 开发流程

1. Fork 仓库并创建分支：`feat/<your-feature>`。
2. 确保通过本地质量门禁：
   - `go vet ./...`
   - `golangci-lint run --timeout=5m ./...`
   - `go test -race -cover ./...`
3. 提交信息遵循 [Conventional Commits](https://www.conventionalcommits.org/)：
   - `feat(domain): support wildcard rules`
   - `fix(ip): correct IPv6 range overflow`
   - `docs: add godoc comments`
4. 测试以表驱动、中文测试名为规范，覆盖 Happy Path + Edge/Error Case。
5. 提交 PR，描述变更与测试方式。

## 代码规范

- 仅使用 Go 标准库，不引入外部依赖。
- 所有导出符号必须有 godoc 注释。
- 并发安全由各子 ACL 自锁保证，Manager 的 mu 仅保护 kind 映射。

## 发布

- 版本号遵循 Semantic Versioning。
- 每个 release 会在 CHANGELOG.md 记录变更。
- 稳定 API（见 README Versioning 段）保证向后兼容。
