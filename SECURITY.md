# 安全策略

## 报告漏洞

本项目重视安全性。如发现安全漏洞，请按以下流程报告：

1. **不要**在公开 issue 中提交安全漏洞。
2. 发送邮件至：security@cyberspacesec.example（替换为真实邮箱）
3. 邮件标题以 `[SECURITY]` 开头，描述漏洞、影响范围与复现步骤。
4. 我们将在 72 小时内确认收到，并在 14 天内给出修复计划。

## 支持版本

| 版本 | 支持状态 |
| --- | --- |
| 1.0.x | :white_check_mark: 支持 |
| < 1.0 | :x: 不支持 |

## 安全设计要点

- 白名单语义 fail-closed：空值输入在白名单模式下默认拒绝。
- 中间件 `TrustProxy` 默认 false，防止伪造 `X-Forwarded-For` 绕过。
- 正则基于 Go RE2 引擎，无回溯，天然防 ReDoS。
- 域名宽松后缀用标签边界匹配，防止 `notevil.com` 误命中 `evil.com`。
