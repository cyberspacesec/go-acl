// Package domain 实现域名维度的访问控制列表。
//
// DomainACL 支持五种匹配维度：
//   - 精确匹配：example.com
//   - 通配仅子域：*.example.com（不含主域本身）
//   - 前缀：api.*（匹配 api. 开头，不含裸域名）
//   - 宽松后缀：*example.com（标签边界匹配主域及子域）
//   - 正则：/pattern/（按声明顺序匹配小写化域名）
//
// 标签边界处理严谨：宽松后缀用 domain==suffix || HasSuffix(domain,"."+suffix)，
// 避免将 notevil.com 误匹配为 evil.com 的子域。
//
// 域名大小写不敏感（遵循 DNS 规范），Check 前先小写化输入。
package domain
