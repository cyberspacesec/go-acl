# 🧪 go-acl 示例指南

<p align="center">
  <img src="https://img.shields.io/badge/Examples-6-brightgreen?style=for-the-badge" alt="示例数量" />
  <img src="https://img.shields.io/badge/Go-1.18+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go版本" />
  <img src="https://img.shields.io/badge/Difficulty-Beginner_to_Advanced-blue?style=for-the-badge" alt="难度" />
</p>

<p align="center">
  <b>从基础到高级的完整示例集</b><br>
  <sub>学习如何在您的应用中实现强大的访问控制</sub>
</p>

---

## 📚 示例概览

本目录包含了一系列精心设计的示例，展示了如何在各种场景中使用 go-acl 库的丰富功能。每个示例都包含详细的注释和预期输出，帮助您快速理解和掌握该库的用法。

示例按照复杂度递增的顺序排列，建议按顺序学习：

## 🔢 示例列表

<table>
  <tr>
    <th width="5%">序号</th>
    <th width="20%">名称</th>
    <th width="45%">描述</th>
    <th width="30%">核心概念</th>
  </tr>
  <tr>
    <td align="center"><b>01</b></td>
    <td><a href="./01_domain_acl/">域名访问控制</a></td>
    <td>演示基本的域名过滤功能，包括黑白名单和子域名匹配。</td>
    <td>
      <code>DomainAcl</code><br>
      <code>黑/白名单模式</code><br>
      <code>子域名匹配</code>
    </td>
  </tr>
  <tr>
    <td align="center"><b>02</b></td>
    <td><a href="./02_ip_acl/">IP访问控制</a></td>
    <td>展示IP和CIDR过滤，包括IPv4和IPv6支持。</td>
    <td>
      <code>IPAcl</code><br>
      <code>CIDR格式</code><br>
      <code>IPv6支持</code>
    </td>
  </tr>
  <tr>
    <td align="center"><b>03</b></td>
    <td><a href="./03_file_operations/">文件操作</a></td>
    <td>演示如何从文件加载规则和保存规则到文件。</td>
    <td>
      <code>ReadIPList</code><br>
      <code>SaveIPList</code><br>
      <code>文件格式</code>
    </td>
  </tr>
  <tr>
    <td align="center"><b>04</b></td>
    <td><a href="./04_predefined_sets/">预定义IP集合</a></td>
    <td>使用内置的IP集合快速构建安全规则。</td>
    <td>
      <code>PredefinedSet</code><br>
      <code>安全增强</code><br>
      <code>SSRF防护</code>
    </td>
  </tr>
  <tr>
    <td align="center"><b>05</b></td>
    <td><a href="./05_acl_manager/">ACL管理器</a></td>
    <td>使用ACL管理器同时控制域名和IP访问。</td>
    <td>
      <code>Manager</code><br>
      <code>URL解析</code><br>
      <code>规则管理</code>
    </td>
  </tr>
  <tr>
    <td align="center"><b>06</b></td>
    <td><a href="./06_complete_example/">完整应用示例</a></td>
    <td>一个完整的Web应用访问控制系统实现。</td>
    <td>
      <code>实际应用</code><br>
      <code>日志记录</code><br>
      <code>安全模式切换</code>
    </td>
  </tr>
</table>

## 🚀 快速开始

### 运行单个示例

每个示例都可以独立运行。导航到相应目录并执行 `go run main.go` 命令：

```bash
cd 01_domain_acl
go run main.go
```

### 运行所有示例

使用以下脚本可以依次运行所有示例：

```bash
#!/bin/bash
for dir in */; do
  if [ -f "${dir}main.go" ]; then
    echo -e "\n\n====================[ 运行 ${dir} ]====================\n"
    (cd "$dir" && go run main.go)
  fi
done
```

## 📝 示例结构

每个示例都遵循一致的结构：

```
examples/XX_name/
  ├── main.go      # 主示例代码
  └── README.md    # (可选) 详细说明
```

每个示例代码文件的结构：

1. **导入必要的包**
2. **多个示例函数** - 每个展示一个特定功能
3. **辅助函数** - 帮助简化示例代码
4. **预期输出注释** - 展示运行结果

## 🔍 核心场景

go-acl库适用于多种安全场景：

- **Web应用防护** - 阻止恶意域名和IP
- **API安全** - 限制API调用者
- **防止SSRF攻击** - 阻止对内部网络的访问
- **数据泄露防护** - 控制敏感数据的外发
- **合规要求** - 满足网络隔离规定

## 🎓 进阶学习

完成这些示例后，您可以：

1. 查看 [pkg 目录](../pkg/) 了解源码实现
2. 阅读 [测试文件](../pkg/domain/domain_test.go) 了解更多用法
3. 参考 [文档](https://pkg.go.dev/github.com/cyberspacesec/go-acl) 获取完整API细节

## 📊 示例复杂度

<table>
  <tr>
    <td><img src="https://progress-bar.dev/20?title=入门&width=100" alt="入门示例" /></td>
    <td>01-02: 基础概念和简单用法</td>
  </tr>
  <tr>
    <td><img src="https://progress-bar.dev/50?title=中级&width=100" alt="中级示例" /></td>
    <td>03-04: 文件操作和预定义集合</td>
  </tr>
  <tr>
    <td><img src="https://progress-bar.dev/80?title=高级&width=100" alt="高级示例" /></td>
    <td>05: 管理器和综合功能</td>
  </tr>
  <tr>
    <td><img src="https://progress-bar.dev/100?title=实战&width=100" alt="实战示例" /></td>
    <td>06: 完整应用集成</td>
  </tr>
</table>

---

<p align="center">
  <sub>所有示例代码均在MIT许可证下提供</sub><br>
  <sub>有问题或建议？请在GitHub上<a href="https://github.com/cyberspacesec/go-acl/issues">提交Issue</a></sub>
</p> 