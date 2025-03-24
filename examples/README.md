# go-acl 示例程序

本目录包含了 go-acl 库的各种使用示例，从基础功能到复杂应用场景，帮助您快速了解和掌握 go-acl 的使用方法。

## 示例列表

### 1. 域名访问控制 ([01_domain_acl](./01_domain_acl/))

演示域名访问控制列表(Domain ACL)的基本用法，包括：

- 黑名单模式：仅阻止特定域名
- 白名单模式：仅允许特定域名 
- 子域名匹配：是否检查子域名
- 动态管理规则：添加和移除域名

```bash
cd 01_domain_acl
go run main.go
```

### 2. IP访问控制 ([02_ip_acl](./02_ip_acl/))

演示IP访问控制列表(IP ACL)的基本用法，包括：

- IP黑名单：阻止特定IP和CIDR范围
- IP白名单：仅允许特定IP和CIDR范围
- 动态管理IP规则
- IPv6支持

```bash
cd 02_ip_acl
go run main.go
```

### 3. 文件操作 ([03_file_operations](./03_file_operations/))

演示与文件相关的操作，包括：

- 保存IP列表到文件
- 从文件加载IP列表
- 向已有ACL添加来自文件的内容
- 文件格式和注释处理

```bash
cd 03_file_operations
go run main.go
```

### 4. 预定义IP集合 ([04_predefined_sets](./04_predefined_sets/))

演示如何使用预定义的IP集合，包括：

- 私有网络、回环网络等常见网络
- 常见云服务商的元数据IP
- 公共DNS服务器
- Docker默认网络
- 组合使用多个预定义集合

```bash
cd 04_predefined_sets
go run main.go
```

### 5. ACL管理器 ([05_acl_manager](./05_acl_manager/))

演示高级ACL管理器的用法，包括：

- 同时管理域名和IP访问控制
- 使用管理器检查访问权限
- 动态更新规则
- 获取和设置ACL类型

```bash
cd 05_acl_manager
go run main.go
```

### 6. 完整应用示例 ([06_complete_example](./06_complete_example/))

展示一个完整的Web应用访问控制系统，演示如何在实际场景中使用 go-acl，包括：

- 初始化访问控制系统（域名黑名单、IP黑名单）
- 处理Web请求时的访问控制
- 动态更新访问规则
- 切换到高安全模式（域名白名单、IP白名单）
- 访问日志记录和统计

```bash
cd 06_complete_example
go run main.go
```

## 运行所有示例

如果您想依次运行所有示例，可以使用以下命令：

```bash
for dir in */; do
  if [ -f "${dir}main.go" ]; then
    echo "===== 运行 ${dir} ====="
    (cd "$dir" && go run main.go)
    echo
  fi
done
```

## 注意事项

- 所有示例代码都包含详细的注释，解释每一步的操作和目的
- 示例程序的输出结果已在代码末尾以注释形式提供，便于您对照结果
- 部分示例会创建临时文件，这些文件会在程序结束时自动清理 