# Sub2API Model Catalog Manager

独立的 Go 命令行工具，用于读取 Sub2API 管理 API 的上游模型目录、对照官方生命周期资料生成筛分与映射计划，并在明确配置的规则哈希门禁通过后应用映射。

## 当前适用范围

当前源码的管理 API 目标被固定为 `https://404token.xyz`。它是 404token 版本的独立管理器，**目前不支持任意 Sub2API 域名**；通用多实例/可配置目标仍是未完成项。仓库独立于 Sub2API 源码，不修改 Sub2API 服务端。

本仓库不包含管理员 API key、DPAPI 密钥文件、实际模型规则、账号映射、运行日志、筛分报告、缓存、状态数据库或编译产物。请勿把这些本地运行数据提交到 Git。

## 重要运行边界

- `scripts/Start-404tokenFullModelScreen.cmd` 会启动全账号筛分流程。它会连接 404token 管理 API，对符合条件的账号调用原生上游目录同步并写回模型元数据。正式模式在规则哈希匹配、预检通过时还会应用映射。
- `-PreviewOnly` 只跳过映射应用；它仍会连接管理 API，并对符合条件的账号执行原生目录同步和元数据写入。
- 启动前必须人工检查目标、全账号范围、凭据暴露接受项、元数据同步开关、规则文件及其 SHA-256。不要把空白/示例配置直接改成自动应用。
- Windows 一键脚本从项目目录下 `secrets/404token-admin-api-key.dpapi` 读取本机 DPAPI 保护的 key。该文件按 Windows 用户/机器保护，不随仓库分发；在当前 Windows 用户下重新创建。`secrets/` 已加入忽略规则。
- 报告会含账号 ID、模型名和映射信息，按敏感运维数据保管。

## 构建

需要 Go 1.23 或更新版本：

```powershell
go test ./... -count=1
go vet ./...
New-Item -ItemType Directory -Force bin | Out-Null
go build -o bin/model-catalog-manager-full-screen.exe ./cmd/model-catalog-manager
```

## 配置与使用

请阅读 [`docs/OPERATOR-GUIDE.md`](docs/OPERATOR-GUIDE.md)。当前提交不带真实运行配置或模型筛分规则；本地配置必须根据目标实例的已验证 API 契约、目标构建和授权范围单独生成。

## 许可

当前仓库未附带开源许可证。除非仓库所有者另行添加许可证，默认不授予第三方复制、分发或修改的额外权利。
