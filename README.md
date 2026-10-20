# Sub2API Model Catalog Manager

独立的 Go 命令行工具，用于读取 404token/Sub2API 上游模型目录，按产品范围同步官方公开模型文档/公告中的生命周期证据，生成筛分与映射计划，并在规则哈希与精确映射所有权门禁通过后应用映射。

## 当前适用范围

当前源码的管理 API 目标被固定为 `https://404token.xyz`。它是 404token 版本的独立管理器，**目前不支持任意 Sub2API 域名**；通用多实例/可配置目标仍是未完成项。仓库独立于 Sub2API 源码，不修改 Sub2API 服务端。

本仓库不包含管理员 API key、DPAPI 密钥文件、实际模型规则、账号映射、运行日志、筛分报告、缓存、状态数据库或编译产物。请勿把这些本地运行数据提交到 Git。

## 重要运行边界

- `scripts/Start-404tokenFullModelScreen.cmd` 会启动全账号筛分流程。它会连接 404token 管理 API，对符合条件的账号调用原生上游目录同步并写回模型元数据。正式模式在规则哈希匹配、预检通过时还会应用映射。
- `-PreviewOnly` 只跳过映射应用；它仍会连接管理 API，并对符合条件的账号执行原生目录同步和元数据写入。
- 启动前必须人工检查目标、全账号范围、凭据暴露接受项、元数据同步开关、规则文件及其 SHA-256。不要把空白/示例配置直接改成自动应用。
- Windows 一键脚本从项目目录下 `secrets/404token-admin-api-key.dpapi` 读取本机 DPAPI 保护的 key。该文件按 Windows 用户/机器保护，不随仓库分发；在当前 Windows 用户下重新创建。`secrets/` 已加入忽略规则。
- 报告会含账号 ID、模型名和映射信息，按敏感运维数据保管。
- 网页版/登录产品只使用对应产品的官方选择器或公告证据；火山方舟与百炼另有严格限定到 platform=volcengine / platform=alibaba 的官方 API 目录规则。API Key 目录不能证明网页版产品可用。当前自动正向来源及未覆盖产品见 [`docs/official-product-availability.md`](docs/official-product-availability.md)。
- 官方清单仅精确匹配或使用代码中明确登记的别名。某个产品的退役公告不会自动删除其他已接受产品可能仍可用的模型；页面未列出但覆盖不完整时，已有映射保留，新 identity 映射阻止导入。404token 目录仍作为路由可行性输入。
- 官方来源必须新鲜且结构有效，404token 目录必须成功、非空且没有影响模型 ID 完整性的警告。精确 identity 映射仍须通过本工具所有权、来源指纹和未漂移检查，自定义别名和通配路由按现有规则处理。
- 火山方舟可选参考通过官方 `ListModelActivations` 查询 AK/SK 账号的当前可用模型；设置 `VOLCENGINE_ARK_CREDENTIAL_FILE` 指向本机 AK/SK 文件后，在线筛分自动刷新。该目录仅用于 `platform=volcengine` 的账号，失败、离线或过期结果不会产生删除依据；配置和文件格式见 [`docs/official-product-availability.md`](docs/official-product-availability.md)。
- 百炼北京地域可选参考通过当前 Workspace 的官方 `GET /api/v1/models` 分页目录获取 Model Studio 正式模型列表；运行进程需设置 `DASHSCOPE_API_KEY`。它只用于 `platform=alibaba` 且上游 `BaseURL` 命中这个 Workspace 域名的模型目录判断，不代表网页产品可用性，也不证明特定 API Key 的推理权限；Key 不保存在程序配置中，筛分边界见 [`docs/official-product-availability.md`](docs/official-product-availability.md)。
- `--preview-only` 不应用 model_mapping，但仍会调用 404token 原生上游同步并写入模型元数据；它不是无副作用预览。

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
