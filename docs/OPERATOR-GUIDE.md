# 运维与安全说明

## 这版能做什么

该工具可通过自身的 Sub2API 管理 API 客户端检查账号上游目录、调用原生上游目录同步、查询官方模型生命周期来源、生成筛分报告和审核计划，并按本地规则与精确 SHA-256 门禁处理映射。官方生命周期页面只作为证据来源，不能证明代理线路仍可用；上游目录出现模型也不代表生成请求成功。

当前 API 客户端仅接受 HTTPS `https://404token.xyz`。想管理其他 Sub2API 实例，需要先完成有边界的目标地址/API 契约适配和独立安全审计；不能只把 URL 改成其他主机。

## 运行前的检查

1. 确认程序版本、目标构建 ID、管理 API 契约和对应证据。
2. 使用本机独立配置，明确选定账号范围。全账号模式涉及账号详情凭据字段在进程内存中的短暂读取，必须理解并明确接受配置门禁。
3. 先核对应用模式、元数据同步开关、规则文件 SHA-256 和回滚备份目录。
4. 不要将管理员 key、provider 凭据、账号详情原始响应、真实规则和输出报告放进仓库。
5. 对每个候选映射先审阅报告与计划。不得按名字相似、官方推荐替代项或目录返回自动推断模型等价。

## Windows 一键入口

`Start-404tokenFullModelScreen.cmd` 调用 `Run-404tokenFullModelScreen.ps1`，再启动 `bin/model-catalog-manager-full-screen.exe`。启动器预期：

- 本地配置：项目根目录的 `config-404token-full-screen.json`
- 本机保护的管理员 key：`secrets/404token-admin-api-key.dpapi`
- 运行日志：`logs/`

这些都属于本机运行数据，应保持 Git 未跟踪。DPAPI 文件需要在运行该脚本的 Windows 用户环境内创建；不能从另一台机器复制后假定可解密。

默认入口不是只读预览：它会对符合条件的账号调用原生 `sync-upstream` 并将模型元数据写回 Sub2API。`-PreviewOnly` 仍然执行上述同步写入，只跳过 model_mapping 应用。正式模式还可能在规则哈希门禁通过后修改模型映射，影响下游可见模型。启动前必须逐项审阅配置和本地规则。

## 构建

```powershell
go test ./... -count=1
go vet ./...
New-Item -ItemType Directory -Force bin | Out-Null
go build -o bin/model-catalog-manager-full-screen.exe ./cmd/model-catalog-manager
```

本仓库不含实测凭据或运行配置。每个目标环境都应单独核验管理 API 兼容性。
