# 运维与安全说明

## 这版能做什么

该工具可通过自身的 Sub2API 管理 API 客户端检查账号上游目录、调用原生上游目录同步、查询官方模型生命周期来源，并同步指定官方产品账号的模型目录，生成筛分报告和审核计划，再按本地规则与精确 SHA-256 门禁处理映射。官方模型证据按产品隔离：API-key scope 使用该 provider 的认证模型目录 API；ChatGPT/Codex/Claude 等 UI scope 仍使用该 UI 的手工完整选择器快照。API 列表只证明模型出现在该凭据的 API 目录中，不保证所有功能、额度或推理调用均可用。官方生命周期页面只作为背景证据；上游目录出现模型也不代表生成请求成功。

当前 API 客户端仅接受 HTTPS `https://404token.xyz`。想管理其他 Sub2API 实例，需要先完成有边界的目标地址/API 契约适配和独立安全审计；不能只把 URL 改成其他主机。

## 运行前的检查

1. 确认程序版本、目标构建 ID、管理 API 契约和对应证据。
2. 使用本机独立配置，明确选定账号范围。全账号模式涉及账号详情凭据字段在进程内存中的短暂读取，必须理解并明确接受配置门禁。
3. 先核对应用模式、元数据同步开关、规则文件 SHA-256 和回滚备份目录。
4. 不要将管理员 key、provider 凭据、账号详情原始响应、真实规则和输出报告放进仓库。
5. 对每个候选映射先审阅报告与计划。不得按名字相似、官方推荐替代项或目录返回自动推断模型等价。

## 官方模型可用性自动同步

只有 API-key 产品支持初版自动采集：OpenAI API、Anthropic API、xAI API、DeepSeek API。host、path、认证头和解析格式由固定 adapter 决定，不能在本地配置里填任意 URL。ChatGPT/Codex/Claude 网页选择器没有自动采集器；这些 UI scope 必须继续人工从对应网页产品完整记录，不能拿 API `/models` 代替。

每个有 `official_selectability_scope` 的 `source_profiles` 都必须先人工确认并显式分类为 `api` 或 `ui`；这是规则文件的全局 schema 校验，未分类的旧 scope 会在任何目录读取/筛分入口阻断，避免把旧手工证据静默当成 API 或网页权限。迁移旧规则时，先逐个确认产品并补分类；API profile 还需填写受支持的 provider，配置同 scope 的官方凭据来源，然后重新审核并批准新的规则 SHA。每个自动采集范围还要声明 provider，并在本地配置添加相同 scope 的 OS credential 引用。例如规则 profile 增加：

```json
{
  "official_selectability_scope": "official-account:openai-api-account-8",
  "official_selectability_product": "api",
  "official_selectability_provider": "openai-api"
}
```

本地配置增加（不要放密钥本身）：

```json
{
  "official_selectability_sources": [
    {
      "scope": "official-account:openai-api-account-8",
      "provider": "openai-api",
      "product": "api",
      "credential": {
        "windows_credential_target": "Official OpenAI API account 8"
      }
    }
  ]
}
```

Windows Credential Manager 项必须是 Generic Credential，target 与配置完全一致，username 固定为 `x-api-key`，secret/password 字段放该官方 API key。Linux 使用 `systemd_credential_name` 指向 systemd 注入的 JSON 凭据文件，形状为 `{"api_key":"..."}`；文件只通过 systemd credential 配置注入，不放仓库或普通运行配置。每个 provider/API 账号使用独立引用。工具不会从 404token/Sub2API 的 key 或管理员环境变量推导官方密钥。管理员需确认 scope alias、provider、产品和凭据实际属于同一官方账号；API 响应自身不验证人类可读账户身份。

全屏运行在规则 SHA 门禁通过后刷新全部已配置 API scopes，快照完整写入后才继续筛分。缺少 API scope 来源、provider 不匹配、认证失败、响应为空/不完整或超时，都会在模型映射写入前阻断；API scope 不回退到规则文件中的旧手工快照。UI 手工快照仍需完整、最新且不超过 24 小时。每次 refresh 的动态快照和筛分计划摘要绑定；审批规则原始 SHA 不随采集时间变化。

当前自动同步上限为 10 分钟，provider 单请求 15 秒，响应体 2 MiB、每账号最多 20,000 个模型、最多 100 页。自动刷新只读取官方模型目录，不调用推理/生图；但会产生少量目录 API 请求。`--preview-only` 仍会按原行为同步 404token 上游目录并写模型元数据，只跳过映射应用，不是无副作用纯预览。

官方 API 契约应以厂商文档为准： [OpenAI Models](https://developers.openai.com/api/reference/resources/models)、[Anthropic List Models](https://platform.claude.com/docs/en/api/models/list)、[xAI Models](https://docs.x.ai/developers/rest-api-reference/inference/models)、[DeepSeek List Models](https://api-docs.deepseek.com/api/list-models/)。

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
