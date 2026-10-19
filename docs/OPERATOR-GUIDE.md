# 运维与安全说明

## 这版能做什么

该工具读取 404token 的账号上游目录，并同步固定清单里的官方网页/登录产品来源。API Key 仍能调用某模型，不会使它进入登录产品的可用清单。404token 目录说明中转当前返回的精确 ID；官方网页产品的精确正向证据决定新 identity 模型能否进入。官方来源不完整时，现有映射进入账号级精确推理复核：任一相关账号成功就保留；所有相关账号都得到终态失败才形成删除候选。新 identity 模型仍不能仅靠推理探测自动加入。

当前 API 客户端仅接受 HTTPS `https://404token.xyz`。想管理其他 Sub2API 实例，需要先完成有边界的目标地址/API 契约适配和独立安全审计；不能只把 URL 改成其他主机。

## 运行前的检查

1. 确认程序版本、目标构建 ID、管理 API 契约和对应证据。
2. 使用本机独立配置，明确选定账号范围。全账号模式涉及账号详情凭据字段在进程内存中的短暂读取，必须理解并明确接受配置门禁。
3. 先核对应用模式、元数据同步开关、规则文件 SHA-256 和回滚备份目录。
4. 不要将管理员 key、provider 凭据、账号详情原始响应、真实规则和输出报告放进仓库。
5. 对每个候选映射先审阅报告与计划。名称建议是人工复核线索，不证明模型等价，也不会自动改写映射或规则。

## 模型名称归并建议

Merge Review 只会分析状态为 `available`、匹配类型为官方 `exact` 或已审核 `explicit_alias`、且带有供应商标识的精确目录 ID。仅因 404token 账号探测成功而保留的 `account_probe_success` 不算官方在售证据，会从候选中排除。大小写与下划线/连字符形式相同的名称可作为低置信候选；完整日期后缀只会与目录中同时出现且分别通过官方筛分的无日期精确 ID 配对。未找到精确正向证据、证据不足或已判下架的 ID 会列在跳过项并说明原因，不参与候选聚类。

建议按账号与来源指纹分别生成，保留每个原始上游 ID。所有候选都标记为 `action=none`、`equivalence=unproven`，需要人工决策。`fast`、`compact`、`thinking`、`reasoning`、`vision`、`code`、`codex`、`preview`、`exp`、`mini`、`nano`、`pro`、`max`、`flash`、`lite`、`sol`、`terra`、`luna`、`astra`、`latest`、`stable`、`auto`、量化、上下文长度、日期和地区等标记不会被删除或折叠。已有精确 AliasRule/VersionFamily 仍是唯一可执行规则；若其只覆盖候选的部分成员，报告显式标出冲突。报告同时列出相关映射的 managed/unmanaged/drifted 归属，候选本身不生成应用计划。

这是一种保守的名称形状筛查，不会猜测供应商别名、能力等价、版本近似或语义相似。无法安全归一的 ID 不会被聚类；需要更广的别名规则时，应单独收集源证据并经过规则审核。

## 全屏筛分的可用性来源

`run --full-screen` 在本地同步固定官方产品来源，并对账号调用 404token 原生上游目录同步。产品当前清单提供精确正向证据；别名只使用审计过的显式映射。一个产品的生命周期公告只覆盖该产品，不能单独证明模型已从所有接受的网页登录产品下架。来源不完整或仅为公告时，现有映射会对该精确目标逐账号发起文本推理复核，成功即保留，全部终态失败才计划删除；新 identity 自动导入仍需官方正向证据。当前支持范围与未覆盖厂商见 [`official-product-availability.md`](official-product-availability.md)。

官方来源必须新鲜且结构有效；404token 必须返回有效非空目录。自动筛分按模型 ID 的厂商命名空间选择对应官方产品证据，不会因为中转账号的 relay 平台而把其他厂商模型当作 OpenAI 等模型处理。通配符不会按具体模型清单自动删除。任一必需来源不可用、陈旧或模型 ID 完整性警告都会阻止该账号的映射变更。

官方证据不足时，管理器对仍被映射引用的文本模型调用 404token 已部署的账号测试接口，使用固定短提示词检查完整 SSE 终态。只有 `test_start.model` 与候选 ID 完全相同且收到成功终态才算可用；映射把请求改到其他模型、HTTP/流错误、超时或缺少终态都按“忽略”处理，保留映射。该原生账号测试接口会应用账号 `model_mapping`，成功后可能恢复账号状态；它会真实调用上游并可能消耗额度。结果不能视为无副作用的低成本 health check。管理器不会保存生成内容或原始上游错误文本。正式任务前请先审阅候选报告与审批计划。

`--preview-only` 不应用映射，但会刷新 404token 上游目录并写入模型元数据，也会更新本地运行状态与报告。正式运行前应先用预览审阅报告。

## 历史：官方账号选择器/API 型号目录方案

以下官方 API 与人工选择器快照设计已被当前的官方公开产品文档/公告筛分边界取代。它保留作历史实现记录，不是运行前置条件。

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

当前自动同步上限为 10 分钟，provider 单请求 15 秒，响应体 2 MiB、每账号最多 20,000 个模型、最多 100 页。全屏筛分、manual-only 和获授权的全账号手动同步预览，在官方证据不足且现有映射目标需复核时，会对相关 active、非 shadow 账号调用 404token 原生账号测试接口，发送固定短文本提示词。该接口的各平台测试路径使用各自的原生输出上限，管理器无法把它统一限制为 1 token；请求会真实调用上游、可能消耗额度，成功后还可能恢复账号状态。原生 `model_mapping` 若把模型改写为其他 ID，结果按证据不足忽略。`--preview-only` 不应用映射，但仍会同步 404token 目录、写本地模型元数据并发送这些请求，因此不是无副作用纯预览。Apply 使用已批准计划中的筛分结果，不会重复发送探测请求；若规则哈希或参与账号集合变化，则阻断映射写入。

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
