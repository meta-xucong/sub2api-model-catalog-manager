# Official product availability contract

## Eligibility rule

The screener compares 404token model IDs with models explicitly shown as
currently available in an official user-facing web or login product. An
API-key catalog, including an API lifecycle page, cannot establish positive
eligibility for a logged-in product.

Availability is a union across the accepted web/login products for a vendor:

- An exact current ID on any accepted product is positive evidence.
- A product-specific retirement is scoped to that product. It does not remove
  the ID from the wider vendor union when another accepted product is missing
  or only has a partial catalog.
- A future retirement date does not make a model unavailable before that
  date; an exact current product listing remains positive evidence.
- Absence from a partial model page, launch announcement, or change log is
  `insufficient_evidence`. Keep an existing mapping and do not create a new
  identity mapping from that candidate.
- Absence can become `unavailable` only when an exhaustive current catalog
  covers the accepted scope, or explicit lifecycle evidence covers every
  accepted product in the union.
- New IDs match by exact spelling (case-insensitive comparison only where the
  vendor's IDs are case-insensitive) or by an explicit, tested alias entry.
  Suffix, date, and version-prefix inference is not allowed.

Model namespaces are classified from the model ID, not the 404token account's
relay platform. A mixed relay account therefore cannot cause a DeepSeek, Qwen,
GLM, or other vendor ID to be evaluated as an OpenAI model.

## Current automated positive sources

These adapters provide positive evidence only. They are not exhaustive for the
vendor-wide accepted product union, so omission from them cannot delete a
mapping:

| Product surface | Official source | Coverage |
| --- | --- | --- |
| ChatGPT signed-in web | [GPT-6 and other models in ChatGPT](https://help.openai.com/en/articles/20001354-gpt-6-and-other-models-in-chatgpt); [GPT-6 for everyone](https://openai.com/index/gpt-6-for-everyone/) | The Help page lists GPT-6 and GPT-5.6 by product/plan but is currently HTTP 403 from the Philippines VPS. The response is a Cloudflare challenge (`cf-mitigated: challenge`); both curl's default User-Agent and the manager's User-Agent receive it with successful TLS. The public OpenAI product announcement independently supplies positive GPT-6 evidence for ChatGPT when reachable and is parsed only for the exact `gpt-6` family. Neither source is a complete selector inventory; absence cannot delete a mapping. |
| OpenAI Codex with ChatGPT sign-in | [Codex models](https://developers.openai.com/codex/models) | Codex model names and Codex-scoped lifecycle notes; not a complete ChatGPT web catalog |
| OpenAI cross-product lifecycle | [ChatGPT & Codex changelog](https://learn.chatgpt.com/docs/changelog) | A retirement becomes accepted-union negative evidence only when one official Codex changelog entry explicitly says the exact GPT model retires from both ChatGPT web/Work and Codex. A Codex-only statement, including “Codex with ChatGPT sign-in,” does not establish that the ChatGPT web product retired the model. |
| Claude consumer web | [Paid Claude plan context window](https://support.claude.com/en/articles/8606394-how-large-is-the-context-window-on-paid-claude-plans) | Names under “Chatting with Claude”; a display name maps only when it has an exact crosswalk in the [Claude Code model configuration](https://support.claude.com/en/articles/11940350-claude-code-model-configuration) |
| Claude Code sign-in | [Claude Code model configuration](https://support.claude.com/en/articles/11940350-claude-code-model-configuration) | Positive exact model IDs for Claude Code; consumer selector retirement is product/plan scoped |
| Kimi consumer web | [Kimi Agentic Chat guide](https://www.kimi.com/en/help/new-user-guide/agentic-chat) | K3 has a tested exact ID crosswalk to `k3`; K2.6 and K3 Cluster remain unclassified because this page does not provide exact IDs |
| Kimi Code sign-in | [Kimi Code models](https://www.kimi.com/en/help/kimi-code/models) | Exact model IDs for Kimi Code; not a complete Kimi web catalog |
| Grok consumer web | [Grok 4.5 announcement](https://x.ai/news/grok-4-5-everywhere) | Positive evidence is accepted only when the announcement explicitly connects an exact model ID to grok.com. The generic overview's `Meet grok-…` banner is not model-specific web availability evidence: its current banner links to the Grok 4.7 announcement, whose availability statement names Grok Build/API and partner coding products without establishing consumer grok.com access. Neither source is a complete selector inventory; the news index remains blocked/stale in the local runtime, and source absence cannot delete a mapping. |

These product sources remain independent surfaces. A Claude consumer-selector
retirement cannot suppress a current exact Claude Code listing. OpenAI Codex
retirement remains scoped to Codex unless the official notice explicitly names
both ChatGPT and Codex; only that cross-product wording qualifies for
accepted-union exclusion. Grok Build, Cursor, API, cloud, and developer
listings do not establish Grok consumer web availability.

For the user's requested stale-version screening, the official Codex signed-in
model listing and the exact Grok consumer-web announcement also establish a
version floor for their own canonical version families. An observed candidate
strictly below that source's lowest currently listed canonical version is
reported as `unavailable` with `accepted_union_version_floor` and the source
URL/hash. This is a conservative negative inference within the same family;
it does not make higher unlisted versions available, and the separate
`gpt-5.3-codex-spark` family does not lower the base GPT floor. Exact current
positive evidence remains required to mark a model `available`.

When accepted-union evidence marks an exact model unavailable, discovery
includes removal proposals for mappings that point to that model even if this
tool did not previously manage those mapping keys. This is necessary to clean
legacy relay mappings. The proposals remain subject to the normal immutable
plan and source/mapping snapshot checks, and backup before remote writes.
Manual apply requires confirmation of the exact plan hash. Configured
`approved_rules` automatic apply may consume fresh matching evidence without a
per-plan confirmation; enabling it is the operator's standing authorization
for rules whose raw hash is pinned in config. Only the bound Codex/Grok version
floor sources and the bound OpenAI cross-product retirement source can propose
removal of unmanaged mappings. Account-scoped API catalog absences retain the
stricter managed-mapping ownership and drift checks.

The Claude consumer display-name aliases are explicitly cross-checked by a
focused test against exact IDs in the official Claude Code model page fixture;
the Kimi K3 → `k3` alias is similarly checked against the official Kimi Code
model-ID fixture. These checks validate the curated crosswalk, not account or
plan entitlements. In the 2026-10-18 local live probe, Codex returned 16 raw
IDs, Claude Code 14, Claude consumer 11, Kimi Code 4, Kimi web 1, and the Grok
announcement 1 (`grok-4.5`). The ChatGPT guide returned HTTP 403. These source
catalogs are partial; the observed counts are not deletion criteria.

For OpenAI, the explicit alias map currently covers `gpt-5.6` to
`gpt-5.6-sol`, `gpt-5.6-terra`, and `gpt-5.6-luna`; `gpt-6` to
`gpt-6-astra`, `gpt-6-sol`, and `gpt-6-luna`; and `gpt-6.1` to
`gpt-6.1-sol`. Unlisted suffixes such as `-openai-compact` are not inferred.

The API lifecycle sources remain useful for reports and investigation. They
are excluded from positive product eligibility and cannot override a product
source's scope or completeness. The OpenAI, Claude, and Kimi model-name
crosswalks are intentionally narrow and covered by focused parser tests; no
suffix or version-family rule is used to manufacture an ID.

## HTTP rate-limit retries

Official-source GETs retry HTTP 429 at most three times after the initial
request, with exponential delays of 1, 2, and 4 seconds. A valid `Retry-After`
value overrides that delay up to an 8-second maximum; a longer server-requested
wait is not retried early. Retries count against the shared startup GET budget
and stop when the sync context is cancelled; cancellation is reported separately
from an exhausted 429 retry. If `Retry-After` exceeds 8 seconds, the source is
not retried during that fetch rather than retrying before the server's requested
time. Exhaustion preserves the 429 failure and last-good snapshot as stale diagnostic context only; it cannot
establish model availability, absence, retirement, or version-floor evidence.

## Volcengine Ark account inventory

The `volcengine-ark-account-models` adapter calls the official
[`ListModelActivations` API](https://docs.volcengine.com/docs/ark/list-model-activations-api?lang=en)
using `VOLCENGINE_ARK_CREDENTIAL_FILE` as a path to a local AK/SK label/value
file. Requests filter to `Available` and exclude deprecated models. The
adapter validates every page and the reported total before treating the
response as complete. Credentials are read at runtime and are never written to
the source cache or reports; the private cache stores only the returned model
IDs and response digests.

This is an account-scoped hosting-platform reference, not a global model maker
catalog or a web/Codex selector list. It applies only to 404token accounts
whose platform is exactly `volcengine`. Exact IDs in a fresh complete response
are available in that Ark account; omissions become `official_account_absence`
only after a successful current fetch. Offline snapshots, stale fallback after
a failed request, missing credentials, incomplete pagination, and expired
snapshots are `insufficient_evidence` and cannot generate removal candidates.
Existing mapping ownership and drift checks still apply before a removal is
planned.

Set the environment variable before starting the screener, for example:

```powershell
$env:VOLCENGINE_ARK_CREDENTIAL_FILE = 'C:\Users\<user>\Desktop\case\火山Access Key ID.txt'
```

The file should contain `Access Key ID` and `Secret Access Key` labels, each
followed by its value (or label/value pairs separated by `:` or `=`). Do not
put credential values in JSON config, command arguments, or logs.

## Alibaba Bailian Beijing Model Studio API catalog

The `alibaba-model-studio-models` adapter calls the official regional model
catalog at `GET https://ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com/api/v1/models`
with `page_no` and `page_size=200`, using the standard Model Studio API key in
`DASHSCOPE_API_KEY`. It requires every page through the response's
`output.total`, consistent pagination metadata, a non-empty exact model-ID
list, and rejects duplicates or truncated pages. This is a metadata GET and
does not call model inference.

The regional catalog is used only for literal `platform=alibaba` upstreams
whose configured `BaseURL` uses this exact Beijing Workspace host. The source
host is checked both during evaluation and again before normalization, so a
same-platform upstream from another workspace, region, HTTP endpoint, or proxy
gets `insufficient_evidence`. Exact listed IDs are present in the official
Beijing Model Studio API catalog; omissions in a fresh, complete catalog are
unavailable only for that workspace-scoped regional API catalog. This does not
establish availability in ChatGPT-like web products, other Bailian regions,
workspace-specific inference permissions, or all Alibaba-published products.
The Workspace ID is the public endpoint identifier, not a credential. Cache
partitions are keyed by a SHA-256 fingerprint; the raw key is not persisted or
logged. Missing credentials, API failures, stale/offline
data, and malformed or incomplete pagination remain
`insufficient_evidence`; existing mapping ownership and drift checks still
apply.

Set the key only in the process environment before starting the screener:

```powershell
$env:DASHSCOPE_API_KEY = '<Model Studio API key>'
```

Do not paste the key into source files, JSON config, command-line arguments, or
logs. Keys shared in chat should be rotated after testing.

## Product coverage still insufficient for automatic import/removal

No general/exhaustive product catalog adapter is currently registered for
DeepSeek, Alibaba/Qwen outside the Beijing Model Studio API catalog above,
Z.ai/GLM, MiniMax, Doubao, Google/Gemini, Tencent/Hy4, Xiaomi/MiMo, Meta/Muse,
or LongCat. Their model IDs are recognized by vendor namespace so 404token
observations are not automatically imported; for these vendors, unsupported
source absence remains insufficient_evidence. Grok has a partial announcement
adapter as described above; it cannot establish absence from the consumer
selector.

The Beijing Model Studio API catalog is an explicit Alibaba API-platform
exception. Its regional exact-ID absence can mark an Alibaba upstream model
unavailable within that API catalog, subject to the manual plan/apply and
managed-mapping ownership and drift gates. It does not establish absence from Alibaba's web
products or other regions. For web/login product union decisions, no current
catalog or lifecycle source has exhaustive accepted-product coverage.

Research has identified product-specific evidence for some of these vendors,
including ZCode built-ins, MiniMax M3, Meta Muse Code, Xiaomi MiMo variants,
Tencent Hy4 Preview, and consumer Grok Image/Video variants. These sources are
not yet wired into exact-ID adapters here, and they do not all establish
exhaustive selector snapshots. DeepSeek, Qwen, Doubao, Gemini, and LongCat
login selector coverage remains inconclusive or non-exhaustive. Future
adapters should cite and parse the primary official product page; do not treat
the 404token or API catalog as a substitute.

Official references identified but not yet wired as exact catalog adapters
include the [ChatGPT Images 2.5 announcement](https://openai.com/index/introducing-chatgpt-images-2-5/),
[Claude Haiku 4.5 selector retirement notice](https://support.claude.com/en/articles/17444146-claude-haiku-4-5-is-leaving-the-model-selector),
[ZCode configuration](https://zcode.z.ai/en/docs/configuration),
[MiniMax M3](https://www.minimax.io/models/text/m3), and
[Meta AI models](https://dev.meta.ai/docs/models). These are positive or
product-scoped research references only; the automated evaluator does not
infer exact IDs or vendor-wide absence from them.

## Plan and apply behavior

Each automatic identity-sync plan records per-model `available`,
`unavailable`, or `insufficient_evidence` and binds the evidence to the plan
digest. A positive record contains the exact source ID, URL, content hash, and
retrieval time. Incomplete source coverage cannot create an unavailable
record. Apply replays the exact availability decisions from the approved plan;
it does not turn missing evidence into a negative decision.

The 404token live directory remains the routing feasibility input. Product
evidence controls which live IDs can be newly identity-imported. A mapped ID
with insufficient official evidence is preserved. A product-scope retirement
is not a vendor-wide removal unless its source is explicitly declared to cover
the accepted union.
