# Official Selectability Auto-Sync and One-Click Screening

## Goal and baseline

Make the existing full-screen command refresh official model-access evidence,
refresh the 404token live catalog, calculate the existing mapping plan, apply
only under the existing approved-rules and mapping-ownership gates, and verify
the write. The code baseline is `87c1fd27845a928c7303dd37c57bc9ac1843d922`.

Current behavior is split across two different sources:

- Startup synchronization fetches public provider lifecycle/release/documentation
  pages. It is useful report context, not account-specific availability.
- Official selectability is required by discovery, but its complete snapshots
  are currently entered by an operator in `model-rules.json`.

Therefore there is automatic official-document synchronization today, but no
automatic account-level selectability synchronization.

## Authority model

The user's decision is to distinguish official products rather than conflate
them:

1. For an account explicitly bound to a provider's API-key product, a documented
   official authenticated model-access endpoint may be the authority for that
   API credential. It does not establish access in a consumer/workspace UI.
2. ChatGPT, Codex, Claude web/Code, and other UI products require that exact
   product's official selector evidence. An API `/models` result is not a
   substitute. Until a supported official selector source is implemented, UI
   scopes stay manual or blocked. API-product scopes without a configured
   matching collector are blocked; they never silently use a pasted snapshot.
3. A 404token/Sub2API `/models` result is only routing feasibility. It cannot
   establish official-provider entitlement.
4. Static rules, release notes, and model names cannot override a complete
   official account snapshot.

Every scoped source profile must explicitly classify its product as
`api` or `ui`. API profiles also declare the provider, and the stable
`official_selectability_scope` must match a local source binding. The profile's
declared provider must match the fixed collector. This is enforced by the
catalog rules schema validator, not only the full-screen CLI, so all readers
reject unclassified legacy scopes until reviewed. Migration requires updating
the reviewed rule file and regenerating/approving its exact SHA. Do not infer
an official provider key from a Sub2API
`base_url`, API protocol, model name, or gateway credential. The API response
confirms a list for the supplied credential, not the real-world identity
behind the operator-assigned alias.

## One-click flow

`run --full-screen` performs these steps in order:

1. Validate the existing target, all-account scope, rules approval, and
   credential-exposure gates before any target write.
2. Refresh every configured official API-key source through a fixed provider
   adapter using a separately provisioned OS credential reference.
3. Validate HTTP status, official origin, response schema, identity/product
   binding, completeness, duplicate/invalid IDs, and pagination termination.
4. Atomically publish a bounded, versioned snapshot artifact outside the rules
   file. Each snapshot binds scope, provider, product, digest, observed/expiry
   times, adapter version, and completeness. Do not persist secrets or raw
   authenticated responses.
5. Refresh the 404token catalog using the existing native path; calculate the
   normal discovery/ownership plan from the freshly loaded snapshot artifact.
6. Apply only if the existing exact static-rules approval matches and all
   current target ownership/drift checks pass. Re-load and verify the exact
   snapshot digest and freshness before applying.
7. Read mappings back and preserve existing reports/backups.

If any configured source is incomplete, unauthorized, stale, ambiguous, or
unsupported, block changes for its scope. Never interpret an empty/error
response as “all models were removed”; never fall back to an older snapshot for
an automatic run.

## Initial supported adapters

Implement only documented official API-key model-access endpoints with fixed
hosts and authentication schemes:

- OpenAI API: `api.openai.com`, bearer key, `GET /v1/models`.
- Anthropic API: `api.anthropic.com`, `x-api-key`, required
  `anthropic-version`, paginated `GET /v1/models`.
- xAI API: `api.x.ai`, bearer key, `GET /v1/models`.
- DeepSeek API: `api.deepseek.com`, bearer key, `GET /models`.

These API catalogs establish only API-key product visibility. The initial
adapter does not scrape ChatGPT/Codex/Claude UI selectors. The exact current
endpoint contracts and authentication headers are captured in tests and linked
in the operator guide to the providers' official API references.

This list establishes API-key product access only. It does not enable any of
these collectors for a ChatGPT/Codex/Claude UI scope. Workspace-specific
endpoints (for example a regional/workspace Model Studio endpoint) require an
explicit adapter with validated region/workspace fields; arbitrary endpoint
URLs are prohibited.

## Secret and network boundary

- Each source entry references Windows Credential Manager or a systemd
  credential; secrets are never stored in JSON config or logs.
- Read a source secret only after validating the source binding. Wipe buffers
  after request completion as far as the runtime permits.
- Disable ambient proxies and redirects for official-source requests.
- Build the URL exclusively from the fixed adapter registry; config cannot set
  host, path, headers, or query templates.
- Bound request timeout, response bytes, page count, ID count, and total
  snapshots. Do not emit response bodies or authorization headers in errors.

## Approval and compatibility

Static policy approval remains the existing rules SHA-256. Dynamic evidence is
stored separately so timestamps do not invalidate static policy approval. The
approval plan continues to bind each account's snapshot digest and expiry.
Apply fails if the evidence artifact changes, expires, or no longer matches the
plan. Existing manual snapshots remain readable for UI scopes until an
officially supported UI selector adapter exists; they remain time-limited and
must be complete. Every API-product source profile must have one matching
configured collector with the same provider, otherwise automatic discovery is
blocked.

## Acceptance

- Unit contract tests for each adapter's auth header, exact URL, schema,
  pagination, empty/malformed responses, HTTP failure, redirect rejection,
  limits, and secret redaction.
- Integration tests prove: refresh → snapshot publication → discovery → plan →
  apply recomputation uses one exact snapshot digest without changing the rules
  hash.
- Different scopes cannot share evidence unless explicitly bound to the same
  credential/product identity.
- Missing/expired/failed sources produce zero mapping writes.
- An official-unavailable model is removed even if present in 404token;
  an officially available API-key model remains even if the gateway catalog
  temporarily omits it.
- Existing manual-only UI selector behavior is preserved and clearly reported
  as requiring a fresh manual snapshot.
- No real provider call or VPS write is part of code tests.

## Deployment boundary

Code integration is not production readiness. Before enabling live sources,
the operator must provision one secure credential reference per official
account scope, verify that the configured product matches the account, review
the static rules hash, and run preview first. Actual API-key catalog results do
not authorize removal from a different UI product. Unsupported UI selectors
remain blocked until a documented/approved official source exists.
