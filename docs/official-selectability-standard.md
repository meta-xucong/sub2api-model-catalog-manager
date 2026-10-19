# Historical: Official Product Selectability as the Model Eligibility Standard

> **Superseded; do not use as the current eligibility contract.** This document
> records the earlier API-key catalog and account-selector snapshot design.
> Current eligibility uses only exact evidence from accepted official web or
> login products, as described in
> [`official-product-availability.md`](official-product-availability.md).
> API-key model lists and API lifecycle sources cannot establish login-product
> eligibility. Product-scoped retirement cannot remove an ID from a wider
> accepted-product union unless complete evidence covers that union.

## Decision

Eligibility evidence is product-specific. A model list from one product must
never be used to claim availability in another product.

- For a scope explicitly bound to a provider's **API-key product**, that
  provider's documented authenticated model-access API is authoritative for
  models visible to that API credential. This proves catalog visibility for
  that credential; it does not prove every operation, quota, region, or
  successful inference call is available.
- For ChatGPT, Codex, Claude web/Code, and other **UI products**, only that
  product's own official model selector is authoritative. API `/models`, public
  lifecycle pages, gateway catalogs, and model names cannot substitute.
- The Sub2API live catalog is only a routing-feasibility check. Its absence
  does not retire a model still present in the bound official product snapshot.
- Static keep/retirement rules cannot override a fresh complete product
  snapshot.

If a required snapshot is missing, expired, future-dated, ambiguous, or bound
to a different product, discovery blocks. It must not infer that an empty or
missing list means every model is unavailable. API scopes require a configured
automatic collector and cannot silently fall back to a manually pasted
snapshot. UI scopes may use a complete, fresh manual selector capture until a
supported selector adapter exists.

## Snapshot contract

Each approved source profile identifies an `official_selectability_scope` using
an operator-assigned stable alias for the concrete official account and
product, for example `official-account:openai-api-account-8` or
`official-account:chatgpt-ui-account-8`. Provider/protocol categories such as
`openai_codex_chatgpt_login` are not account identities. Profiles may share an
alias only when they intentionally share the same account and product.

API profiles declare both `official_selectability_product: "api"` and an
`official_selectability_provider` matching the configured fixed adapter. UI
profiles declare `official_selectability_product: "ui"` and no API provider.
Unclassified legacy scopes block until an operator reviews and classifies the
actual product. API profiles without a matching automatic source block. UI
manual snapshots in `model-rules.json` retain this shape:

    {
      "official_selectability": [
        {
          "scope": "official-account:chatgpt-ui-account-8",
          "complete": true,
          "model_ids": ["model-id-copied-from-the-official-selector"],
          "observed_at": "2026-10-17T08:00:00Z",
          "expires_at": "2026-10-18T08:00:00Z",
          "evidence": "Operator-captured complete UI selector for the approved account scope"
        }
      ]
    }

Current API adapters fetch authenticated model catalogs directly from fixed
official provider origins. The HTTP response does not prove a human-readable
account identity. The scope-to-provider/product/credential-reference relation
is an operator-owned configuration binding and must not be described as
identity verified by the provider response. Snapshots are valid for no more
than 24 hours.

## Reconciliation behavior

- Current mapping points to a model absent from the bound official product
  snapshot: remove it only when this manager still owns the exact unchanged
  mapping. Unowned or drifted mappings block the account plan.
- Current mapping points to a selectable model absent from the Sub2API live
  list: keep the mapping. A temporary gateway omission is not retirement.
- New mapping: require both official product availability and an exact usable
  Sub2API live model ID, plus existing source/rule policy.
- Wildcard routes (`*`, `gpt-*`, and similar patterns) are routing policy, not
  concrete model IDs. They retain existing ownership policy and are excluded
  from model-retirement decisions.
- Static keep, hide, retirement, and lifecycle rules cannot override a fresh
  complete product snapshot.
- The scope, snapshot digest, observation time, and expiry are included in each
  approval plan. Apply rechecks the static rules hash and exact dynamic
  snapshot digest; source-binding drift, snapshot expiry, or selector changes
  block writes.

## Earlier removal discrepancy

The October 17, 2026 full-screen execution report recorded 24 removals across
accounts 8, 11, 13, and 20. It used rules SHA-256
`76288cde545e6869f62bb2c1683e560066913eafa050965fe65e4dc1e49b3500`, whose
owner lifecycle exclusions included seven owner-confirmed unavailable IDs,
including `gpt-5.2`, `gpt-5.2-pro`, and `gpt-5.4`.

A later preview used rules SHA-256 `2b591b750d...`, which lacked those
exclusions. The implementation still had static version-family keep entries,
so that different ruleset proposed nine re-additions. The later plan was
preview-only and was not applied. The removals had an active rule; the defect
was that different runs used different rule evidence without a positive,
complete product snapshot bound into each approval.

## Verification scope

Regression tests cover:

- officially unavailable IDs are removed even if present in Sub2API and marked
  keep;
- officially available IDs remain even if static retirement says otherwise
  or Sub2API temporarily omits them;
- missing/expired evidence blocks changes;
- changing the snapshot invalidates an approved plan;
- API scopes without a matching automatic source and API/provider mismatches
  fail closed, while UI manual snapshots remain supported.
