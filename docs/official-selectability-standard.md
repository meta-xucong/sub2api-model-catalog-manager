# Official Account Selectability as the Model Eligibility Standard

## Decision

The exact, complete, current model list shown as selectable by the corresponding
official account is the sole authority for whether a model is retained in a
Sub2API mapping.

The Sub2API live catalog is a routing-feasibility check: a model must be present
there before the manager adds or changes a route. Its absence does not retire a
model that remains selectable in the official account. Static keep rules,
retirement documents, and upstream catalog presence cannot override the
official selector snapshot.

If a complete selector snapshot is missing, expired, future-dated, or
ambiguous, discovery produces a blocked plan. It must not infer that an empty
or missing list means every model is unavailable.

## Snapshot contract

Each approved source profile identifies an `official_selectability_scope` using
an operator-assigned stable alias for the concrete official account, for
example `official-account:404token-account-8`. Provider/protocol categories
such as `openai_codex_chatgpt_login` are not valid account identities. Profiles
may share one alias only when they intentionally use the same official account.
official_selectability contains one complete snapshot for that scope:

    {
      "official_selectability": [
        {
          "scope": "official-account:404token-account-8",
          "complete": true,
          "model_ids": ["model-id-copied-from-the-official-selector"],
          "observed_at": "2026-10-17T08:00:00Z",
          "expires_at": "2026-10-18T08:00:00Z",
          "evidence": "Operator-captured complete model selector for the approved account scope"
        }
      ]
    }

The operator must refresh the list from that exact official account's selector and attest
that the captured list is complete. The manager does not currently scrape an
authenticated account selector, so an upstream /models response or official
documentation page must not be substituted as evidence. A snapshot can be valid
for no more than 24 hours.

## Reconciliation behavior

- Current mapping points to a model absent from the official selector:
  remove it only when this manager still owns the exact unchanged mapping.
  Unowned or drifted mappings block the account plan; they are never overwritten
  or removed automatically.
- Current mapping points to a selectable model absent from the Sub2API live
  list: keep the mapping. Do not treat a temporary upstream omission as model
  retirement.
- New mapping: require both official selectability and an exact usable
  Sub2API live model ID, plus the existing source/rule policy for the mapping.
- Wildcard routing entries (`*`, `gpt-*`, and similar patterns) are routing
  policy, not concrete official model IDs. The selector cannot classify them;
  they retain the existing ownership and routing policy and are excluded from
  model-retirement decisions.
- Keep, hide, retirement, and documentation lifecycle rules cannot retain
  or remove a model against the official selector result.
- Existing lifecycle documents remain report context only. Their fetch status
  no longer changes the mapping result.

The official selector scope, snapshot digest, observation time, and expiry are
included in each approval plan. Apply recomputes the plan against the same
rules file; raw rules hash drift, snapshot expiry, or selector changes block the
write.

## Why the earlier removals happened

The October 17, 2026 full-screen execution report recorded 24 removals across
accounts 8, 11, 13, and 20. It used rules SHA-256
76288cde545e6869f62bb2c1683e560066913eafa050965fe65e4dc1e49b3500, whose
owner_lifecycle_exclusions contained seven owner-confirmed unavailable IDs,
including gpt-5.2, gpt-5.2-pro, and gpt-5.4.

A later preview used rules SHA-256 2b591b750d..., which had no such exclusions.
The implementation still had static version-family keep entries, so that
different ruleset proposed nine re-additions. That later plan was preview-only
and was not applied. Therefore, the deletion did have an active rule; the
defect was that deletion and later screening used different rulesets, with no
positive complete selector snapshot binding every run.

This change makes the evidence positive, complete, time-bounded, and bound into
the approval/apply contract. Existing remote mappings are not changed by this
code change.

## Verification scope

Regression tests cover:

- an officially unavailable model is removed even when present in the
  Sub2API catalog and marked keep;
- an officially selectable model remains even when a static retirement rule
  says otherwise or the Sub2API catalog omits it;
- missing and expired snapshots produce no mapping changes;
- changing the selector snapshot invalidates an existing approved plan.

