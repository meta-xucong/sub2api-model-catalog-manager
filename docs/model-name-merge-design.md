# Conservative model-name merge review

## Goal and boundary

This feature adds best-effort, report-only name recommendations after official exact-ID availability screening. It does not alter product eligibility, create aliases, update version-family rules, modify mappings, or generate an apply plan. Existing approved `AliasRule` and `VersionFamily` rules remain the only executable merge instructions.

Each recommendation is isolated to one account and its source fingerprint. Original upstream IDs are retained byte-for-byte. The report includes mapping ownership (`managed`, `unmanaged`, or `drifted`), exact availability skip reasons, and partial explicit-rule conflicts.

## Eligibility gate

The discovery report transports the post-screening status and match kind for each exact model ID. A live ID can enter a recommendation only when its status is `available`, its match kind is official `exact` or reviewed `explicit_alias`, and its provider is present. A model retained only because a 404token account probe succeeded (`account_probe_success`) is excluded: probe success does not establish official product availability. Missing evidence, `insufficient_evidence`, and `unavailable` IDs are also excluded and reported with a reason. The report-review code never infers availability from an ID's spelling, another account, or another source.

For date candidates, both the dated exact ID and the undated exact ID must independently be present in the live directory and have exact `available` product evidence. Date removal is never part of the normalizer.

## Deterministic name shape

The low-confidence normalizer only folds ASCII letters to lowercase and changes `_` to `-`. It preserves dots, every version/date/capability suffix, quantization, context length, and region. IDs containing unsupported characters are skipped from normalized candidates. A normalized key with more than one exact live and available ID yields a candidate with `action=none`, `equivalence=unproven`, and `decision_required=true`.

This deliberately misses many real aliases. It avoids speculative semantic matching: `fast`, `compact`, `thinking`, `reasoning`, `vision`, `code`, `codex`, `preview`, `exp`, `mini`, `nano`, `pro`, `max`, `flash`, `lite`, `sol`, `terra`, `luna`, `astra`, `latest`, `stable`, `auto`, dates, quantization, context sizes, and regions remain distinct. Broader aliases require separate evidence and explicitly reviewed rules.

## Rule and ownership reporting

Recommendations show how many approved source-scoped alias and family rules already touch candidate members. A rule covering only a subset is marked as a conflict and blocks any interpretation that the whole group is already governed consistently. The candidate itself remains non-actionable in all cases. Related mappings are matched by exact candidate IDs and classified using local ownership state and source fingerprint.

## Limitations

- Official web/login source completeness remains a separate concern. This report can only recommend among IDs whose current exact product status is positively available.
- Case-fold and underscore folding can still join distinct provider IDs. That is why these are human-review candidates only, never automatic merges.
- The report is based on separate inspect and discover snapshots; mapping drift must be reviewed before a later rules change.
- No candidate is proof of equivalence or a recommendation of which upstream ID to prefer.
