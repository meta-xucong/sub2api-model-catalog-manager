package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestModelProbeDigestValidatesAggregateAndAccountOrder(t *testing.T) {
	valid := ModelProbeDecision{ModelID: "gpt-5.5", Status: "available", ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 3, Reason: "probe"}, {AccountID: 9, Reason: "probe"}}, Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "succeeded"}, {AccountID: 9, Outcome: "not_attempted_after_success"}}}
	if _, err := ModelProbeDigest([]ModelProbeDecision{valid}); err != nil {
		t.Fatalf("valid one-success aggregate rejected: %v", err)
	}
	allFailed := ModelProbeDecision{ModelID: "grok-4.5", Status: "unavailable", ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 3, Reason: "probe"}, {AccountID: 9, Reason: "official_unavailable"}}, Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "failed"}, {AccountID: 9, Outcome: "failed"}}}
	if _, err := ModelProbeDigest([]ModelProbeDecision{allFailed}); err != nil {
		t.Fatalf("complete all-failed aggregate rejected: %v", err)
	}
	ignored := ModelProbeDecision{ModelID: "codex-auto-review", Status: "ignored", ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 3, Reason: "probe"}, {AccountID: 9, Reason: "probe"}}, Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "incomplete"}, {AccountID: 9, Outcome: "failed"}}}
	if _, err := ModelProbeDigest([]ModelProbeDecision{ignored}); err != nil {
		t.Fatalf("incomplete probe was not accepted as an ignored candidate: %v", err)
	}
	ignoredWithOfficialPositive := ModelProbeDecision{ModelID: "gpt-5.5", Status: "ignored", ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 3, Reason: "probe"}, {AccountID: 9, Reason: "official_available"}}, Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "failed"}}}
	if _, err := ModelProbeDigest([]ModelProbeDecision{ignoredWithOfficialPositive}); err != nil {
		t.Fatalf("probe failure with an exact official-positive account was not safely ignored: %v", err)
	}
	availableAfterIncomplete := ModelProbeDecision{ModelID: "gpt-6-sol", Status: "available", ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 3, Reason: "probe"}, {AccountID: 9, Reason: "probe"}}, Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "incomplete"}, {AccountID: 9, Outcome: "succeeded"}}}
	if _, err := ModelProbeDigest([]ModelProbeDecision{availableAfterIncomplete}); err != nil {
		t.Fatalf("a later exact success did not override an earlier incomplete probe: %v", err)
	}
	for _, invalid := range []ModelProbeDecision{
		{ModelID: "gpt-5.5", Status: "available", Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "failed"}}},
		{ModelID: "gpt-5.5", Status: "unavailable", Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "succeeded"}}},
		{ModelID: "gpt-5.5", Status: "available", Accounts: []ModelProbeOutcome{{AccountID: 9, Outcome: "succeeded"}, {AccountID: 3, Outcome: "not_attempted_after_success"}}},
		{ModelID: "gpt-5.5", Status: "available", Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "succeeded"}, {AccountID: 9, Outcome: "failed"}}},
		{ModelID: "gpt-5.5", Status: "unavailable", Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "incomplete"}}},
		{ModelID: "gpt-5.5", Status: "ignored", Accounts: []ModelProbeOutcome{{AccountID: 3, Outcome: "failed"}}},
	} {
		if _, err := ModelProbeDigest([]ModelProbeDecision{invalid}); err == nil {
			t.Errorf("invalid probe aggregate accepted: %#v", invalid)
		}
	}
}

func TestCascadedEvidenceRequiresMatchingUnavailableFloor(t *testing.T) {
	when := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	trigger := ProductModelAvailability{ModelID: "gpt-5.5", Provider: "openai", Status: "unavailable", MatchKind: "accepted_union_retirement", SourceIDs: []string{"openai-cross-product-lifecycle-v2"}, SourceURLs: []string{"https://learn.chatgpt.com/docs/changelog"}, ContentSHA256: []string{strings.Repeat("a", 64)}, RetrievedAt: when}
	cascaded := ProductModelAvailability{ModelID: "gpt-5.5-fast", Provider: "openai", Status: "unavailable", MatchKind: "lower_than_unavailable_version", VersionFloorModelID: "gpt-5.5", SourceIDs: append([]string(nil), trigger.SourceIDs...), SourceURLs: append([]string(nil), trigger.SourceURLs...), ContentSHA256: append([]string(nil), trigger.ContentSHA256...), RetrievedAt: when}
	if !hasValidatedVersionFloorProof(ApprovalPlan{Accounts: []Plan{{ProductAvailability: []ProductModelAvailability{trigger, cascaded}}}}, []ProductModelAvailability{cascaded}) {
		t.Fatal("cascaded evidence with a matching unavailable trigger was rejected")
	}
	if hasValidatedVersionFloorProof(ApprovalPlan{Accounts: []Plan{{ProductAvailability: []ProductModelAvailability{cascaded}}}}, []ProductModelAvailability{cascaded}) {
		t.Fatal("cascaded evidence without its unavailable trigger was accepted")
	}
}

func TestCascadeOverridesLowerModelProbeDecisionWithoutParticipantEvidence(t *testing.T) {
	when := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	higher := ModelProbeDecision{
		Provider: "openai", ModelID: "gpt-5.5", Status: "unavailable",
		ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 7, Reason: "probe"}},
		Accounts:      []ModelProbeOutcome{{AccountID: 7, Outcome: "failed"}},
	}
	lower := ModelProbeDecision{
		Provider: "openai", ModelID: "gpt-5.4", Status: "available",
		ScopeAccounts: []ModelProbeScopeAccount{{AccountID: 7, Reason: "probe"}},
		Accounts:      []ModelProbeOutcome{{AccountID: 7, Outcome: "succeeded"}},
	}
	digest, err := ModelProbeDigest([]ModelProbeDecision{higher, lower})
	if err != nil {
		t.Fatalf("valid pre-cascade probe decisions were rejected: %v", err)
	}
	higherBody, err := json.Marshal(higher)
	if err != nil {
		t.Fatalf("higher unavailable probe decision could not be serialized: %v", err)
	}
	higherHash := sha256.Sum256(higherBody)
	higherDigest := hex.EncodeToString(higherHash[:])
	trigger := ProductModelAvailability{
		ModelID: "gpt-5.5", Provider: "openai", Status: "unavailable", MatchKind: "all_account_probes_failed",
		SourceIDs: []string{"404token-account-probe-v1"}, SourceURLs: []string{"https://404token.xyz/api/v1/admin/accounts/{account_id}/test"},
		ContentSHA256: []string{higherDigest}, RetrievedAt: when,
	}
	cascaded := ProductModelAvailability{
		ModelID: "gpt-5.4", Provider: "openai", Status: "unavailable", MatchKind: "lower_than_unavailable_version", VersionFloorModelID: "gpt-5.5",
		SourceIDs: append([]string(nil), trigger.SourceIDs...), SourceURLs: append([]string(nil), trigger.SourceURLs...),
		ContentSHA256: append([]string(nil), trigger.ContentSHA256...), RetrievedAt: when,
	}
	source := Source{Platform: "openai", AccountType: "apikey", APIProtocol: "openai", BaseURL: "https://api.example/v1", AccountID: 7}
	productAvailability := []ProductModelAvailability{trigger, cascaded}
	productDigest, err := ProductAvailabilityDigest(productAvailability)
	if err != nil {
		t.Fatalf("product availability digest failed: %v", err)
	}
	directoryDigest, err := DirectoryDigest(nil, false, nil)
	if err != nil {
		t.Fatalf("directory digest failed: %v", err)
	}
	lifecycleDigest, err := LifecycleEvidenceDigest(nil, nil)
	if err != nil {
		t.Fatalf("lifecycle digest failed: %v", err)
	}
	now := when.Add(time.Minute)
	plan := ApprovalPlan{
		SchemaVersion: ApprovalPlanSchemaVersion, CreatedAt: now, ExpiresAt: now.Add(ApprovalPlanTTL),
		Target:       TargetBinding{Origin: "https://404token.xyz", BuildID: "test-build", APIContractID: "admin-catalog-v1"},
		AccountScope: "allowlist", RulesSHA256: strings.Repeat("b", 64), StateSHA256: strings.Repeat("c", 64),
		ModelProbeDecisions: []ModelProbeDecision{higher, lower}, ModelProbeSHA256: digest,
		Accounts: []Plan{{
			AccountID: 7, Source: source, SourceFingerprint: SourceFingerprint(source), DirectoryHash: directoryDigest,
			CatalogObservedAt: when, LifecycleEvidenceSHA256: lifecycleDigest, ProductAvailabilityEnforced: true,
			ProductAvailability: productAvailability, ProductAvailabilitySHA256: productDigest,
			CatalogModels: []string{}, CatalogWarningCodes: []string{}, Before: map[string]string{"old-gpt": "gpt-5.5", "older-gpt": "gpt-5.4"},
			After: map[string]string{}, Conflicts: []string{}, AbsenceCountsBefore: map[string]int{}, AbsenceCountsAfter: map[string]int{},
		}},
	}
	if err := plan.ValidateShape(now); err != nil {
		t.Fatalf("valid equal-version failure cascade should pass full approval validation: %v", err)
	}
	badTrigger := trigger
	badTrigger.ContentSHA256 = []string{strings.Repeat("f", 64)}
	badCascade := cascaded
	badCascade.ContentSHA256 = append([]string(nil), badTrigger.ContentSHA256...)
	if hasValidatedVersionFloorProof(ApprovalPlan{Accounts: []Plan{{ProductAvailability: []ProductModelAvailability{badTrigger, badCascade}}}, ModelProbeDecisions: []ModelProbeDecision{higher}}, []ProductModelAvailability{badCascade}) {
		t.Fatal("a probe floor with a mismatched source hash was accepted")
	}
}
