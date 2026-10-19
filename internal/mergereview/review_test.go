package mergereview

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sub2api-model-catalog-manager/internal/catalog"
	"sub2api-model-catalog-manager/internal/state"
)

func TestBuildReportsSameSourceDateFamilyWithoutApprovingIt(t *testing.T) {
	inspect, discover, source := reviewFixture(t)
	rules := catalog.Rules{
		SchemaVersion: 1,
		VersionFamilies: []catalog.VersionFamily{{
			Source:              source,
			PublicID:            "deepseek-v4-flash",
			PreferredUpstreamID: "deepseek-v4-flash-20261002",
			Members: []catalog.FamilyMember{
				{UpstreamID: "deepseek-v4-flash", ExactIDAction: "keep"},
				{UpstreamID: "deepseek-v4-flash-20261001", ExactIDAction: "hide"},
				{UpstreamID: "deepseek-v4-flash-20261002", ExactIDAction: "keep"},
			},
			Decision: "approved", Evidence: "operator-reviewed source evidence", ReviewedAt: "2026-10-12",
		}},
	}
	if err := rules.Validate(); err != nil {
		t.Fatal(err)
	}
	local := state.Empty()
	out, err := Build(inspect, discover, rules, strings.Repeat("a", 64), local, time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if out.RuleCounts.VersionFamilies != 1 || out.Summary.DateFamilyCandidates != 1 || out.Summary.CandidatesWithCompleteRule != 1 {
		t.Fatalf("unexpected review counts: %#v %#v", out.RuleCounts, out.Summary)
	}
	candidate := out.Accounts[0].DateFamilies[0]
	if candidate.PublicIDCandidate != "deepseek-v4-flash" || candidate.Equivalence != "unproven" || candidate.Action != "none" || !candidate.DecisionRequired {
		t.Fatalf("candidate was approved or changed: %#v", candidate)
	}
	if candidate.DiscoverFamilyChanges != 1 || candidate.UnmanagedHideTargets != 1 || candidate.NoMergeReason != "hide_or_rewrite_requires_explicit_adoption_of_unmanaged_mapping_keys" {
		t.Fatalf("missing apply/readiness blocker: %#v", candidate)
	}
	if len(candidate.Members) != 3 || candidate.Members[0].UpstreamID != "deepseek-v4-flash" {
		t.Fatalf("candidate member list is not exact and sorted: %#v", candidate.Members)
	}
}

func TestBuildDoesNotGroupWithoutExactPrefixOrValidDate(t *testing.T) {
	inspect, discover, _ := reviewFixture(t)
	discover.Discovery[0].Models = []string{"gpt-5.2-2026-02-31", "other-model-20261001", "deepseek-v4-pro-20261001"}
	rules := catalog.Rules{SchemaVersion: 1}
	out, err := Build(inspect, discover, rules, strings.Repeat("b", 64), state.Empty(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if out.Summary.DateFamilyCandidates != 0 {
		t.Fatalf("unproven or invalid names were grouped: %#v", out.Accounts[0].DateFamilies)
	}
}

func TestBuildCreatesConservativeNameRecommendationsOnlyForAvailableExactIDs(t *testing.T) {
	inspect, discover, _ := reviewFixture(t)
	discover.Discovery[0].Models = []string{"GPT_5.6", "gpt-5.6", "gpt-5.6-fast", "gpt-5.6-compact", "opaque/variant", "unlisted"}
	discover.Discovery[0].ProductAvailability = []ProductAvailabilityEvidence{
		{ModelID: "GPT_5.6", Provider: "openai", Status: "available", MatchKind: "exact"},
		{ModelID: "gpt-5.6", Provider: "openai", Status: "available", MatchKind: "exact"},
		{ModelID: "gpt-5.6-fast", Provider: "openai", Status: "available", MatchKind: "exact"},
		{ModelID: "gpt-5.6-compact", Provider: "openai", Status: "available", MatchKind: "exact"},
		{ModelID: "opaque/variant", Provider: "openai", Status: "available", MatchKind: "exact"},
		{ModelID: "unlisted", Provider: "openai", Status: "insufficient_evidence", MatchKind: "none"},
	}
	out, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("1", 64), state.Empty(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	row := out.Accounts[0]
	if len(row.NameMergeCandidates) != 1 {
		t.Fatalf("expected one conservative punctuation/case candidate, got %#v", row.NameMergeCandidates)
	}
	candidate := row.NameMergeCandidates[0]
	if candidate.NormalizedKey != "gpt-5.6" || candidate.Action != "none" || candidate.Equivalence != "unproven" || !candidate.DecisionRequired || len(candidate.Members) != 2 {
		t.Fatalf("candidate overstates merge certainty or changed exact members: %#v", candidate)
	}
	if len(row.NameMergeSkips) != 2 || row.NameMergeSkips[0].ModelID != "opaque/variant" || row.NameMergeSkips[1].Reason != "exact_model_screening_insufficient_evidence" {
		t.Fatalf("missing explicit skip reasons: %#v", row.NameMergeSkips)
	}
}

func TestBuildDateCandidatesRequireEachExactMemberAvailable(t *testing.T) {
	inspect, discover, _ := reviewFixture(t)
	discover.Discovery[0].ProductAvailability[1].Status = "unavailable"
	discover.Discovery[0].ProductAvailability[2].Status = "unavailable"
	out, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("2", 64), state.Empty(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if out.Summary.DateFamilyCandidates != 0 || len(out.Accounts[0].NameMergeSkips) == 0 {
		t.Fatalf("date candidate was formed without every exact member being available: %#v", out.Accounts[0])
	}
}

func TestBuildRejectsDuplicateAvailabilityEvidence(t *testing.T) {
	inspect, discover, _ := reviewFixture(t)
	discover.Discovery[0].ProductAvailability = append(discover.Discovery[0].ProductAvailability, discover.Discovery[0].ProductAvailability[0])
	if _, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("3", 64), state.Empty(), time.Now()); err == nil {
		t.Fatal("duplicate exact availability evidence was accepted")
	}
}

func TestMergeCandidatesRequireApprovedOfficialMatchKinds(t *testing.T) {
	inspect, discover, _ := reviewFixture(t)
	discover.Discovery[0].Models = []string{
		"gpt_5.6", "gpt-5.6",
		"grok_4.5", "grok-4.5",
		"gpt_5.7", "gpt-5.7",
	}
	discover.Discovery[0].ProductAvailability = []ProductAvailabilityEvidence{
		{ModelID: "gpt_5.6", Provider: "openai", Status: "available", MatchKind: "exact"},
		{ModelID: "gpt-5.6", Provider: "openai", Status: "available", MatchKind: "exact"},
		{ModelID: "grok_4.5", Provider: "xai", Status: "available", MatchKind: "explicit_alias"},
		{ModelID: "grok-4.5", Provider: "xai", Status: "available", MatchKind: "explicit_alias"},
		{ModelID: "gpt_5.7", Provider: "openai", Status: "available", MatchKind: "account_probe_success"},
		{ModelID: "gpt-5.7", Provider: "openai", Status: "available", MatchKind: "account_probe_success"},
	}
	out, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("5", 64), state.Empty(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	row := out.Accounts[0]
	if len(row.NameMergeCandidates) != 2 || row.NameMergeCandidates[0].NormalizedKey != "gpt-5.6" || row.NameMergeCandidates[1].NormalizedKey != "grok-4.5" {
		t.Fatalf("exact and explicit-alias official evidence should qualify, probe-only evidence should not: %#v", row.NameMergeCandidates)
	}
	if len(row.NameMergeSkips) != 2 || row.NameMergeSkips[0].Reason != "account_probe_success_is_not_official_product_evidence" || row.NameMergeSkips[1].Reason != "account_probe_success_is_not_official_product_evidence" {
		t.Fatalf("probe-only IDs lack a clear official-evidence skip reason: %#v", row.NameMergeSkips)
	}
}

func TestBuildRejectsAvailabilityWithoutProvider(t *testing.T) {
	inspect, discover, _ := reviewFixture(t)
	discover.Discovery[0].ProductAvailability[0].Provider = ""
	if _, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("6", 64), state.Empty(), time.Now()); err == nil {
		t.Fatal("availability evidence without a provider was accepted")
	}
}

func TestProbeEvidenceWithoutProviderIsReportedAsSkip(t *testing.T) {
	for _, tc := range []struct {
		name, status, kind, skipReason string
	}{
		{name: "success", status: "available", kind: "account_probe_success", skipReason: "account_probe_success_is_not_official_product_evidence"},
		{name: "all_failed", status: "unavailable", kind: "all_account_probes_failed", skipReason: "exact_model_screened_unavailable"},
		{name: "ignored", status: "insufficient_evidence", kind: "account_probe_ignored", skipReason: "exact_model_screening_insufficient_evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inspect, discover, _ := reviewFixture(t)
			discover.Discovery[0].Models = []string{"probe-only", "GPT_5.6", "gpt-5.6"}
			discover.Discovery[0].ProductAvailability = []ProductAvailabilityEvidence{
				{ModelID: "probe-only", Status: tc.status, MatchKind: tc.kind},
				{ModelID: "GPT_5.6", Provider: "openai", Status: "available", MatchKind: "exact"},
				{ModelID: "gpt-5.6", Provider: "openai", Status: "available", MatchKind: "exact"},
			}
			out, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("7", 64), state.Empty(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			row := out.Accounts[0]
			if len(row.NameMergeCandidates) != 1 || len(row.NameMergeSkips) != 1 {
				t.Fatalf("official records should still form the candidate while providerless probe evidence is filtered: %#v", row)
			}
			if row.NameMergeCandidates[0].NormalizedKey != "gpt-5.6" || row.NameMergeCandidates[0].Action != "none" || row.NameMergeSkips[0].Reason != tc.skipReason {
				t.Fatalf("probe-only ID entered or changed a name candidate: %#v", row)
			}
		})
	}
}

func TestProbeEvidenceWithoutProviderRequiresMatchingStatus(t *testing.T) {
	for _, tc := range []struct {
		status string
		kind   string
	}{
		{status: "unavailable", kind: "account_probe_success"},
		{status: "available", kind: "all_account_probes_failed"},
		{status: "available", kind: "account_probe_ignored"},
	} {
		t.Run(tc.status+"/"+tc.kind, func(t *testing.T) {
			inspect, discover, _ := reviewFixture(t)
			discover.Discovery[0].ProductAvailability[0] = ProductAvailabilityEvidence{ModelID: "gpt-5.6", Status: tc.status, MatchKind: tc.kind}
			if _, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("8", 64), state.Empty(), time.Now()); err == nil {
				t.Fatal("providerless probe evidence with mismatched status was accepted")
			}
		})
	}
}

func TestNameMergeCandidateReportsPartialRuleConflictAndMappingOwnership(t *testing.T) {
	inspect, discover, source := reviewFixture(t)
	inspect.Accounts[0].Mappings = append(inspect.Accounts[0].Mappings,
		Mapping{PublicID: "GPT_5.6", UpstreamID: "GPT_5.6"},
		Mapping{PublicID: "gpt-5.6", UpstreamID: "gpt-5.6"},
	)
	values := map[string]string{}
	for _, mapping := range inspect.Accounts[0].Mappings {
		values[mapping.PublicID] = mapping.UpstreamID
	}
	var err error
	inspect.Accounts[0].MappingSHA256, err = catalog.MappingHash(values)
	if err != nil {
		t.Fatal(err)
	}
	discover.Discovery[0].Models = []string{"GPT_5.6", "gpt-5.6"}
	discover.Discovery[0].ProductAvailability = []ProductAvailabilityEvidence{
		{ModelID: "GPT_5.6", Provider: "openai", Status: "available", MatchKind: "exact"},
		{ModelID: "gpt-5.6", Provider: "openai", Status: "available", MatchKind: "exact"},
	}
	rules := catalog.Rules{SchemaVersion: 1, Aliases: []catalog.AliasRule{{
		Source: source, UpstreamID: "GPT_5.6", PublicID: "public-gpt", Decision: "approved", Evidence: "reviewed", ReviewedAt: "2026-10-20",
	}}}
	local := state.Empty()
	local.Accounts["9001"] = state.Account{ManagedMappings: map[string]state.ManagedMapping{
		"GPT_5.6": {LastAppliedValue: "GPT_5.6", SourceFingerprint: inspect.Accounts[0].SourceFingerprint},
	}}
	out, err := Build(inspect, discover, rules, strings.Repeat("4", 64), local, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	candidate := out.Accounts[0].NameMergeCandidates[0]
	if !candidate.RuleConflict || candidate.SkipReason != "explicit_rules_conflict_with_candidate" || candidate.MatchingAliasRules != 1 {
		t.Fatalf("partial explicit alias rule was not exposed as a conflict: %#v", candidate)
	}
	if len(candidate.RelatedMappings) != 2 || candidate.RelatedMappings[0].Ownership != "managed" || candidate.RelatedMappings[1].Ownership != "unmanaged" {
		t.Fatalf("candidate mapping ownership was not reported exactly: %#v", candidate.RelatedMappings)
	}
}

func TestBuildRejectsMismatchedOrPartialReports(t *testing.T) {
	inspect, discover, _ := reviewFixture(t)
	discover.AccountInventorySHA256 = strings.Repeat("f", 64)
	if _, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("c", 64), state.Empty(), time.Now()); err == nil {
		t.Fatal("mismatched report pair was accepted")
	}
	inspect, discover, _ = reviewFixture(t)
	inspect.AccountScanStatus = "partial"
	if _, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("c", 64), state.Empty(), time.Now()); err == nil {
		t.Fatal("partial report was accepted")
	}
}

func TestBuildRequiresSourceFingerprintForCandidateDiscovery(t *testing.T) {
	inspect, discover, _ := reviewFixture(t)
	discover.Discovery[0].SourceFingerprint = ""
	if _, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("e", 64), state.Empty(), time.Now()); err == nil {
		t.Fatal("candidate discovery without a source fingerprint was accepted")
	}

	inspect, discover, _ = reviewFixture(t)
	discover.Discovery[0].SourceFingerprint = strings.Repeat("f", 64)
	if _, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("e", 64), state.Empty(), time.Now()); err == nil {
		t.Fatal("candidate discovery with a mismatched source fingerprint was accepted")
	}
}

func TestBuildAllowsSkippedUnrestrictedAccountWithoutDiscoveryFingerprint(t *testing.T) {
	inspect, discover, _ := reviewFixture(t)
	inspect.Accounts[0].MappingStatus = "no_explicit_mapping"
	inspect.Accounts[0].MappingSHA256 = ""
	inspect.Accounts[0].Mappings = nil
	discover.Discovery[0].SourceFingerprint = ""
	discover.Discovery[0].Status = "skipped_unrestricted_mapping"
	discover.Discovery[0].LiveListAvailable = false
	discover.Discovery[0].Models = nil
	out, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("e", 64), state.Empty(), time.Now())
	if err != nil {
		t.Fatalf("skipped unrestricted account without a candidate should be accepted: %v", err)
	}
	if out.Summary.DateFamilyCandidates != 0 || len(out.Accounts[0].DateFamilies) != 0 || out.Accounts[0].ExcludedReason != "no_eligible_live_catalog" {
		t.Fatalf("skipped unrestricted account was treated as candidate evidence: %#v", out.Accounts[0])
	}
}

func TestBuildFailsClosedOnTamperedMappingHashAndCorruptState(t *testing.T) {
	inspect, discover, _ := reviewFixture(t)
	inspect.Accounts[0].MappingSHA256 = strings.Repeat("f", 64)
	if _, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("e", 64), state.Empty(), time.Now()); err == nil {
		t.Fatal("mapping snapshot with a mismatched hash was accepted")
	}

	inspect, discover, _ = reviewFixture(t)
	corrupt := state.State{Version: state.CurrentVersion + 1, Accounts: map[string]state.Account{}}
	if _, err := Build(inspect, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("e", 64), corrupt, time.Now()); err == nil {
		t.Fatal("corrupt state was accepted")
	}
}

func TestNoExplicitMappingIsValidButCannotAuthorizeCandidateChanges(t *testing.T) {
	if err := validateMappingSnapshot(InspectAccount{ID: 12, MappingStatus: "no_explicit_mapping"}); err != nil {
		t.Fatalf("empty unrestricted mapping should remain a valid read-only observation: %v", err)
	}
	if err := validateMappingSnapshot(InspectAccount{ID: 12, MappingStatus: "no_explicit_mapping", Mappings: []Mapping{{PublicID: "model", UpstreamID: "model"}}}); err == nil {
		t.Fatal("no-explicit-mapping status with mapping rows was accepted")
	}
}

func TestReadReportAndWriteDropUnknownSecretsAndSourceURL(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "inspect.json")
	const sentinel = "MERGE-REVIEW-SECRET-SENTINEL"
	inspect, discover, _ := reviewFixture(t)
	body, err := json.Marshal(inspect)
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimSuffix(string(body), "}") + `,"admin_key":"` + sentinel + `","headers":{"authorization":"` + sentinel + `"}}`
	if err := os.WriteFile(input, []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadReport(input)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Build(loaded, discover, catalog.Rules{SchemaVersion: 1}, strings.Repeat("d", 64), state.Empty(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(dir, "reports")
	path, err := Write(outputDir, out)
	if err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result), sentinel) || strings.Contains(string(result), "base_url") || strings.Contains(string(result), "provider.example") {
		t.Fatal("merge review output exposed an unapproved input field")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.PathSeparator == '/' && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("report permissions are broader than owner-only: %v", info.Mode().Perm())
	}
}

func reviewFixture(t *testing.T) (InputReport, InputReport, catalog.Source) {
	t.Helper()
	source, err := catalog.SourceForAccount("openai", "apikey", "openai", "https://provider.example/v1", 9001)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := catalog.SourceFingerprint(source)
	idsHash, err := catalog.AccountIDsDigest([]int64{9001})
	if err != nil {
		t.Fatal(err)
	}
	mapping := map[string]string{
		"deepseek-v4-flash":          "deepseek-v4-flash",
		"deepseek-v4-flash-20261001": "deepseek-v4-flash-20261001",
	}
	mappingHash, err := catalog.MappingHash(mapping)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 10, 12, 11, 0, 0, 0, time.UTC)
	inspect := InputReport{
		RunID: "inspect-test", CreatedAt: created, Mode: "inspect", AccountScope: "all", AccountScanStatus: "complete",
		AccountInventoryCount: 1, AccountInventorySHA256: idsHash, TargetFingerprint: "build-test",
		Accounts: []InspectAccount{{
			ID: 9001, Platform: source.Platform, AccountType: source.AccountType, APIProtocol: source.APIProtocol,
			BaseURL: source.BaseURL, SourceFingerprint: fingerprint, MappingSHA256: mappingHash, MappingStatus: "explicit_nonempty",
			Mappings: []Mapping{
				{PublicID: "deepseek-v4-flash", UpstreamID: "deepseek-v4-flash"},
				{PublicID: "deepseek-v4-flash-20261001", UpstreamID: "deepseek-v4-flash-20261001"},
			},
		}},
	}
	discover := InputReport{
		RunID: "discover-test", CreatedAt: created.Add(time.Minute), Mode: "discover", AccountScope: "all", AccountScanStatus: "complete",
		AccountInventoryCount: 1, AccountInventorySHA256: idsHash, TargetFingerprint: "build-test",
		Discovery: []DiscoveryAccount{{
			ID: 9001, SourceFingerprint: fingerprint, Status: "candidate_reported", LiveListAvailable: true,
			Models: []string{"deepseek-v4-flash", "deepseek-v4-flash-20261001", "deepseek-v4-flash-20261002"},
			ProductAvailability: []ProductAvailabilityEvidence{
				{ModelID: "deepseek-v4-flash", Provider: "deepseek", Status: "available", MatchKind: "exact"},
				{ModelID: "deepseek-v4-flash-20261001", Provider: "deepseek", Status: "available", MatchKind: "exact"},
				{ModelID: "deepseek-v4-flash-20261002", Provider: "deepseek", Status: "available", MatchKind: "exact"},
			},
			Changes: []MappingChange{{Action: "remove", PublicID: "deepseek-v4-flash-20261001", RuleKind: "version_family"}},
		}},
	}
	return inspect, discover, source
}
