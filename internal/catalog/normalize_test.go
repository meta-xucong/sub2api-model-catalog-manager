package catalog

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"sub2api-model-catalog-manager/internal/state"
)

func sourceFixture() Source {
	return Source{Platform: "openai", AccountType: "apikey", APIProtocol: "openai", BaseURL: "https://provider.example/v1", AccountID: 9001}
}

func TestProductAvailabilityAcceptsAccountScopedOfficialAbsence(t *testing.T) {
	item := ProductModelAvailability{
		ModelID: "doubao-seed-2-0-lite", Provider: "volcengine", Status: "unavailable", MatchKind: "official_account_absence",
		SourceIDs: []string{"volcengine-ark-account-models"}, SourceURLs: []string{"https://ark.cn-beijing.volcengineapi.com/?Action=ListModelActivations&Version=2024-01-01"},
		ContentSHA256: []string{strings.Repeat("a", 64)}, RetrievedAt: time.Date(2026, 10, 18, 4, 0, 0, 0, time.UTC),
	}
	if err := validateProductModelAvailability(item); err != nil {
		t.Fatalf("complete account-scoped absence was rejected: %v", err)
	}
	item.SourceIDs = nil
	if err := validateProductModelAvailability(item); err == nil {
		t.Fatal("account-scoped absence without source evidence was accepted")
	}
}

func TestVersionFloorEvidenceIsBoundToApprovedOfficialCatalogs(t *testing.T) {
	base := ProductModelAvailability{
		ModelID: "gpt-5.4", Provider: "openai", Status: "unavailable", MatchKind: "accepted_union_version_floor",
		SourceIDs: []string{"openai-codex-models"}, SourceURLs: []string{"https://developers.openai.com/codex/models"},
		ContentSHA256: []string{strings.Repeat("a", 64)}, RetrievedAt: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
	}
	if err := validateProductModelAvailability(base); err != nil {
		t.Fatalf("approved OpenAI version-floor evidence was rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*ProductModelAvailability)
	}{
		{name: "unrecognized source", edit: func(item *ProductModelAvailability) { item.SourceIDs = []string{"arbitrary-source"} }},
		{name: "mismatched provider", edit: func(item *ProductModelAvailability) { item.Provider = "xai" }},
		{name: "model outside provider family", edit: func(item *ProductModelAvailability) { item.ModelID = "grok-4.3" }},
		{name: "separate Codex Spark family", edit: func(item *ProductModelAvailability) { item.ModelID = "gpt-5.4-codex-spark" }},
		{name: "mismatched URL", edit: func(item *ProductModelAvailability) { item.SourceURLs = []string{"https://example.com/models"} }},
		{name: "multiple sources", edit: func(item *ProductModelAvailability) {
			item.SourceIDs = []string{"openai-codex-models", "xai-grok-web-models"}
			item.SourceURLs = []string{"https://developers.openai.com/codex/models", "https://x.ai/news/grok-4-5-everywhere"}
			item.ContentSHA256 = []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := base
			item.SourceIDs = append([]string(nil), base.SourceIDs...)
			item.SourceURLs = append([]string(nil), base.SourceURLs...)
			item.ContentSHA256 = append([]string(nil), base.ContentSHA256...)
			tc.edit(&item)
			if err := validateProductModelAvailability(item); err == nil {
				t.Fatal("unbound version-floor evidence was accepted")
			}
		})
	}
	grok := base
	grok.ModelID, grok.Provider = "grok-4.3", "xai"
	grok.SourceIDs = []string{"xai-grok-web-models"}
	grok.SourceURLs = []string{"https://x.ai/news/grok-4-5-everywhere"}
	if err := validateProductModelAvailability(grok); err != nil {
		t.Fatalf("approved Grok version-floor evidence was rejected: %v", err)
	}
	grok.ModelID = "gpt-5.4"
	if err := validateProductModelAvailability(grok); err == nil {
		t.Fatal("Grok catalog floor evidence was accepted for a GPT model ID")
	}
	retirement := ProductModelAvailability{
		ModelID: "gpt-5.5", Provider: "openai", Status: "unavailable", MatchKind: "accepted_union_retirement",
		SourceIDs: []string{"openai-cross-product-lifecycle-v2"}, SourceURLs: []string{"https://learn.chatgpt.com/docs/changelog"},
		ContentSHA256: []string{strings.Repeat("c", 64)}, RetrievedAt: base.RetrievedAt,
	}
	if err := validateProductModelAvailability(retirement); err != nil {
		t.Fatalf("approved OpenAI cross-product retirement evidence was rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*ProductModelAvailability)
	}{
		{name: "arbitrary lifecycle source", edit: func(item *ProductModelAvailability) { item.SourceIDs = []string{"arbitrary-source"} }},
		{name: "wrong provider", edit: func(item *ProductModelAvailability) { item.Provider = "xai" }},
		{name: "non GPT model", edit: func(item *ProductModelAvailability) { item.ModelID = "grok-4.3" }},
	} {
		item := retirement
		item.SourceIDs = append([]string(nil), retirement.SourceIDs...)
		item.SourceURLs = append([]string(nil), retirement.SourceURLs...)
		item.ContentSHA256 = append([]string(nil), retirement.ContentSHA256...)
		tc.edit(&item)
		if err := validateProductModelAvailability(item); err == nil {
			t.Errorf("%s retirement evidence was accepted", tc.name)
		}
	}
}

func TestArkAccountAbsenceIsBoundToVolcengineAndOwnership(t *testing.T) {
	s := Source{Platform: "volcengine", AccountType: "apikey", APIProtocol: "openai", BaseURL: "https://provider.example/v1", AccountID: 9002}
	rules := identitySyncRules(s)
	fingerprint := SourceFingerprint(s)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	unavailable := ProductModelAvailability{
		ModelID: "doubao-seed-2-0-lite", Provider: "volcengine", Status: "unavailable", MatchKind: "official_account_absence",
		SourceIDs: []string{"volcengine-ark-account-models"}, SourceURLs: []string{"https://ark.cn-beijing.volcengineapi.com/?Action=ListModelActivations&Version=2024-01-01"},
		ContentSHA256: []string{strings.Repeat("a", 64)}, RetrievedAt: now,
	}
	positive := ProductModelAvailability{
		ModelID: "doubao-seed-2-1-pro", Provider: "volcengine", Status: "available", MatchKind: "exact",
		SourceIDs: []string{"volcengine-ark-account-models"}, SourceURLs: []string{"https://ark.cn-beijing.volcengineapi.com/?Action=ListModelActivations&Version=2024-01-01"},
		ContentSHA256: []string{strings.Repeat("b", 64)}, RetrievedAt: now,
	}
	makeInput := func(mapping map[string]string, managed map[string]state.ManagedMapping) Input {
		in := identitySyncInput(s, mapping, []string{"doubao-seed-2-0-lite", "doubao-seed-2-1-pro"})
		in.ProductAvailabilityEnforced = true
		in.ProductAvailability = []ProductModelAvailability{unavailable, positive}
		in.ManagedMappings = managed
		return in
	}
	owned := makeInput(map[string]string{"doubao-seed-2-0-lite": "doubao-seed-2-0-lite", "legacy-alias": "doubao-seed-2-0-lite"}, map[string]state.ManagedMapping{
		"doubao-seed-2-0-lite": {LastAppliedValue: "doubao-seed-2-0-lite", SourceFingerprint: fingerprint},
		"legacy-alias":         {LastAppliedValue: "doubao-seed-2-0-lite", SourceFingerprint: fingerprint},
	})
	plan, err := Normalize(rules, owned, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || plan.After["doubao-seed-2-0-lite"] != "" || plan.After["legacy-alias"] != "" || plan.After["doubao-seed-2-1-pro"] != "doubao-seed-2-1-pro" {
		t.Fatalf("owned unavailable Ark mappings were not removed while preserving the current model: %#v", plan)
	}
	arkReasonFound := false
	for _, change := range plan.Changes {
		if change.Action == "remove" && strings.Contains(change.Reason, "configured Volcengine account") {
			arkReasonFound = true
		}
	}
	if len(plan.Changes) != 3 || !arkReasonFound {
		t.Fatalf("Ark removal reason did not describe account-scoped evidence: %#v", plan.Changes)
	}
	for _, tc := range []struct {
		name    string
		managed map[string]state.ManagedMapping
	}{
		{name: "unowned"},
		{name: "drifted", managed: map[string]state.ManagedMapping{
			"doubao-seed-2-0-lite": {LastAppliedValue: "other-model", SourceFingerprint: fingerprint},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := makeInput(map[string]string{"doubao-seed-2-0-lite": "doubao-seed-2-0-lite"}, tc.managed)
			got, err := Normalize(rules, input, state.Account{})
			if err != nil {
				t.Fatal(err)
			}
			if got.ApplyEligible || len(got.Changes) != 0 || got.After["doubao-seed-2-0-lite"] != "doubao-seed-2-0-lite" {
				t.Fatalf("Ark absence changed an unowned or drifted mapping: %#v", got)
			}
		})
	}
	for _, platform := range []string{"Volcengine", " volcengine", "volcengine "} {
		input := makeInput(map[string]string{}, nil)
		input.Source.Platform = platform
		if _, err := Normalize(rules, input, state.Account{}); err == nil {
			t.Fatalf("Ark account absence was accepted for non-literal platform %q", platform)
		}
	}
	wrongPlatformPositive := makeInput(map[string]string{}, nil)
	wrongPlatformPositive.Source.Platform = "alibaba"
	wrongPlatformPositive.ProductAvailability = []ProductModelAvailability{positive}
	if _, err := Normalize(rules, wrongPlatformPositive, state.Account{}); err == nil || !strings.Contains(err.Error(), "official model availability evidence") {
		t.Fatalf("Ark exact-positive evidence was not rejected for another platform: err=%v", err)
	}
}

func TestBailianModelStudioAbsenceIsBoundToAlibabaAndOwnership(t *testing.T) {
	s := Source{Platform: "alibaba", AccountType: "apikey", APIProtocol: "openai", BaseURL: "https://ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com/compatible-mode/v1", AccountID: 9003}
	rules := identitySyncRules(s)
	fingerprint := SourceFingerprint(s)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	baseEvidence := func(id, status, match string, digit byte) ProductModelAvailability {
		return ProductModelAvailability{
			ModelID: id, Provider: "alibaba", Status: status, MatchKind: match,
			SourceIDs: []string{"alibaba-model-studio-models"}, SourceURLs: []string{"https://ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com/api/v1/models?page_no=1&page_size=200"},
			ContentSHA256: []string{strings.Repeat(string(digit), 64)}, RetrievedAt: now,
		}
	}
	unavailable := baseEvidence("qwen3.5-plus", "unavailable", "official_api_catalog_absence", 'a')
	positive := baseEvidence("qwen3.7-plus", "available", "exact", 'b')
	makeInput := func(mapping map[string]string, managed map[string]state.ManagedMapping) Input {
		in := identitySyncInput(s, mapping, []string{"qwen3.5-plus", "qwen3.7-plus"})
		in.ProductAvailabilityEnforced = true
		in.ProductAvailability = []ProductModelAvailability{unavailable, positive}
		in.ManagedMappings = managed
		return in
	}
	owned := makeInput(map[string]string{"qwen3.5-plus": "qwen3.5-plus", "legacy-alias": "qwen3.5-plus"}, map[string]state.ManagedMapping{
		"qwen3.5-plus": {LastAppliedValue: "qwen3.5-plus", SourceFingerprint: fingerprint},
		"legacy-alias": {LastAppliedValue: "qwen3.5-plus", SourceFingerprint: fingerprint},
	})
	plan, err := Normalize(rules, owned, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || plan.After["qwen3.5-plus"] != "" || plan.After["legacy-alias"] != "" || plan.After["qwen3.7-plus"] != "qwen3.7-plus" {
		t.Fatalf("owned unavailable Model Studio mappings were not removed safely: %#v", plan)
	}
	modelStudioReasonFound := false
	for _, change := range plan.Changes {
		if change.Action == "remove" && strings.Contains(change.Reason, "official Beijing Model Studio API catalog") {
			modelStudioReasonFound = true
		}
	}
	if !modelStudioReasonFound {
		t.Fatalf("Model Studio removal reason did not identify its account-scoped evidence: %#v", plan.Changes)
	}
	for _, tc := range []struct {
		name    string
		managed map[string]state.ManagedMapping
	}{
		{name: "unowned"},
		{name: "drifted", managed: map[string]state.ManagedMapping{
			"qwen3.5-plus": {LastAppliedValue: "other-model", SourceFingerprint: fingerprint},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := makeInput(map[string]string{"qwen3.5-plus": "qwen3.5-plus"}, tc.managed)
			got, err := Normalize(rules, input, state.Account{})
			if err != nil {
				t.Fatal(err)
			}
			if got.ApplyEligible || len(got.Changes) != 0 || got.After["qwen3.5-plus"] != "qwen3.5-plus" {
				t.Fatalf("Model Studio absence changed an unowned or drifted mapping: %#v", got)
			}
		})
	}
	wrongPlatform := makeInput(map[string]string{}, nil)
	wrongPlatform.Source.Platform = "volcengine"
	if _, err := Normalize(rules, wrongPlatform, state.Account{}); err == nil {
		t.Fatal("Model Studio catalog absence was accepted for another platform")
	}
	wrongPositive := makeInput(map[string]string{}, nil)
	wrongPositive.Source.Platform = "volcengine"
	wrongPositive.ProductAvailability = []ProductModelAvailability{positive}
	if _, err := Normalize(rules, wrongPositive, state.Account{}); err == nil {
		t.Fatal("Model Studio exact-positive evidence was accepted for another platform")
	}
	wrongWorkspace := makeInput(map[string]string{"qwen3.5-plus": "qwen3.5-plus"}, map[string]state.ManagedMapping{
		"qwen3.5-plus": {LastAppliedValue: "qwen3.5-plus", SourceFingerprint: fingerprint},
	})
	wrongWorkspace.Source.BaseURL = "https://other-workspace.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
	if _, err := Normalize(rules, wrongWorkspace, state.Account{}); err == nil || !strings.Contains(err.Error(), "outside the configured Alibaba workspace") {
		t.Fatalf("Beijing workspace absence was accepted for another workspace: err=%v", err)
	}
}

func approvedAlias(source Source, upstream, public string) AliasRule {
	return AliasRule{Source: source, UpstreamID: upstream, PublicID: public, Decision: "approved", Evidence: "https://provider.example/models", ReviewedAt: "2026-10-11"}
}

func baseRules() Rules {
	return Rules{SchemaVersion: 1, Aliases: []AliasRule{}, VersionFamilies: []VersionFamily{}, RetiredModels: []RetiredRule{}}
}

func TestManualRefreshRulesPreserveAdditiveLifecycleBoundary(t *testing.T) {
	newSyntheticRules := func() Rules {
		source := Source{Platform: "openai", AccountType: "apikey", APIProtocol: "openai", BaseURL: "https://example.invalid/v1"}
		profile := SourceProfile{
			Source: source, BuildID: "synthetic-build", APIContractID: "admin-catalog-all-v1", Decision: "approved",
			LifecycleScopes: []string{"openai_codex_chatgpt_login"}, IdentityAddPolicy: "add_exact",
			IdentityCatalogPolicy: "add_identity_from_live_list", Evidence: "synthetic test policy fixture", ReviewedAt: "2026-01-01",
		}
		return Rules{SchemaVersion: 1, Aliases: []AliasRule{}, VersionFamilies: []VersionFamily{}, RetiredModels: []RetiredRule{}, SourceProfiles: []SourceProfile{profile}}
	}
	manual, fullScreen := newSyntheticRules(), newSyntheticRules()
	for name, rules := range map[string]Rules{"manual refresh": manual, "full screen": fullScreen} {
		if err := rules.Validate(); err != nil {
			t.Fatalf("%s synthetic rules are invalid: %v", name, err)
		}
	}
	if len(manual.SourceProfiles) != len(fullScreen.SourceProfiles) || len(manual.SourceProfiles) == 0 {
		t.Fatalf("manual refresh source profile set is not aligned with full-screen policy: manual=%d full-screen=%d", len(manual.SourceProfiles), len(fullScreen.SourceProfiles))
	}
	for _, source := range manual.SourceProfiles {
		if source.IdentityCatalogPolicy != "add_identity_from_live_list" {
			t.Errorf("manual refresh profile %s still uses destructive or unsupported catalog reconciliation: %q", source.Source.Platform, source.IdentityCatalogPolicy)
		}
		var matched *SourceProfile
		for i := range fullScreen.SourceProfiles {
			candidate := &fullScreen.SourceProfiles[i]
			if SourceMatches(candidate.Source, source.Source) {
				if matched != nil {
					t.Fatalf("full-screen rules have ambiguous source profile for %s", source.Source.Platform)
				}
				matched = candidate
			}
		}
		if matched == nil || !reflect.DeepEqual(source.LifecycleScopes, matched.LifecycleScopes) {
			t.Errorf("manual refresh lifecycle scopes differ from the reviewed full-screen profile for %s: manual=%v full-screen=%v", source.Source.Platform, source.LifecycleScopes, matched)
		}
	}
	if !reflect.DeepEqual(manual.OwnerLifecycleExclusions, fullScreen.OwnerLifecycleExclusions) {
		t.Errorf("manual refresh owner-confirmed availability exclusions differ from the full-screen rules")
	}
	if !reflect.DeepEqual(manual.Aliases, fullScreen.Aliases) || !reflect.DeepEqual(manual.VersionFamilies, fullScreen.VersionFamilies) || !reflect.DeepEqual(manual.RetiredModels, fullScreen.RetiredModels) {
		t.Errorf("manual refresh semantic rules drifted from the reviewed full-screen rules")
	}
}

func TestAliasIsExactAndSourceScopedUnknownModelsRemainCandidates(t *testing.T) {
	rules := baseRules()
	// These fictional IDs exercise normalization only; they do not assert a
	// mapping for any real provider or model.
	rules.Aliases = []AliasRule{approvedAlias(sourceFixture(), "raw-lantern", "public-lantern")}
	in := Input{AccountID: 9001, Source: sourceFixture(), CurrentMapping: map[string]string{"manual": "raw-manual", "wildcard-*": "*"}, LiveModels: []string{"raw-lantern", "raw-lantern-2026-01-01", "UNKNOWN-5.2"}, LiveListAvailable: true, Completeness: CompletenessUnknown}
	plan, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.After["public-lantern"] != "raw-lantern" || plan.After["manual"] != "raw-manual" || plan.After["wildcard-*"] != "*" {
		t.Fatalf("unexpected mapping result: %#v", plan.After)
	}
	if len(plan.UnreviewedModels) != 2 || plan.UnreviewedModels[0] != "UNKNOWN-5.2" || plan.UnreviewedModels[1] != "raw-lantern-2026-01-01" {
		t.Fatalf("unknown/date IDs must remain review candidates: %#v", plan.UnreviewedModels)
	}
	other := in
	other.Source = Source{Platform: "anthropic", AccountType: "apikey", APIProtocol: "anthropic", BaseURL: sourceFixture().BaseURL, AccountID: 9001}
	otherPlan, err := Normalize(rules, other, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := otherPlan.After["public-lantern"]; exists {
		t.Fatal("alias leaked across source identity")
	}
}

func TestOfficialAccountSelectabilityOverridesKeepAndRetirementRules(t *testing.T) {
	source := sourceFixture()
	now := time.Now().UTC().Truncate(time.Second)
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: source, BuildID: "build-1", APIContractID: "admin-catalog-v1", Decision: "approved", OfficialSelectabilityScope: "official-account:openai-test-account", OfficialSelectabilityProduct: "ui", Evidence: "synthetic source profile", ReviewedAt: now.Format("2006-01-02")}}
	rules.OfficialSelectability = []OfficialSelectability{{Scope: "official-account:openai-test-account", Complete: true, ModelIDs: []string{"stable"}, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(23 * time.Hour), Evidence: "complete official selector snapshot"}}
	rules.VersionFamilies = []VersionFamily{exactFamily(source, "gpt-5.2", "gpt-5.2", FamilyMember{UpstreamID: "gpt-5.2", ExactIDAction: "keep"})}
	rules.RetiredModels = []RetiredRule{{Source: source, UpstreamID: "stable", PublicID: "stable", Decision: "approved", Evidence: "old lifecycle note says retired", ReviewedAt: now.Format("2006-01-02")}}
	fingerprint := SourceFingerprint(source)
	current := map[string]string{"gpt-5.2": "gpt-5.2", "stable": "stable"}
	managed := map[string]state.ManagedMapping{
		"gpt-5.2": {LastAppliedValue: "gpt-5.2", SourceFingerprint: fingerprint},
		"stable":  {LastAppliedValue: "stable", SourceFingerprint: fingerprint},
	}
	plan, err := Normalize(rules, Input{AccountID: source.AccountID, Source: source, CurrentMapping: current, ManagedMappings: managed, LiveModels: []string{"gpt-5.2", "stable"}, LiveListAvailable: true, Completeness: CompletenessUnknown, RequireOfficialSelectability: true, OfficialSelectabilityScope: "official-account:openai-test-account", Now: now}, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("complete current selector snapshot should produce an applicable plan: %#v", plan)
	}
	if _, exists := plan.After["gpt-5.2"]; exists {
		t.Fatalf("static keep/upstream presence re-added an officially unavailable model: %#v", plan.After)
	}
	if plan.After["stable"] != "stable" {
		t.Fatalf("static retirement overrode official selector availability: %#v", plan.After)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].RuleKind != "official_selectability" {
		t.Fatalf("expected only the selector-authorized removal, got %#v", plan.Changes)
	}
}

func TestOfficialAccountSelectabilityMissingOrStaleBlocksAllChanges(t *testing.T) {
	source := sourceFixture()
	now := time.Now().UTC().Truncate(time.Second)
	base := baseRules()
	base.SourceProfiles = []SourceProfile{{Source: source, BuildID: "build-1", APIContractID: "admin-catalog-v1", Decision: "approved", OfficialSelectabilityScope: "official-account:openai-test-account", OfficialSelectabilityProduct: "ui", Evidence: "synthetic source profile", ReviewedAt: now.Format("2006-01-02")}}
	cases := []struct {
		name  string
		rules Rules
	}{
		{name: "missing snapshot", rules: base},
		{name: "stale snapshot", rules: func() Rules {
			rules := base
			rules.OfficialSelectability = []OfficialSelectability{{Scope: "official-account:openai-test-account", Complete: true, ModelIDs: []string{"new-model"}, ObservedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-24 * time.Hour), Evidence: "stale synthetic selector snapshot"}}
			return rules
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current := map[string]string{"old-model": "old-model"}
			plan, err := Normalize(tc.rules, Input{AccountID: source.AccountID, Source: source, CurrentMapping: current, LiveModels: []string{"new-model"}, LiveListAvailable: true, Completeness: CompletenessUnknown, RequireOfficialSelectability: true, OfficialSelectabilityScope: "official-account:openai-test-account", Now: now}, state.Account{})
			if err != nil {
				t.Fatal(err)
			}
			if plan.ApplyEligible || len(plan.Changes) != 0 || !reflect.DeepEqual(plan.After, current) || len(plan.Conflicts) == 0 {
				t.Fatalf("missing/stale official selector snapshot did not fail closed: %#v", plan)
			}
		})
	}
}

func TestOfficialAccountSelectabilityDoesNotClassifyWildcardRoutes(t *testing.T) {
	source := sourceFixture()
	now := time.Now().UTC().Truncate(time.Second)
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: source, BuildID: "build-1", APIContractID: "admin-catalog-v1", Decision: "approved", OfficialSelectabilityScope: "official-account:openai-test-account", OfficialSelectabilityProduct: "ui", Evidence: "synthetic source profile", ReviewedAt: now.Format("2006-01-02")}}
	rules.OfficialSelectability = []OfficialSelectability{{Scope: "official-account:openai-test-account", Complete: true, ModelIDs: []string{"selected-model"}, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(23 * time.Hour), Evidence: "complete official selector snapshot"}}
	fingerprint := SourceFingerprint(source)
	current := map[string]string{"*": "*", "gpt-*": "gpt-*", "model?x": "model?x", "old-model": "old-model"}
	managed := map[string]state.ManagedMapping{}
	for key, value := range current {
		managed[key] = state.ManagedMapping{LastAppliedValue: value, SourceFingerprint: fingerprint}
	}
	plan, err := Normalize(rules, Input{AccountID: source.AccountID, Source: source, CurrentMapping: current, ManagedMappings: managed, LiveModels: []string{"selected-model"}, LiveListAvailable: true, Completeness: CompletenessUnknown, RequireOfficialSelectability: true, OfficialSelectabilityScope: "official-account:openai-test-account", Now: now}, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("wildcard routes should not make selector reconciliation ineligible: %#v", plan)
	}
	for _, wildcard := range []string{"*", "gpt-*", "model?x"} {
		if got := plan.After[wildcard]; got != wildcard {
			t.Errorf("wildcard route %q was changed by a concrete account selector: got %q", wildcard, got)
		}
	}
	if _, exists := plan.After["old-model"]; exists {
		t.Fatal("concrete unavailable model was retained")
	}
	if len(plan.Changes) != 1 || plan.Changes[0].PublicID != "old-model" {
		t.Fatalf("expected only concrete unavailable model removal, got %#v", plan.Changes)
	}
}

func TestOfficialSelectabilityRequiresAccountIdentityAlias(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	source := sourceFixture()
	for _, scope := range []string{"openai_codex_chatgpt_login", "", "official-account:", "official-account:openai account"} {
		rules := baseRules()
		rules.SourceProfiles = []SourceProfile{{Source: source, BuildID: "build-1", APIContractID: "admin-catalog-v1", Decision: "approved", OfficialSelectabilityScope: scope, OfficialSelectabilityProduct: "ui", Evidence: "synthetic source profile", ReviewedAt: now.Format("2006-01-02")}}
		rules.OfficialSelectability = []OfficialSelectability{{Scope: scope, Complete: true, ModelIDs: []string{"selected-model"}, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(23 * time.Hour), Evidence: "complete official selector snapshot"}}
		if err := rules.Validate(); err == nil {
			t.Errorf("non-account-specific selector scope %q was accepted", scope)
		}
	}
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: source, BuildID: "build-1", APIContractID: "admin-catalog-v1", Decision: "approved", OfficialSelectabilityScope: "official-account:openai-test-account", OfficialSelectabilityProduct: "ui", Evidence: "synthetic source profile", ReviewedAt: now.Format("2006-01-02")}}
	rules.OfficialSelectability = []OfficialSelectability{{Scope: "official-account:openai-test-account", Complete: true, ModelIDs: []string{"*"}, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(23 * time.Hour), Evidence: "invalid wildcard selector fixture"}}
	if err := rules.Validate(); err == nil {
		t.Fatal("wildcard routing patterns were accepted as official selectable model IDs")
	}
}

func TestScopedOfficialSelectabilityRequiresProductClassification(t *testing.T) {
	now := time.Now().UTC()
	source := sourceFixture()
	baseProfile := SourceProfile{
		Source: source, BuildID: "build-1", APIContractID: "admin-catalog-v1", Decision: "approved",
		OfficialSelectabilityScope: "official-account:openai-test-account",
		Evidence:                   "synthetic source profile", ReviewedAt: now.Format("2006-01-02"),
	}
	for _, product := range []string{"", "api", "ui"} {
		rules := baseRules()
		profile := baseProfile
		profile.OfficialSelectabilityProduct = product
		if product == "api" {
			profile.OfficialSelectabilityProvider = "openai-api"
		}
		rules.SourceProfiles = []SourceProfile{profile}
		if err := rules.Validate(); (product == "") != (err != nil) {
			t.Errorf("product classification %q validation error = %v, want rejected only when unclassified", product, err)
		}
	}
}

func TestOrdinaryNormalizationRejectsWildcardVersionFamilyAccountScope(t *testing.T) {
	s := sourceFixture()
	wildcardAccountSource := s
	wildcardAccountSource.AccountID = 0
	rules := baseRules()
	rules.VersionFamilies = []VersionFamily{exactFamily(wildcardAccountSource, "canonical", "preferred", FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"})}
	current := map[string]string{"manual": "manual-target"}
	plan, err := Normalize(rules, Input{
		AccountID: 9001, Source: s, CurrentMapping: current,
		LiveModels: []string{"preferred"}, LiveListAvailable: true, Completeness: CompletenessUnknown,
	}, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || len(plan.Conflicts) == 0 || !reflect.DeepEqual(plan.After, current) || len(plan.Changes) != 0 {
		t.Fatalf("wildcard-account family must fail closed before changing ordinary mappings: %#v", plan)
	}
}

func TestVersionFamilyUsesOnlyPreferredLiveIDAndManagedExactHide(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.VersionFamilies = []VersionFamily{{
		Source: s, PublicID: "model-stable", PreferredUpstreamID: "model-2026-10-01",
		Members:  []FamilyMember{{UpstreamID: "model-2026-10-01", ExactIDAction: "hide"}, {UpstreamID: "model-2026-09-01", ExactIDAction: "keep"}},
		Decision: "approved", Evidence: "https://provider.example/family", ReviewedAt: "2026-10-11",
	}}
	fingerprint := SourceFingerprint(s)
	in := Input{AccountID: 9001, Source: s, CurrentMapping: map[string]string{"model-2026-10-01": "model-2026-10-01", "model-2026-09-01": "model-2026-09-01"}, LiveModels: []string{"model-2026-10-01", "model-2026-09-01"}, LiveListAvailable: true, Completeness: CompletenessUnknown}
	prior := state.Account{ManagedMappings: map[string]state.ManagedMapping{
		"model-2026-10-01": {OriginalValue: "model-2026-10-01", LastAppliedValue: "model-2026-10-01", SourceFingerprint: fingerprint},
	}}
	plan, err := Normalize(rules, in, prior)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) != 0 || plan.After["model-stable"] != "model-2026-10-01" {
		t.Fatalf("preferred mapping failed: conflicts=%v after=%v", plan.Conflicts, plan.After)
	}
	if _, exists := plan.After["model-2026-10-01"]; exists {
		t.Fatal("managed exact hide identity was retained")
	}
	if plan.After["model-2026-09-01"] != "model-2026-09-01" {
		t.Fatal("explicit keep member was not preserved")
	}

	delete(in.CurrentMapping, "model-2026-10-01")
	in.LiveModels = []string{"model-2026-09-01"}
	plan, err = Normalize(rules, in, prior)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) == 0 || plan.After["model-stable"] != "" {
		t.Fatalf("missing preferred ID must block family without fallback: conflicts=%v after=%v", plan.Conflicts, plan.After)
	}
}

func TestUnmanagedHideAndRetirementAreBlocked(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.VersionFamilies = []VersionFamily{{
		Source: s, PublicID: "stable", PreferredUpstreamID: "model-v2",
		Members:  []FamilyMember{{UpstreamID: "model-v2", ExactIDAction: "hide"}},
		Decision: "approved", Evidence: "https://provider.example/family", ReviewedAt: "2026-10-11",
	}}
	rules.RetiredModels = []RetiredRule{{Source: s, UpstreamID: "old", PublicID: "legacy", Decision: "approved", Evidence: "https://provider.example/retired", ReviewedAt: "2026-10-11"}}
	in := Input{AccountID: 9001, Source: s, CurrentMapping: map[string]string{"model-v2": "model-v2", "legacy": "old"}, LiveModels: []string{"model-v2"}, LiveListAvailable: true, Completeness: CompletenessUnknown}
	plan, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) < 2 || plan.After["model-v2"] != "model-v2" || plan.After["legacy"] != "old" {
		t.Fatalf("unmanaged mappings were changed: conflicts=%v after=%v", plan.Conflicts, plan.After)
	}
}

func TestRetirementRuleIsIdempotentAfterExactMappingWasRemoved(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.RetiredModels = []RetiredRule{{Source: s, UpstreamID: "old-model", PublicID: "legacy", Decision: "approved", Evidence: "verified retired ID", ReviewedAt: "2026-10-11"}}
	plan, err := Normalize(rules, Input{AccountID: 9001, Source: s, CurrentMapping: map[string]string{"manual": "keep"}, LiveModels: []string{"current"}, LiveListAvailable: true, Completeness: CompletenessUnknown}, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) != 0 || plan.After["manual"] != "keep" {
		t.Fatalf("already-removed retired model blocked unrelated mapping: conflicts=%v after=%v", plan.Conflicts, plan.After)
	}
}

func TestRuleConflictsBlockPlanAndUnknownOrIncompleteCatalogNeverRetires(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.Aliases = []AliasRule{approvedAlias(s, "raw-a", "public"), approvedAlias(s, "raw-b", "public")}
	managed := map[string]state.ManagedMapping{
		"stale": {OriginalValue: "stale-model", LastAppliedValue: "stale-model", SourceFingerprint: SourceFingerprint(s)},
	}
	for _, completeness := range []Completeness{CompletenessUnknown} {
		in := Input{AccountID: 9001, Source: s, CurrentMapping: map[string]string{"stale": "stale-model"}, ManagedMappings: managed, LiveModels: []string{"raw-a", "raw-b"}, LiveListAvailable: true, Completeness: completeness}
		plan, err := Normalize(rules, in, state.Account{})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Conflicts) == 0 {
			t.Fatal("alias collision should block apply")
		}
		if plan.After["stale"] != "stale-model" {
			t.Fatal("unknown/incomplete source removed a missing model")
		}
	}
}

func TestNoUnimplementedCompleteCatalogProfilesCanBeSelected(t *testing.T) {
	rules := baseRules()
	rules.CompleteCatalogProfiles = []CompleteCatalogProfile{{Source: sourceFixture(), ProfileID: "not-implemented", Evidence: "https://provider.example", ReviewedAt: "2026-10-11"}}
	if err := rules.Validate(); err == nil {
		t.Fatal("unregistered complete-catalog profile was accepted")
	}
}

func TestSourceProfileIdentityPolicyIsExplicitAndBuildScoped(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-v1", Decision: "approved", Evidence: "target test", ReviewedAt: "2026-10-11"}}
	if err := rules.Validate(); err != nil {
		t.Fatal(err)
	}
	profile, ok := rules.MatchSourceProfile(s, "build-1", "admin-catalog-v1")
	if !ok || profile.IdentityAddPolicy != "report_only" {
		t.Fatalf("default policy was not fail closed: %#v %v", profile, ok)
	}
	if _, ok := rules.MatchSourceProfile(s, "build-2", "admin-catalog-v1"); ok {
		t.Fatal("source profile matched an unreviewed target build")
	}
	rules.SourceProfiles[0].IdentityAddPolicy = "guess"
	if err := rules.Validate(); err == nil {
		t.Fatal("invalid identity_add_policy was accepted")
	}
}

func TestLiveIdentityCatalogSyncReplacesOnlyIdentityMappings(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", IdentityCatalogPolicy: "replace_identity_from_live_list", Evidence: "owner-approved live upstream catalog for the exact source", ReviewedAt: "2026-10-12"}}
	in := Input{
		AccountID: 9001, Source: s,
		IdentityCatalogPolicy: "replace_identity_from_live_list", AllowIdentityCatalogSync: true,
		CurrentMapping: map[string]string{"stale-model": "stale-model", "keep-alias": "provider-alias", "wildcard-*": "model-*", "gpt-*": "gpt-*", "model?x": "model?x", "*": "*", "still-live": "still-live"},
		LiveModels:     []string{"new-model", "still-live", "Model-X", "model-x"}, LiveListAvailable: true,
		Completeness: CompletenessUnknown,
	}
	plan, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 || plan.IdentityCatalogPolicy != "replace_identity_from_live_list" {
		t.Fatalf("approved live catalog policy did not produce an applicable plan: %#v", plan)
	}
	if _, ok := plan.After["stale-model"]; ok {
		t.Fatal("stale identity mapping was not removed")
	}
	if plan.After["new-model"] != "new-model" || plan.After["still-live"] != "still-live" || plan.After["Model-X"] != "Model-X" || plan.After["model-x"] != "model-x" {
		t.Fatalf("exact live IDs were not added with case preserved: %#v", plan.After)
	}
	if plan.After["keep-alias"] != "provider-alias" || plan.After["wildcard-*"] != "model-*" || plan.After["gpt-*"] != "gpt-*" || plan.After["model?x"] != "model?x" || plan.After["*"] != "*" {
		t.Fatalf("manual alias or wildcard was changed: %#v", plan.After)
	}
	if len(plan.Changes) != 4 || len(plan.UnreviewedModels) != 4 {
		t.Fatalf("unexpected exact mapping diff: changes=%#v unreviewed=%#v", plan.Changes, plan.UnreviewedModels)
	}
}

func TestAdditiveLiveIdentityCatalogKeepsMappingsMissingFromPossiblyPartialList(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", IdentityCatalogPolicy: "add_identity_from_live_list", Evidence: "owner-approved exact-source additive catalog import", ReviewedAt: "2026-10-14"}}
	in := Input{
		AccountID: 9001, Source: s,
		IdentityCatalogPolicy: "add_identity_from_live_list", AllowIdentityCatalogSync: true,
		CurrentMapping: map[string]string{"unverified-custom": "unverified-custom", "manual-alias": "provider-target", "still-live": "still-live"},
		LiveModels:     []string{"new-model", "still-live"}, LiveListAvailable: true,
		Completeness: CompletenessUnknown,
	}
	plan, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 || plan.IdentityCatalogPolicy != "add_identity_from_live_list" {
		t.Fatalf("additive live catalog should produce an applicable plan: %#v", plan)
	}
	if plan.After["unverified-custom"] != "unverified-custom" || plan.After["manual-alias"] != "provider-target" {
		t.Fatalf("the possibly partial live list deleted a mapping absent from this sync: %#v", plan.After)
	}
	if plan.After["new-model"] != "new-model" || plan.After["still-live"] != "still-live" {
		t.Fatalf("exact live IDs were not added/preserved: %#v", plan.After)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].Action != "add" || plan.Changes[0].PublicID != "new-model" {
		t.Fatalf("unexpected additive catalog changes: %#v", plan.Changes)
	}
}

func TestOfficialProductUnionBlocksUnprovenImportsAndPreservesUnknownMappings(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	observed := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	positive := func(id string) ProductModelAvailability {
		return ProductModelAvailability{ModelID: id, Provider: "openai", Status: "available", MatchKind: "exact", SourceIDs: []string{"openai-codex-models"}, SourceURLs: []string{"https://developers.openai.com/codex/models"}, ContentSHA256: []string{strings.Repeat("a", 64)}, RetrievedAt: observed}
	}
	uncertain := func(id string) ProductModelAvailability {
		return ProductModelAvailability{ModelID: id, Provider: "openai", Status: "insufficient_evidence", MatchKind: "none"}
	}
	in := identitySyncInput(s, map[string]string{"gpt-5.5": "gpt-5.5"}, []string{"gpt-6-sol", "gpt-4o-audio-preview", "gpt-4o-realtime-preview", "deepseek-flash", "qwen3.8-flash"})
	in.ProductAvailabilityEnforced = true
	in.ProductAvailability = []ProductModelAvailability{
		positive("gpt-6-sol"), uncertain("gpt-4o-audio-preview"), uncertain("gpt-4o-realtime-preview"), uncertain("gpt-5.5"),
		{ModelID: "deepseek-flash", Provider: "deepseek", Status: "insufficient_evidence", MatchKind: "none"},
		{ModelID: "qwen3.8-flash", Provider: "alibaba", Status: "insufficient_evidence", MatchKind: "none"},
	}
	in.LifecycleScopes = []string{"openai_codex_chatgpt_login"}
	in.LifecycleExclusions = []LifecycleExclusion{{
		Scope: "openai_codex_chatgpt_login", ModelID: "gpt-5.5", Status: "retired",
		SourceID: "openai-cross-product-lifecycle-v2", SourceURL: "https://learn.chatgpt.com/docs/changelog",
		SourceTitle: "Codex changelog", RetrievedAt: observed, ContentSHA256: strings.Repeat("b", 64),
		Excerpt: "gpt-5.5 retired from Codex only",
	}}
	plan, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("product availability evidence should safely produce an additive plan: %#v", plan)
	}
	if plan.After["gpt-5.5"] != "gpt-5.5" {
		t.Fatalf("Codex-only retirement with incomplete ChatGPT evidence removed the existing mapping: %#v", plan.After)
	}
	if plan.After["gpt-6-sol"] != "gpt-6-sol" {
		t.Fatalf("exact current user-product model was not imported: %#v", plan.After)
	}
	for _, id := range []string{"gpt-4o-audio-preview", "gpt-4o-realtime-preview", "deepseek-flash", "qwen3.8-flash"} {
		if _, imported := plan.After[id]; imported {
			t.Fatalf("unconfirmed product model %s was imported: %#v", id, plan.After)
		}
	}
	if plan.ProductAvailabilitySHA256 == "" {
		t.Fatal("the approval plan did not bind the product availability evidence")
	}
}

func TestAllAccountProbeFailureRemovesEveryMappingForExactTarget(t *testing.T) {
	s := sourceFixture()
	observed := time.Date(2026, 10, 19, 7, 0, 0, 0, time.UTC)
	base := ProductModelAvailability{ModelID: "gpt-5.5", Provider: "openai", MatchKind: "all_account_probes_failed", SourceIDs: []string{"404token-account-probe-v1"}, SourceURLs: []string{"https://404token.xyz/api/v1/admin/accounts/{account_id}/test"}, ContentSHA256: []string{strings.Repeat("a", 64)}, RetrievedAt: observed}
	in := Input{AccountID: s.AccountID, Source: s, Completeness: CompletenessUnknown, CurrentMapping: map[string]string{"alias-one": "gpt-5.5", "gpt-5.5": "gpt-5.5", "case-variant": "GPT-5.5", "other": "gpt-6-sol"}, LiveModels: []string{"gpt-5.5"}, LiveListAvailable: true, ProductAvailabilityEnforced: true, ProductAvailability: []ProductModelAvailability{{ModelID: "gpt-5.5", Provider: "openai", Status: "unavailable", MatchKind: base.MatchKind, SourceIDs: base.SourceIDs, SourceURLs: base.SourceURLs, ContentSHA256: base.ContentSHA256, RetrievedAt: base.RetrievedAt}, {ModelID: "gpt-6-sol", Provider: "openai", Status: "insufficient_evidence", MatchKind: "none"}}}
	plan, err := Normalize(baseRules(), in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plan.After["alias-one"]; ok {
		t.Fatalf("alias mapping to the failed exact target remains: %#v", plan.After)
	}
	if _, ok := plan.After["gpt-5.5"]; ok {
		t.Fatalf("identity mapping to the failed exact target remains: %#v", plan.After)
	}
	if plan.After["case-variant"] != "GPT-5.5" {
		t.Fatalf("probe failure removed a case-distinct upstream ID: %#v", plan.After)
	}
	if plan.After["other"] != "gpt-6-sol" {
		t.Fatalf("unrelated mapping changed: %#v", plan.After)
	}
	identitySync := in
	identitySync.AllowIdentityCatalogSync = true
	identitySync.IdentityCatalogPolicy = "add_identity_from_live_list"
	identityPlan, err := Normalize(baseRules(), identitySync, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if identityPlan.After["case-variant"] != "GPT-5.5" {
		t.Fatalf("probe evidence authorized identity-sync removal of a case-distinct ID: %#v", identityPlan.After)
	}
}

func TestIncompleteAccountProbePreservesExactTargetMapping(t *testing.T) {
	s := sourceFixture()
	observed := time.Date(2026, 10, 19, 7, 0, 0, 0, time.UTC)
	ignored := ProductModelAvailability{ModelID: "gpt-5.5", Provider: "openai", Status: "insufficient_evidence", MatchKind: "account_probe_ignored", SourceIDs: []string{"404token-account-probe-v1"}, SourceURLs: []string{"https://404token.xyz/api/v1/admin/accounts/{account_id}/test"}, ContentSHA256: []string{strings.Repeat("a", 64)}, RetrievedAt: observed}
	in := Input{AccountID: s.AccountID, Source: s, Completeness: CompletenessUnknown, CurrentMapping: map[string]string{"gpt-5.5": "gpt-5.5", "case-variant": "GPT-5.5", "other": "gpt-6-sol"}, LiveModels: []string{"gpt-5.5"}, LiveListAvailable: true, ProductAvailabilityEnforced: true, ProductAvailability: []ProductModelAvailability{ignored, {ModelID: "gpt-6-sol", Provider: "openai", Status: "insufficient_evidence", MatchKind: "none"}}}
	plan, err := Normalize(baseRules(), in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.After["gpt-5.5"] != "gpt-5.5" || plan.After["case-variant"] != "GPT-5.5" || plan.After["other"] != "gpt-6-sol" {
		t.Fatalf("incomplete probe changed an exact or case-distinct mapping: %#v", plan.After)
	}
}

func TestAcceptedUnionAndVersionFloorUnavailableRemoveRelayPresentIDs(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	fingerprint := SourceFingerprint(s)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	unavailable := ProductModelAvailability{
		ModelID: "gpt-5.5", Provider: "openai", Status: "unavailable", MatchKind: "accepted_union_retirement",
		SourceIDs: []string{"openai-cross-product-lifecycle-v2"}, SourceURLs: []string{"https://learn.chatgpt.com/docs/changelog"},
		ContentSHA256: []string{strings.Repeat("d", 64)}, RetrievedAt: now,
	}
	positive := ProductModelAvailability{
		ModelID: "gpt-6-sol", Provider: "openai", Status: "available", MatchKind: "exact",
		SourceIDs: []string{"openai-codex-models"}, SourceURLs: []string{"https://developers.openai.com/codex/models"},
		ContentSHA256: []string{strings.Repeat("e", 64)}, RetrievedAt: now,
	}
	versionFloor := ProductModelAvailability{
		ModelID: "gpt-5.4", Provider: "openai", Status: "unavailable", MatchKind: "accepted_union_version_floor",
		SourceIDs: []string{"openai-codex-models"}, SourceURLs: []string{"https://developers.openai.com/codex/models"},
		ContentSHA256: []string{strings.Repeat("f", 64)}, RetrievedAt: now,
	}
	current := map[string]string{"gpt-5.5": "gpt-5.5", "gpt-5.4": "gpt-5.4", "custom-route": "gpt-5.5"}
	in := identitySyncInput(s, current, []string{"gpt-5.5", "gpt-5.4", "gpt-6-sol"})
	in.ProductAvailabilityEnforced = true
	in.ProductAvailability = []ProductModelAvailability{unavailable, versionFloor, positive}
	in.ManagedMappings = map[string]state.ManagedMapping{
		"gpt-5.5":      {LastAppliedValue: "gpt-5.5", SourceFingerprint: fingerprint},
		"gpt-5.4":      {LastAppliedValue: "gpt-5.4", SourceFingerprint: fingerprint},
		"custom-route": {LastAppliedValue: "gpt-5.5", SourceFingerprint: fingerprint},
	}
	plan, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || plan.After["gpt-5.5"] != "" || plan.After["gpt-5.4"] != "" || plan.After["custom-route"] != "" || plan.After["gpt-6-sol"] != "gpt-6-sol" {
		t.Fatalf("accepted-union retirement or version-floor evidence did not remove stale relay IDs while keeping the exact positive: %#v", plan)
	}
	if len(plan.Changes) != 4 {
		t.Fatalf("expected three stale-mapping removals and one exact positive add, got %#v", plan.Changes)
	}

	in.ManagedMappings = map[string]state.ManagedMapping{}
	approvedCandidate, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !approvedCandidate.ApplyEligible || len(approvedCandidate.Conflicts) != 0 || approvedCandidate.After["gpt-5.5"] != "" || approvedCandidate.After["gpt-5.4"] != "" || approvedCandidate.After["custom-route"] != "" {
		t.Fatalf("official product-union evidence should propose removals even for mappings not previously managed by this tool: %#v", approvedCandidate)
	}
	unboundedAbsence := unavailable
	unboundedAbsence.MatchKind = "accepted_union_absence"
	unboundedAbsence.SourceIDs = []string{"unreviewed-source"}
	unboundedAbsence.SourceURLs = []string{"https://example.com/models"}
	in.ProductAvailability = []ProductModelAvailability{unboundedAbsence, versionFloor, positive}
	blockedAbsence, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if blockedAbsence.ApplyEligible || len(blockedAbsence.Changes) != 0 {
		t.Fatalf("unbound complete-catalog absence should not authorize unmanaged mapping removal: %#v", blockedAbsence)
	}
}

func TestProductAvailabilityGatesAliasAndVersionFamilyTargets(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.Aliases = []AliasRule{approvedAlias(s, "alias-target", "alias-public")}
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "canonical", "preferred",
		FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"},
		FamilyMember{UpstreamID: "keep-new", ExactIDAction: "keep"},
	)}
	fingerprint := SourceFingerprint(s)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	availability := func(id, status string) ProductModelAvailability {
		item := ProductModelAvailability{ModelID: id, Provider: "test-vendor", Status: status, MatchKind: "none"}
		if status == "available" {
			item.MatchKind = "exact"
			item.SourceIDs = []string{"test-login-models"}
			item.SourceURLs = []string{"https://provider.example/models"}
			item.ContentSHA256 = []string{strings.Repeat("f", 64)}
			item.RetrievedAt = now
		}
		return item
	}
	current := map[string]string{
		"canonical":     "old-canonical",
		"alias-public":  "old-alias",
		"keep-existing": "keep-existing",
	}
	live := []string{"preferred", "alias-target", "keep-new"}
	in := Input{
		AccountID: s.AccountID, Source: s, CurrentMapping: current, LiveModels: live, LiveListAvailable: true, Completeness: CompletenessUnknown,
		ProductAvailabilityEnforced: true,
		ProductAvailability: []ProductModelAvailability{
			availability("preferred", "insufficient_evidence"),
			availability("alias-target", "insufficient_evidence"),
			availability("keep-new", "insufficient_evidence"),
			availability("old-canonical", "insufficient_evidence"),
			availability("old-alias", "insufficient_evidence"),
			availability("keep-existing", "insufficient_evidence"),
		},
	}
	uncertain, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !uncertain.ApplyEligible || len(uncertain.Conflicts) != 0 || len(uncertain.Changes) != 0 {
		t.Fatalf("incomplete product evidence should preserve mappings without applying family/alias actions: %#v", uncertain)
	}
	for key, value := range current {
		if uncertain.After[key] != value {
			t.Fatalf("insufficient evidence changed existing mapping %s: got %#v", key, uncertain.After)
		}
	}
	if _, exists := uncertain.After["canonical"]; !exists {
		t.Fatal("uncertain preferred family target removed its existing canonical mapping")
	}
	if _, exists := uncertain.After["keep-new"]; exists {
		t.Fatal("uncertain keep member was automatically imported")
	}

	for i := range in.ProductAvailability {
		in.ProductAvailability[i] = availability(in.ProductAvailability[i].ModelID, "available")
	}
	in.ManagedMappings = map[string]state.ManagedMapping{
		"canonical":    {LastAppliedValue: "old-canonical", SourceFingerprint: fingerprint},
		"alias-public": {LastAppliedValue: "old-alias", SourceFingerprint: fingerprint},
	}
	positive, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !positive.ApplyEligible || positive.After["canonical"] != "preferred" || positive.After["alias-public"] != "alias-target" || positive.After["keep-new"] != "keep-new" {
		t.Fatalf("exact positive product evidence did not permit reviewed exact targets: %#v", positive)
	}
}

func TestProductAvailabilityGatesIdentitySyncFamilyPreferredAndKeep(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "canonical", "preferred",
		FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"},
		FamilyMember{UpstreamID: "keep-new", ExactIDAction: "keep"},
	)}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	availability := func(id, status string) ProductModelAvailability {
		item := ProductModelAvailability{ModelID: id, Provider: "openai", Status: status, MatchKind: "none"}
		if status == "available" {
			item.MatchKind = "exact"
			item.SourceIDs = []string{"openai-codex-models"}
			item.SourceURLs = []string{"https://developers.openai.com/codex/models"}
			item.ContentSHA256 = []string{strings.Repeat("c", 64)}
			item.RetrievedAt = now
		}
		return item
	}
	for _, tc := range []struct {
		name          string
		preferred     string
		keep          string
		wantCanonical string
		wantKeep      bool
	}{
		{name: "uncertain preferred", preferred: "insufficient_evidence", keep: "insufficient_evidence"},
		{name: "uncertain keep", preferred: "available", keep: "insufficient_evidence", wantCanonical: "preferred"},
		{name: "both exact positive", preferred: "available", keep: "available", wantCanonical: "preferred", wantKeep: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := identitySyncInput(s, map[string]string{"existing": "existing"}, []string{"preferred", "keep-new"})
			in.ProductAvailabilityEnforced = true
			in.ProductAvailability = []ProductModelAvailability{availability("preferred", tc.preferred), availability("keep-new", tc.keep), availability("existing", "insufficient_evidence")}
			plan, err := Normalize(rules, in, state.Account{})
			if err != nil {
				t.Fatal(err)
			}
			if plan.After["canonical"] != tc.wantCanonical {
				t.Fatalf("family preferred target bypassed product evidence gate: %#v", plan)
			}
			_, hasKeep := plan.After["keep-new"]
			if hasKeep != tc.wantKeep {
				t.Fatalf("family keep target did not follow exact product evidence: %#v", plan)
			}
			if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
				t.Fatalf("uncertain family evidence should not make unrelated exact mapping changes conflict: %#v", plan)
			}
		})
	}
}

func TestPartialProductEvidenceGatesTargetModelsOnly(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "gpt-5.2", "gpt-5.2",
		FamilyMember{UpstreamID: "gpt-5.2", ExactIDAction: "keep"},
		FamilyMember{UpstreamID: "gpt-5.4", ExactIDAction: "keep"},
	)}
	in := identitySyncInput(s, map[string]string{"gpt-5.2": "gpt-5.2"}, []string{"gpt-5.2", "gpt-5.4", "custom-live-model"})
	in.ProductAvailabilityEnforced = true
	in.ProductAvailability = []ProductModelAvailability{{ModelID: "gpt-5.2", Provider: "openai", Status: "insufficient_evidence", MatchKind: "none"}, {ModelID: "gpt-5.4", Provider: "openai", Status: "insufficient_evidence", MatchKind: "none"}}
	plan, err := Normalize(rules, in, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || plan.After["gpt-5.2"] != "gpt-5.2" {
		t.Fatalf("insufficient evidence must preserve the exact existing GPT mapping: %#v", plan)
	}
	if _, exists := plan.After["gpt-5.4"]; exists {
		t.Fatalf("version-family keep bypassed insufficient product evidence: %#v", plan.After)
	}
	if plan.After["custom-live-model"] != "custom-live-model" {
		t.Fatalf("screening changed the existing non-target vendor behavior: %#v", plan.After)
	}
}

func TestAdditiveCatalogStillAppliesExactOwnedLifecycleExclusion(t *testing.T) {
	source := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: source, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", IdentityCatalogPolicy: "add_identity_from_live_list", LifecycleScopes: []string{"openai_codex_chatgpt_login"}, Evidence: "owner-approved additive exact-source catalog import", ReviewedAt: "2026-10-14"}}
	fingerprint := SourceFingerprint(source)
	current := map[string]string{"unknown-custom": "unknown-custom", "gpt-5.4": "gpt-5.4", "keep": "keep"}
	input := Input{
		AccountID: 9001, Source: source,
		IdentityCatalogPolicy: "add_identity_from_live_list", AllowIdentityCatalogSync: true,
		CurrentMapping: current, ManagedMappings: map[string]state.ManagedMapping{
			"gpt-5.4": {LastAppliedValue: "gpt-5.4", SourceFingerprint: fingerprint},
		},
		LiveModels: []string{"gpt-5.4", "keep", "new-model"}, LiveListAvailable: true,
		LifecycleScopes: []string{"openai_codex_chatgpt_login"}, Completeness: CompletenessUnknown,
		LifecycleExclusions: []LifecycleExclusion{{
			Scope: "openai_codex_chatgpt_login", ModelID: "gpt-5.4", Status: "retired", SourceID: "openai-codex-models",
			SourceURL: "https://developers.openai.com/codex/models", SourceTitle: "Codex models",
			RetrievedAt: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), ContentSHA256: strings.Repeat("c", 64), Excerpt: "gpt-5.4 retired from Codex",
		}},
	}
	plan, err := Normalize(rules, input, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("additive lifecycle plan should apply safe changes: %#v", plan)
	}
	if _, exists := plan.After["gpt-5.4"]; exists {
		t.Fatal("exact owned lifecycle exclusion did not remove its mapping")
	}
	if plan.After["unknown-custom"] != "unknown-custom" {
		t.Fatalf("a mapping absent from live list was removed: %#v", plan.After)
	}
	if plan.After["new-model"] != "new-model" {
		t.Fatalf("exact live model was not added: %#v", plan.After)
	}
}

func TestLiveIdentityCatalogSyncDoesNotTreatWildcardAsRetirement(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", IdentityCatalogPolicy: "replace_identity_from_live_list", Evidence: "owner-approved exact source", ReviewedAt: "2026-10-12"}}
	rules.RetiredModels = []RetiredRule{{
		Source: s, UpstreamID: "gpt-*", PublicID: "gpt-*",
		Decision: "approved", Evidence: "invalid wildcard retirement fixture", ReviewedAt: "2026-10-12",
	}, {
		Source: s, UpstreamID: "model?x", PublicID: "model?x",
		Decision: "approved", Evidence: "invalid wildcard retirement fixture", ReviewedAt: "2026-10-12",
	}}
	plan, err := Normalize(rules, Input{
		AccountID: 9001, Source: s, IdentityCatalogPolicy: "replace_identity_from_live_list", AllowIdentityCatalogSync: true,
		CurrentMapping: map[string]string{"gpt-*": "gpt-*", "model?x": "model?x", "*": "*", "stale-model": "stale-model"},
		LiveModels:     []string{"new-model"}, LiveListAvailable: true, Completeness: CompletenessUnknown,
	}, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || len(plan.Conflicts) == 0 {
		t.Fatalf("wildcard retirement rule must fail closed: %#v", plan)
	}
	if plan.After["gpt-*"] != "gpt-*" || plan.After["model?x"] != "model?x" || plan.After["*"] != "*" {
		t.Fatalf("wildcard mappings were removed by live catalog reconciliation: %#v", plan.After)
	}
}

func TestLiveIdentityCatalogSyncRejectsWildcardLiveIDs(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", IdentityCatalogPolicy: "replace_identity_from_live_list", Evidence: "owner-approved exact source", ReviewedAt: "2026-10-12"}}
	current := map[string]string{"known-model": "known-model", "gpt-*": "gpt-*"}
	for _, wildcardID := range []string{"*", "gpt-*", "model?x"} {
		plan, err := Normalize(rules, Input{
			AccountID: 9001, Source: s, IdentityCatalogPolicy: "replace_identity_from_live_list", AllowIdentityCatalogSync: true,
			CurrentMapping: current,
			LiveModels:     []string{"known-model", wildcardID}, LiveListAvailable: true, Completeness: CompletenessUnknown,
		}, state.Account{})
		if err != nil {
			t.Fatalf("wildcard ID %q: %v", wildcardID, err)
		}
		if plan.ApplyEligible || len(plan.Conflicts) == 0 || len(plan.Changes) != 0 {
			t.Fatalf("wildcard live ID %q must block the whole account plan without mapping changes: %#v", wildcardID, plan)
		}
		if plan.After["known-model"] != "known-model" || plan.After["gpt-*"] != "gpt-*" || len(plan.After) != len(current) {
			t.Fatalf("wildcard live ID %q changed the existing mapping: %#v", wildcardID, plan.After)
		}
		if !strings.Contains(plan.DiscoveryReason, "wildcard") {
			t.Fatalf("wildcard live ID %q lacks explicit discovery reason: %#v", wildcardID, plan)
		}
	}
}

func TestLiveIdentityCatalogSyncBlocksEmptyResultMapping(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", IdentityCatalogPolicy: "replace_identity_from_live_list", Evidence: "owner-approved exact source", ReviewedAt: "2026-10-12"}}
	rules.RetiredModels = []RetiredRule{{
		Source: s, UpstreamID: "retired-id", PublicID: "retired-id",
		Decision: "approved", Evidence: "owner-approved exact retirement", ReviewedAt: "2026-10-12",
	}}
	plan, err := Normalize(rules, Input{
		AccountID: 9001, Source: s, IdentityCatalogPolicy: "replace_identity_from_live_list", AllowIdentityCatalogSync: true,
		CurrentMapping: map[string]string{"stale-id": "stale-id", "retired-id": "retired-id"},
		LiveModels:     []string{"retired-id"}, LiveListAvailable: true, Completeness: CompletenessUnknown,
	}, state.Account{ManagedMappings: map[string]state.ManagedMapping{
		"retired-id": {LastAppliedValue: "retired-id", SourceFingerprint: SourceFingerprint(s)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || len(plan.Conflicts) == 0 || len(plan.After) != 0 {
		t.Fatalf("empty resulting mapping must be blocked: %#v", plan)
	}
	if !strings.Contains(strings.Join(plan.Conflicts, " "), "empty mappings") {
		t.Fatalf("expected an explicit empty-mapping guard finding: %#v", plan.Conflicts)
	}
}

func TestLiveIdentityCatalogSyncFailsClosedOnMissingApprovalOrAliasCollision(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", Evidence: "sync only", ReviewedAt: "2026-10-12"}}
	plan, err := Normalize(rules, Input{AccountID: 9001, Source: s, AllowIdentityCatalogSync: true, CurrentMapping: map[string]string{"old": "old"}, LiveModels: []string{"new"}, LiveListAvailable: true, Completeness: CompletenessUnknown}, state.Account{})
	if err != nil || plan.ApplyEligible || len(plan.Conflicts) == 0 || plan.After["old"] != "old" {
		t.Fatalf("missing source policy did not fail closed: err=%v plan=%#v", err, plan)
	}

	rules.SourceProfiles[0].IdentityCatalogPolicy = "replace_identity_from_live_list"
	plan, err = Normalize(rules, Input{AccountID: 9001, Source: s, IdentityCatalogPolicy: "replace_identity_from_live_list", AllowIdentityCatalogSync: true, CurrentMapping: map[string]string{"new": "manual-target", "keep": "keep"}, LiveModels: []string{"new"}, LiveListAvailable: true, Completeness: CompletenessUnknown}, state.Account{})
	if err != nil || plan.ApplyEligible || len(plan.Conflicts) == 0 || plan.After["new"] != "manual-target" {
		t.Fatalf("live model colliding with a manual alias was overwritten: err=%v plan=%#v", err, plan)
	}
}

func TestLiveIdentityCatalogSyncStillRejectsFallbackAndEmptyCatalog(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", IdentityCatalogPolicy: "replace_identity_from_live_list", Evidence: "owner-approved exact source", ReviewedAt: "2026-10-12"}}
	for _, tc := range []struct {
		live bool
		ids  []string
	}{{false, []string{"new"}}, {true, nil}} {
		plan, err := Normalize(rules, Input{AccountID: 9001, Source: s, IdentityCatalogPolicy: "replace_identity_from_live_list", AllowIdentityCatalogSync: true, CurrentMapping: map[string]string{"old": "old"}, LiveModels: tc.ids, LiveListAvailable: tc.live, Completeness: CompletenessUnknown}, state.Account{})
		if err != nil || plan.ApplyEligible || len(plan.Conflicts) == 0 || plan.After["old"] != "old" {
			t.Fatalf("fallback/empty live catalog must preserve mapping: err=%v plan=%#v", err, plan)
		}
	}
}

func TestLiveIdentityCatalogSyncHonorsExactRetirementRules(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", IdentityCatalogPolicy: "replace_identity_from_live_list", Evidence: "owner-approved live catalog for the exact source", ReviewedAt: "2026-10-12"}}
	rules.SourceProfiles[0].IdentityCatalogPolicy = "replace_identity_from_live_list"
	rules.RetiredModels = []RetiredRule{{
		Source: s, UpstreamID: "retired-id", PublicID: "retired-id",
		Decision: "approved", Evidence: "owner-approved exact retirement", ReviewedAt: "2026-10-12",
	}}
	plan, err := Normalize(rules, Input{
		AccountID: 9001, Source: s, IdentityCatalogPolicy: "replace_identity_from_live_list", AllowIdentityCatalogSync: true,
		CurrentMapping: map[string]string{"retired-id": "retired-id", "old-live-id": "old-live-id", "keep-alias": "provider-name"},
		LiveModels:     []string{"retired-id", "new-live-id"}, LiveListAvailable: true, Completeness: CompletenessUnknown,
	}, state.Account{ManagedMappings: map[string]state.ManagedMapping{
		"retired-id": {LastAppliedValue: "retired-id", SourceFingerprint: SourceFingerprint(s)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("an exact retirement rule should remain compatible with live identity sync: %#v", plan)
	}
	if _, exists := plan.After["retired-id"]; exists {
		t.Fatal("explicitly retired live ID was re-added")
	}
	if _, exists := plan.After["old-live-id"]; exists {
		t.Fatal("stale identity mapping absent from the live list was retained")
	}
	if plan.After["new-live-id"] != "new-live-id" || plan.After["keep-alias"] != "provider-name" {
		t.Fatalf("new exact ID or non-identity mapping was not handled correctly: %#v", plan.After)
	}
	if len(plan.UnreviewedModels) != 1 || plan.UnreviewedModels[0] != "new-live-id" {
		t.Fatalf("retired ID should not remain an unreviewed add candidate: %v", plan.UnreviewedModels)
	}
	foundRetirement := false
	for _, change := range plan.Changes {
		if change.PublicID == "retired-id" && change.RuleKind == "retired_model" && change.Action == "remove" {
			foundRetirement = true
		}
	}
	if !foundRetirement {
		t.Fatalf("retirement was not represented as an exact removal: %#v", plan.Changes)
	}
}

func TestLiveIdentityCatalogSyncBlocksUnmanagedExactRetirement(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", IdentityCatalogPolicy: "add_identity_from_live_list", Evidence: "owner-approved exact source", ReviewedAt: "2026-10-14"}}
	rules.RetiredModels = []RetiredRule{{
		Source: s, UpstreamID: "retired-id", PublicID: "retired-id",
		Decision: "approved", Evidence: "exact source retirement evidence", ReviewedAt: "2026-10-14",
	}}
	current := map[string]string{"retired-id": "retired-id", "keep": "keep"}
	plan, err := Normalize(rules, Input{
		AccountID: 9001, Source: s, IdentityCatalogPolicy: "add_identity_from_live_list", AllowIdentityCatalogSync: true,
		CurrentMapping: current, LiveModels: []string{"retired-id", "keep", "new-model"}, LiveListAvailable: true,
		Completeness: CompletenessUnknown,
	}, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || len(plan.Conflicts) == 0 {
		t.Fatalf("unmanaged exact retirement must block the account plan: %#v", plan)
	}
	if !reflect.DeepEqual(plan.After, current) || len(plan.Changes) != 0 {
		t.Fatalf("unmanaged mapping was changed before ownership conflict was reported: %#v", plan)
	}
}

func identitySyncRules(source Source) Rules {
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: source, BuildID: "build-1", APIContractID: "admin-catalog-all-v1", Decision: "approved", IdentityCatalogPolicy: "replace_identity_from_live_list", Evidence: "owner-approved exact source", ReviewedAt: "2026-10-12"}}
	return rules
}

func identitySyncInput(source Source, mapping map[string]string, live []string) Input {
	return Input{AccountID: source.AccountID, Source: source, IdentityCatalogPolicy: "replace_identity_from_live_list", AllowIdentityCatalogSync: true, CurrentMapping: mapping, LiveModels: live, LiveListAvailable: true, Completeness: CompletenessUnknown}
}

func exactFamily(source Source, publicID, preferredID string, members ...FamilyMember) VersionFamily {
	return VersionFamily{Source: source, PublicID: publicID, PreferredUpstreamID: preferredID, Members: members, Decision: "approved", Evidence: "https://provider.example/exact-alias-snapshot", ReviewedAt: "2026-10-13"}
}

func TestLiveIdentityCatalogSyncOverlaysApprovedExactVersionFamily(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "model", "model", FamilyMember{UpstreamID: "model", ExactIDAction: "keep"}, FamilyMember{UpstreamID: "model-2026-10-01", ExactIDAction: "hide"})}
	fingerprint := SourceFingerprint(s)
	input := identitySyncInput(s, map[string]string{"model-2026-10-01": "model-2026-10-01", "stale": "stale"}, []string{"model", "model-2026-10-01", "unknown"})
	prior := state.Account{ManagedMappings: map[string]state.ManagedMapping{"model-2026-10-01": {LastAppliedValue: "model-2026-10-01", SourceFingerprint: fingerprint}}}
	plan, err := Normalize(rules, input, prior)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("exact approved family was not applicable: conflicts=%v", plan.Conflicts)
	}
	if plan.After["model"] != "model" {
		t.Fatalf("canonical identity did not map to the preferred live target: %#v", plan.After)
	}
	if _, exists := plan.After["model-2026-10-01"]; exists {
		t.Fatalf("managed exact snapshot hide was not applied: %#v", plan.After)
	}
	if plan.After["unknown"] != "unknown" || len(plan.UnreviewedModels) != 1 || plan.UnreviewedModels[0] != "unknown" {
		t.Fatalf("unknown live model was not preserved and reported: after=%#v unreviewed=%v", plan.After, plan.UnreviewedModels)
	}
}

func TestProductLifecycleFiltersLiveIDAndRemovesOnlyOwnedExactEdges(t *testing.T) {
	source := sourceFixture()
	rules := identitySyncRules(source)
	rules.SourceProfiles[0].LifecycleScopes = []string{"openai_codex_chatgpt_login"}
	fingerprint := SourceFingerprint(source)
	current := map[string]string{
		"gpt-5.4":     "gpt-5.4",
		"spark-route": "gpt-5.3-codex-spark",
		"keep":        "keep",
	}
	managed := map[string]state.ManagedMapping{
		"gpt-5.4":     {LastAppliedValue: "gpt-5.4", SourceFingerprint: fingerprint},
		"spark-route": {LastAppliedValue: "gpt-5.3-codex-spark", SourceFingerprint: fingerprint},
		"keep":        {LastAppliedValue: "keep", SourceFingerprint: fingerprint},
	}
	input := identitySyncInput(source, current, []string{"gpt-5.4", "gpt-5.3-codex-spark", "keep", "new-model"})
	input.ManagedMappings = managed
	input.LifecycleScopes = []string{"openai_codex_chatgpt_login"}
	input.LifecycleExclusions = []LifecycleExclusion{
		{Scope: "openai_codex_chatgpt_login", ModelID: "gpt-5.4", Status: "retired", SourceID: "openai-codex-models", SourceURL: "https://developers.openai.com/codex/models", SourceTitle: "Codex models", RetrievedAt: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), ContentSHA256: strings.Repeat("a", 64), Excerpt: "gpt-5.4 retired from Codex"},
		{Scope: "openai_codex_chatgpt_login", ModelID: "gpt-5.3-codex-spark", Status: "owner_confirmed_unavailable", SourceTitle: "Owner-confirmed model availability", Excerpt: "Owner-confirmed unavailable under normal Codex sign-in.", OwnerRule: true},
	}
	plan, err := Normalize(rules, input, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("owned exact retirement edges should be applicable: conflicts=%v", plan.Conflicts)
	}
	if _, exists := plan.After["gpt-5.4"]; exists {
		t.Fatal("retired exact ID was retained in the mapping")
	}
	if _, exists := plan.After["spark-route"]; exists {
		t.Fatal("alias edge pointing to the exact retired upstream ID was retained")
	}
	if _, exists := plan.After["gpt-5.3-codex-spark"]; exists {
		t.Fatal("live catalog re-imported an exact retired upstream ID")
	}
	if plan.After["keep"] != "keep" || plan.After["new-model"] != "new-model" {
		t.Fatalf("unrelated exact mappings were changed: %#v", plan.After)
	}
	removed := map[string]bool{}
	for _, change := range plan.Changes {
		if change.RuleKind == "product_lifecycle" && change.Action == "remove" {
			removed[change.PublicID] = true
			if change.PublicID == "spark-route" && !strings.Contains(change.Reason, "owner-confirmed") {
				t.Fatalf("owner-confirmed availability decision was mislabeled as official lifecycle retirement: %+v", change)
			}
		}
	}
	if !removed["gpt-5.4"] || !removed["spark-route"] {
		t.Fatalf("lifecycle removals were not auditable: %#v", plan.Changes)
	}
}

func TestProductLifecycleRefusesUnownedOrDriftedEdgesAndKeepsUnknownIDs(t *testing.T) {
	source := sourceFixture()
	rules := identitySyncRules(source)
	rules.SourceProfiles[0].LifecycleScopes = []string{"openai_codex_chatgpt_login"}
	fingerprint := SourceFingerprint(source)
	current := map[string]string{"manual-route": "gpt-5.4", "keep": "keep"}
	input := identitySyncInput(source, current, []string{"gpt-5.4", "keep", "relay-custom-model"})
	input.LifecycleScopes = []string{"openai_codex_chatgpt_login"}
	input.LifecycleExclusions = []LifecycleExclusion{{
		Scope: "openai_codex_chatgpt_login", ModelID: "gpt-5.4", Status: "retired", SourceID: "openai-codex-models",
		SourceURL: "https://developers.openai.com/codex/models", SourceTitle: "Codex models", RetrievedAt: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), ContentSHA256: strings.Repeat("b", 64), Excerpt: "official retired exact ID",
	}}
	input.ManagedMappings = map[string]state.ManagedMapping{"keep": {LastAppliedValue: "keep", SourceFingerprint: fingerprint}}
	plan, err := Normalize(rules, input, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || len(plan.Conflicts) == 0 {
		t.Fatalf("unowned mapping removal did not block the account plan: %#v", plan)
	}
	if plan.After["manual-route"] != "gpt-5.4" {
		t.Fatalf("unowned route was modified: %#v", plan.After)
	}
	if !containsString(plan.CatalogModels, "relay-custom-model") || len(plan.LifecycleExclusions) != 1 || plan.LifecycleExclusions[0].ModelID == "relay-custom-model" {
		t.Fatalf("unclassified relay model was incorrectly treated as a lifecycle exclusion: %#v", plan)
	}
}

func TestOfficialProductLifecycleCanRemoveUnownedExactIdentityMapping(t *testing.T) {
	source := sourceFixture()
	rules := identitySyncRules(source)
	rules.SourceProfiles[0].LifecycleScopes = []string{"openai_codex_chatgpt_login"}
	current := map[string]string{"gpt-5.2": "gpt-5.2", "keep": "keep"}
	input := identitySyncInput(source, current, []string{"gpt-5.2", "keep"})
	input.LifecycleScopes = []string{"openai_codex_chatgpt_login"}
	input.LifecycleExclusions = []LifecycleExclusion{{
		Scope: "openai_codex_chatgpt_login", ModelID: "gpt-5.2", Status: "deprecated", SourceID: "openai-cross-product-lifecycle-v2",
		SourceURL: "https://learn.chatgpt.com/docs/changelog", SourceTitle: "Codex changelog", RetrievedAt: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC),
		ContentSHA256: strings.Repeat("c", 64), Excerpt: "GPT-5.2 is deprecated for Codex",
	}}
	plan, err := Normalize(rules, input, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("official exclusion of an exact identity mapping should be applicable: conflicts=%v", plan.Conflicts)
	}
	if _, exists := plan.After["gpt-5.2"]; exists {
		t.Fatal("unowned exact identity mapping was retained despite official exclusion")
	}
	if plan.After["keep"] != "keep" {
		t.Fatalf("unrelated mapping changed: %#v", plan.After)
	}
	if len(plan.Changes) != 1 || !strings.Contains(plan.Changes[0].Reason, "exact identity mapping") {
		t.Fatalf("removal was not narrowly explained: %+v", plan.Changes)
	}
}

func TestOfficialProductLifecycleEvidenceCannotCrossProviderNamespaces(t *testing.T) {
	for _, item := range []LifecycleExclusion{
		{Scope: "openai_codex_chatgpt_login", ModelID: "deepseek-flash", Status: "not_listed"},
		{Scope: "anthropic_claude_code_login", ModelID: "gpt-5.2", Status: "retired"},
		{Scope: "kimi_code_login", ModelID: "claude-sonnet-4-5", Status: "not_listed"},
	} {
		if validLifecycleExclusion(item) {
			t.Fatalf("cross-provider product ID accepted as lifecycle evidence: %+v", item)
		}
	}
}

func TestLifecycleEvidenceDigestIgnoresRefreshOnlyTimestamp(t *testing.T) {
	evidence := LifecycleExclusion{
		Scope: "openai_codex_chatgpt_login", ModelID: "gpt-5.4", Status: "retired",
		SourceID: "openai-codex-models", SourceURL: "https://developers.openai.com/codex/models",
		SourceTitle: "Codex models", RetrievedAt: time.Date(2026, 10, 14, 1, 0, 0, 0, time.UTC),
		ContentSHA256: strings.Repeat("a", 64), Excerpt: "gpt-5.4 retired from Codex",
	}
	first, err := LifecycleEvidenceDigest([]string{"openai_codex_chatgpt_login"}, []LifecycleExclusion{evidence})
	if err != nil {
		t.Fatal(err)
	}
	evidence.RetrievedAt = evidence.RetrievedAt.Add(time.Hour)
	second, err := LifecycleEvidenceDigest([]string{"openai_codex_chatgpt_login"}, []LifecycleExclusion{evidence})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("a 304-only retrieval timestamp change altered semantic lifecycle evidence digest")
	}
}

func TestFullScreenPrunesMissingOwnedRoutesFrom404tokenCatalog(t *testing.T) {
	source := sourceFixture()
	fingerprint := SourceFingerprint(source)
	current := map[string]string{
		"keep-live": "keep-live",
		"remove-me": "remove-me",
		"custom":    "provider-specific-id",
		"fallback":  "gpt-*",
	}
	managed := make(map[string]state.ManagedMapping, len(current))
	for publicID, upstreamID := range current {
		managed[publicID] = state.ManagedMapping{LastAppliedValue: upstreamID, SourceFingerprint: fingerprint}
	}
	plan, err := Normalize(baseRules(), Input{
		AccountID: source.AccountID, Source: source, CurrentMapping: current, ManagedMappings: managed,
		LiveModels: []string{"keep-live"}, LiveListAvailable: true, Completeness: CompletenessUnknown,
		PruneMissingMappings: true,
	}, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("successful live catalog did not produce an eligible owned-route plan: conflicts=%v", plan.Conflicts)
	}
	if _, exists := plan.After["remove-me"]; exists {
		t.Fatalf("identity mapping missing from 404token catalog was retained: %#v", plan.After)
	}
	if plan.After["keep-live"] != "keep-live" || plan.After["custom"] != "" || plan.After["fallback"] != "gpt-*" {
		t.Fatalf("live, missing exact, or wildcard mapping was screened incorrectly: %#v", plan.After)
	}
	if len(plan.Changes) != 2 || plan.Changes[0].RuleKind != "live_catalog_absence" || plan.Changes[0].PublicID != "custom" || plan.Changes[1].PublicID != "remove-me" {
		t.Fatalf("unexpected live-catalog screening changes: %#v", plan.Changes)
	}
}

func TestFullScreenReportsUnownedMissingRouteAsConflict(t *testing.T) {
	source := sourceFixture()
	plan, err := Normalize(baseRules(), Input{
		AccountID: source.AccountID, Source: source, CurrentMapping: map[string]string{"remove-me": "remove-me"},
		LiveModels: []string{"keep-live"}, LiveListAvailable: true, Completeness: CompletenessUnknown,
		PruneMissingMappings: true,
	}, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || plan.After["remove-me"] != "remove-me" || len(plan.Conflicts) != 1 {
		t.Fatalf("unowned route was not preserved and blocked for review: %#v", plan)
	}
}

func TestLiveIdentityCatalogSyncAddsCanonicalPublicIDForDatedOnlyUpstream(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "claude-haiku-4-5", "claude-haiku-4-5-20251001", FamilyMember{UpstreamID: "claude-haiku-4-5-20251001", ExactIDAction: "hide"})}
	fingerprint := SourceFingerprint(s)
	input := identitySyncInput(s, map[string]string{"claude-haiku-4-5-20251001": "claude-haiku-4-5-20251001"}, []string{"claude-haiku-4-5-20251001"})
	prior := state.Account{ManagedMappings: map[string]state.ManagedMapping{"claude-haiku-4-5-20251001": {OriginalValue: "claude-haiku-4-5-20251001", LastAppliedValue: "claude-haiku-4-5-20251001", SourceFingerprint: fingerprint}}}
	plan, err := Normalize(rules, input, prior)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("exact dated-only upstream target should allow canonical public name: conflicts=%v", plan.Conflicts)
	}
	if plan.After["claude-haiku-4-5"] != "claude-haiku-4-5-20251001" {
		t.Fatalf("canonical public key did not preserve exact live upstream target: %#v", plan.After)
	}
	if _, exists := plan.After["claude-haiku-4-5-20251001"]; exists {
		t.Fatalf("dated public key was not hidden: %#v", plan.After)
	}
}

func TestLiveIdentityCatalogSyncCollapsesReviewedExactAliasesToTargets(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{
		// Fictional IDs keep this test focused on exact-family mechanics; they
		// do not approve a mapping for a real provider or model.
		exactFamily(s, "public-sunbird", "raw-sunbird-v1",
			FamilyMember{UpstreamID: "raw-sunbird-v1", ExactIDAction: "keep"},
			FamilyMember{UpstreamID: "raw-sunbird-legacy", ExactIDAction: "hide"}),
		exactFamily(s, "public-lantern", "raw-lantern-v2",
			FamilyMember{UpstreamID: "raw-lantern-v2", ExactIDAction: "hide"}),
	}
	fingerprint := SourceFingerprint(s)
	current := map[string]string{
		"raw-sunbird-v1":     "raw-sunbird-v1",
		"raw-sunbird-legacy": "raw-sunbird-legacy",
		"raw-lantern-v2":     "raw-lantern-v2",
	}
	managed := make(map[string]state.ManagedMapping, len(current))
	for id, value := range current {
		managed[id] = state.ManagedMapping{OriginalValue: value, LastAppliedValue: value, SourceFingerprint: fingerprint}
	}
	plan, err := Normalize(rules, identitySyncInput(s, current, []string{
		"raw-sunbird-v1", "raw-sunbird-legacy", "raw-lantern-v2",
	}), state.Account{ManagedMappings: managed})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("exact reviewed aliases were not applicable: conflicts=%v", plan.Conflicts)
	}
	want := map[string]string{
		"public-sunbird": "raw-sunbird-v1",
		"public-lantern": "raw-lantern-v2",
		"raw-sunbird-v1": "raw-sunbird-v1",
	}
	if !reflect.DeepEqual(plan.After, want) {
		t.Fatalf("aliases did not collapse onto their exact upstream targets: got=%#v want=%#v", plan.After, want)
	}
}

func TestLiveIdentityCatalogSyncFamilyRequiresPreferredIDLive(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "canonical", "preferred", FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"}, FamilyMember{UpstreamID: "snapshot", ExactIDAction: "hide"})}
	current := map[string]string{"existing": "existing"}
	plan, err := Normalize(rules, identitySyncInput(s, current, []string{"snapshot", "other"}), state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || len(plan.Conflicts) == 0 || !reflect.DeepEqual(plan.After, current) || len(plan.Changes) != 0 {
		t.Fatalf("missing preferred target must block without a partial diff: %#v", plan)
	}
}

func TestLiveIdentityCatalogSyncFamilyHideRequiresManagedUnchangedExactMapping(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "canonical", "preferred", FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"}, FamilyMember{UpstreamID: "snapshot", ExactIDAction: "hide"})}
	for _, tc := range []struct {
		name    string
		mapping map[string]string
		managed map[string]state.ManagedMapping
	}{
		{name: "unmanaged", mapping: map[string]string{"snapshot": "snapshot"}},
		{name: "drifted", mapping: map[string]string{"snapshot": "changed"}, managed: map[string]state.ManagedMapping{"snapshot": {LastAppliedValue: "snapshot", SourceFingerprint: SourceFingerprint(s)}}},
		{name: "wrong source fingerprint", mapping: map[string]string{"snapshot": "snapshot"}, managed: map[string]state.ManagedMapping{"snapshot": {LastAppliedValue: "snapshot", SourceFingerprint: "another-source"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := identitySyncInput(s, tc.mapping, []string{"preferred", "snapshot"})
			input.ManagedMappings = tc.managed
			plan, err := Normalize(rules, input, state.Account{})
			if err != nil {
				t.Fatal(err)
			}
			if plan.ApplyEligible || len(plan.Conflicts) == 0 || !reflect.DeepEqual(plan.After, tc.mapping) || len(plan.Changes) != 0 {
				t.Fatalf("unsafe hide did not fail closed: %#v", plan)
			}
		})
	}
}

func TestLiveIdentityCatalogSyncFamilyCannotOverwriteUnmanagedCanonicalKey(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "canonical", "preferred", FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"})}
	current := map[string]string{"canonical": "manual-target"}
	plan, err := Normalize(rules, identitySyncInput(s, current, []string{"preferred", "canonical"}), state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || len(plan.Conflicts) == 0 || !reflect.DeepEqual(plan.After, current) || len(plan.Changes) != 0 {
		t.Fatalf("unmanaged canonical key was overwritten by family overlay: %#v", plan)
	}
}

func TestLiveIdentityCatalogSyncSkipsNewHiddenMemberBeforeImport(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "canonical", "preferred", FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"}, FamilyMember{UpstreamID: "new-snapshot", ExactIDAction: "hide"})}
	plan, err := Normalize(rules, identitySyncInput(s, map[string]string{}, []string{"preferred", "new-snapshot", "unknown"}), state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 {
		t.Fatalf("new hidden member should not create a hide conflict: %#v", plan)
	}
	if _, exists := plan.After["new-snapshot"]; exists {
		t.Fatalf("new hidden member was implicitly imported: %#v", plan.After)
	}
	if plan.After["canonical"] != "preferred" || plan.After["unknown"] != "unknown" {
		t.Fatalf("family overlay or unknown preservation failed: %#v", plan.After)
	}
}

func TestLiveIdentityCatalogSyncFamilyIsSourceScopedAndPreservesVariants(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "gpt-5.2", "gpt-5.2", FamilyMember{UpstreamID: "gpt-5.2", ExactIDAction: "keep"}, FamilyMember{UpstreamID: "gpt-5.2-2025-12-11", ExactIDAction: "hide"})}
	live := []string{"gpt-5.2", "gpt-5.2-2025-12-11", "gpt-5.2-pro", "gpt-5.2-codex", "gpt-5.2-compact"}
	input := identitySyncInput(s, map[string]string{}, live)
	input.Source.APIProtocol = "anthropic"
	plan, err := Normalize(rules, input, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range live {
		if plan.After[id] != id {
			t.Fatalf("source-mismatched rule or variant altered %q: %#v", id, plan.After)
		}
	}

	input = identitySyncInput(s, map[string]string{}, live)
	plan, err = Normalize(rules, input, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := plan.After["gpt-5.2-2025-12-11"]; exists {
		t.Fatalf("exact approved snapshot was not hidden: %#v", plan.After)
	}
	for _, id := range []string{"gpt-5.2", "gpt-5.2-pro", "gpt-5.2-codex", "gpt-5.2-compact"} {
		if plan.After[id] != id {
			t.Fatalf("distinct protocol/capability variant %q was incorrectly merged: %#v", id, plan.After)
		}
	}
}

func TestLiveIdentityCatalogSyncFamilyRejectsCrossFamilyIDOverlap(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{
		exactFamily(s, "model-a", "model-a", FamilyMember{UpstreamID: "model-a", ExactIDAction: "keep"}, FamilyMember{UpstreamID: "shared-snapshot", ExactIDAction: "hide"}),
		exactFamily(s, "model-b", "model-b", FamilyMember{UpstreamID: "model-b", ExactIDAction: "keep"}, FamilyMember{UpstreamID: "shared-snapshot", ExactIDAction: "keep"}),
	}
	current := map[string]string{"model-a": "model-a", "model-b": "model-b", "shared-snapshot": "shared-snapshot", "unrelated": "unrelated"}
	plan, err := Normalize(rules, identitySyncInput(s, current, []string{"model-a", "model-b", "shared-snapshot", "unrelated"}), state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || len(plan.Conflicts) == 0 || len(plan.Changes) != 0 || !reflect.DeepEqual(plan.After, current) {
		t.Fatalf("cross-family exact-ID overlap must block the whole plan: %#v", plan)
	}
}

func TestLiveIdentityCatalogSyncFamilyCanBePinnedToExactAccount(t *testing.T) {
	ruleSource := sourceFixture()
	rules := identitySyncRules(ruleSource)
	rules.VersionFamilies = []VersionFamily{exactFamily(ruleSource, "canonical", "preferred", FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"}, FamilyMember{UpstreamID: "snapshot", ExactIDAction: "hide"})}
	otherSource := ruleSource
	otherSource.AccountID++
	current := map[string]string{"canonical": "canonical", "preferred": "preferred", "snapshot": "snapshot"}
	plan, err := Normalize(rules, identitySyncInput(otherSource, current, []string{"canonical", "preferred", "snapshot"}), state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ApplyEligible || len(plan.Conflicts) != 0 || plan.After["snapshot"] != "snapshot" || plan.After["canonical"] != "canonical" {
		t.Fatalf("account-pinned family leaked to another account sharing the same endpoint: %#v", plan)
	}
}

func TestLiveIdentityCatalogSyncFamilyRequiresExactAccountRule(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	familySource := s
	familySource.AccountID = 0
	rules.VersionFamilies = []VersionFamily{exactFamily(familySource, "canonical", "preferred", FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"}, FamilyMember{UpstreamID: "snapshot", ExactIDAction: "hide"})}
	current := map[string]string{"canonical": "canonical", "preferred": "preferred", "snapshot": "snapshot"}
	plan, err := Normalize(rules, identitySyncInput(s, current, []string{"canonical", "preferred", "snapshot"}), state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || len(plan.Conflicts) == 0 || len(plan.Changes) != 0 || !reflect.DeepEqual(plan.After, current) {
		t.Fatalf("wildcard-account family must fail closed without producing changes: %#v", plan)
	}
}

func TestLiveIdentityCatalogSyncFamilyIsIdempotentAfterApply(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "canonical", "preferred", FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"}, FamilyMember{UpstreamID: "snapshot", ExactIDAction: "hide"})}
	fingerprint := SourceFingerprint(s)
	prior := state.Account{ManagedMappings: map[string]state.ManagedMapping{"snapshot": {LastAppliedValue: "snapshot", SourceFingerprint: fingerprint}}}
	first, err := Normalize(rules, identitySyncInput(s, map[string]string{"snapshot": "snapshot"}, []string{"preferred", "snapshot"}), prior)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Conflicts) != 0 || first.After["canonical"] != "preferred" {
		t.Fatalf("first family overlay failed: %#v", first)
	}
	second, err := Normalize(rules, identitySyncInput(s, first.After, []string{"preferred", "snapshot"}), prior)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Conflicts) != 0 || len(second.Changes) != 0 || !reflect.DeepEqual(second.After, first.After) {
		t.Fatalf("second run was not idempotent: first=%#v second=%#v", first.After, second)
	}
}

func TestLiveIdentityCatalogSyncAliasRulesRemainFailClosedWithFamilies(t *testing.T) {
	s := sourceFixture()
	rules := identitySyncRules(s)
	rules.Aliases = []AliasRule{approvedAlias(s, "alias", "canonical")}
	rules.VersionFamilies = []VersionFamily{exactFamily(s, "family", "preferred", FamilyMember{UpstreamID: "preferred", ExactIDAction: "keep"})}
	current := map[string]string{"existing": "existing"}
	plan, err := Normalize(rules, identitySyncInput(s, current, []string{"preferred", "alias"}), state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyEligible || len(plan.Conflicts) == 0 || !reflect.DeepEqual(plan.After, current) || len(plan.Changes) != 0 {
		t.Fatalf("alias rules must still fail closed in identity sync: %#v", plan)
	}
}

func TestSourceProtocolIsOptionalButMatchedExactly(t *testing.T) {
	base := Source{Platform: "openai", AccountType: "apikey", BaseURL: "https://provider.example/v1", AccountID: 9001}
	accountSource, err := SourceForAccount(base.Platform, base.AccountType, "", base.BaseURL, base.AccountID)
	if err != nil || accountSource.APIProtocol != "" {
		t.Fatalf("source construction inferred or rejected an absent protocol: %#v err=%v", accountSource, err)
	}

	blankRules := baseRules()
	blankRules.SourceProfiles = []SourceProfile{{Source: base, BuildID: "build-1", APIContractID: "admin-catalog-v1", Decision: "approved", Evidence: "synthetic fixture DTO and sync evidence", ReviewedAt: "2026-10-11"}}
	if err := blankRules.Validate(); err != nil {
		t.Fatalf("blank protocol source profile rejected: %v", err)
	}
	if _, ok := blankRules.MatchSourceProfile(accountSource, "build-1", "admin-catalog-v1"); !ok {
		t.Fatal("blank protocol source profile did not match the original blank account value")
	}

	explicitSource := base
	explicitSource.APIProtocol = "openai"
	explicitRules := baseRules()
	explicitRules.SourceProfiles = []SourceProfile{{Source: explicitSource, BuildID: "build-1", APIContractID: "admin-catalog-v1", Decision: "approved", Evidence: "explicit protocol evidence", ReviewedAt: "2026-10-11"}}
	if err := explicitRules.Validate(); err != nil {
		t.Fatalf("explicit protocol source profile rejected: %v", err)
	}
	if _, ok := explicitRules.MatchSourceProfile(accountSource, "build-1", "admin-catalog-v1"); ok {
		t.Fatal("explicit protocol source profile matched an account whose original protocol is blank")
	}
	if catalogSourceMatches := SourceMatches(base, explicitSource); catalogSourceMatches {
		t.Fatal("blank source identity matched an explicit protocol source")
	}
	if _, ok := blankRules.MatchSourceProfile(explicitSource, "build-1", "admin-catalog-v1"); ok {
		t.Fatal("blank protocol source profile matched an explicit protocol account")
	}

	otherAccount := accountSource
	otherAccount.AccountID = 9002
	if _, ok := blankRules.MatchSourceProfile(otherAccount, "build-1", "admin-catalog-v1"); ok {
		t.Fatal("account-scoped source profile matched a different account ID")
	}
	if SourceFingerprint(base) == SourceFingerprint(explicitSource) {
		t.Fatal("empty and explicit protocol source fingerprints unexpectedly matched")
	}
}

func TestAddExactCannotAddUnknownModelWithoutRegisteredCompleteProfile(t *testing.T) {
	s := sourceFixture()
	rules := baseRules()
	rules.SourceProfiles = []SourceProfile{{Source: s, BuildID: "build-1", APIContractID: "admin-catalog-v1", Decision: "approved", IdentityAddPolicy: "add_exact", Evidence: "target test", ReviewedAt: "2026-10-11"}}
	if err := rules.Validate(); err != nil {
		t.Fatal(err)
	}
	plan, err := Normalize(rules, Input{AccountID: 9001, Source: s, CurrentMapping: map[string]string{}, LiveModels: []string{"new-raw-model"}, LiveListAvailable: true, Completeness: CompletenessComplete, CompletenessProfileID: "fake-complete-profile", SourceIdentityAddPolicy: "add_exact"}, state.Account{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 0 || len(plan.UnreviewedModels) != 1 || plan.After["new-raw-model"] != "" {
		t.Fatalf("unregistered completeness profile caused identity add: %#v", plan)
	}
}

func TestUnavailableFallbackAndEmptyCatalogBlockAllMappingChanges(t *testing.T) {
	rules := baseRules()
	rules.Aliases = []AliasRule{approvedAlias(sourceFixture(), "raw", "public")}
	for _, tc := range []struct {
		liveFlag bool
		models   []string
	}{
		{false, []string{"raw"}},
		{true, nil},
	} {
		plan, err := Normalize(rules, Input{AccountID: 9001, Source: sourceFixture(), CurrentMapping: map[string]string{}, LiveModels: tc.models, LiveListAvailable: tc.liveFlag, Completeness: CompletenessUnknown}, state.Account{})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Changes) != 0 || len(plan.Conflicts) == 0 {
			t.Fatalf("fallback/empty catalog should be blocked: %#v", plan)
		}
	}
}

func TestTwoSnapshotAbsenceCounterRequiresCompleteLiveSnapshots(t *testing.T) {
	count := ObserveAbsence(0, CompletenessUnknown, true, false)
	if count != 0 {
		t.Fatalf("unknown catalog changed absence count: %d", count)
	}
	count = ObserveAbsence(count, CompletenessComplete, true, false)
	if count != 1 {
		t.Fatalf("first complete absence = %d", count)
	}
	count = ObserveAbsence(count, CompletenessUnknown, true, false)
	if count != 1 {
		t.Fatalf("unknown snapshot must not advance count: %d", count)
	}
	count = ObserveAbsence(count, CompletenessComplete, true, false)
	if count != 2 {
		t.Fatalf("second complete absence = %d", count)
	}
	if got := ObserveAbsence(count, CompletenessComplete, true, true); got != 0 {
		t.Fatalf("model reappearance did not reset count: %d", got)
	}
}

func TestCompleteCatalogAbsenceCounterReturnsAndPersistsAcrossRuns(t *testing.T) {
	source := sourceFixture()
	fingerprint := SourceFingerprint(source)
	managed := map[string]state.ManagedMapping{
		"public-model": {OriginalValue: "old", LastAppliedValue: "upstream-model", SourceFingerprint: fingerprint},
	}
	before := map[string]string{"public-model": "upstream-model"}
	currentCounts := map[string]int{}
	allow := func(string) bool { return true }

	afterFirstMapping := cloneMapping(before)
	countsAfterFirst, firstChanges := updateCompleteCatalogAbsence(fingerprint, map[string]bool{}, managed, currentCounts, afterFirstMapping, nil, allow)
	if countsAfterFirst["public-model"] != 1 || len(firstChanges) != 0 {
		t.Fatalf("first complete absence should persist count 1 without removal: counts=%v changes=%v", countsAfterFirst, firstChanges)
	}
	if currentCounts["public-model"] != 0 {
		t.Fatal("counter helper mutated its input map instead of returning updated state")
	}

	// The persisted state is the source for the next discovery run.
	path := filepath.Join(t.TempDir(), "state.json")
	stateBefore := state.Empty()
	stateBefore.Accounts["9001"] = state.Account{ManagedMappings: managed, AbsenceCounts: countsAfterFirst}
	if err := state.Save(path, stateBefore); err != nil {
		t.Fatal(err)
	}
	stateAfterFirst, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	afterSecondMapping := cloneMapping(before)
	countsAfterSecond, secondChanges := updateCompleteCatalogAbsence(fingerprint, map[string]bool{}, stateAfterFirst.Accounts["9001"].ManagedMappings, stateAfterFirst.Accounts["9001"].AbsenceCounts, afterSecondMapping, nil, allow)
	if len(secondChanges) != 1 || secondChanges[0].Action != "remove" || secondChanges[0].PublicID != "public-model" {
		t.Fatalf("second consecutive complete absence should propose exact retirement: %#v", secondChanges)
	}
	if countsAfterSecond["public-model"] != 2 {
		t.Fatalf("the approval state must retain count 2 until apply consumes the retirement: %v", countsAfterSecond)
	}
	secondPlan := Plan{
		Completeness: CompletenessComplete, AbsenceCountsBefore: cloneAbsenceCounts(stateAfterFirst.Accounts["9001"].AbsenceCounts),
		AbsenceCountsAfter: cloneAbsenceCounts(countsAfterSecond), Before: cloneMapping(before), After: afterSecondMapping, Changes: secondChanges,
	}
	encodedPlan, err := json.Marshal(secondPlan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encodedPlan), `"absence_counts_before"`) || !strings.Contains(string(encodedPlan), `"absence_counts_after"`) {
		t.Fatalf("approval plan JSON did not bind both counter snapshots: %s", encodedPlan)
	}
	stateAfterSecond := stateAfterFirst
	stateAfterSecond.Accounts = map[string]state.Account{}
	for key, value := range stateAfterFirst.Accounts {
		stateAfterSecond.Accounts[key] = value
	}
	accountAfterSecond := stateAfterSecond.Accounts["9001"]
	accountAfterSecond.AbsenceCounts = cloneAbsenceCounts(secondPlan.AbsenceCountsAfter)
	stateAfterSecond.Accounts["9001"] = accountAfterSecond
	if err := state.Save(path, stateAfterSecond); err != nil {
		t.Fatal(err)
	}
	stateForApply, err := state.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stateForApply.Accounts["9001"].AbsenceCounts, secondPlan.AbsenceCountsAfter) {
		t.Fatalf("persisted after-counter snapshot differs from approved plan: state=%v plan=%v", stateForApply.Accounts["9001"].AbsenceCounts, secondPlan.AbsenceCountsAfter)
	}
	// Apply replays the same catalog snapshot from the plan's before-counter
	// snapshot, not the already-advanced state counter. The retirement delta and
	// after snapshot therefore remain byte-for-byte equivalent.
	applyMapping := cloneMapping(secondPlan.Before)
	applyCounts, applyChanges := updateCompleteCatalogAbsence(fingerprint, map[string]bool{}, managed, secondPlan.AbsenceCountsBefore, applyMapping, nil, allow)
	if !reflect.DeepEqual(applyCounts, secondPlan.AbsenceCountsAfter) || !reflect.DeepEqual(applyMapping, secondPlan.After) || !reflect.DeepEqual(applyChanges, secondPlan.Changes) {
		t.Fatalf("apply re-normalized a different retirement delta: counts=%v mapping=%v changes=%v", applyCounts, applyMapping, applyChanges)
	}
	driftedCounts := cloneAbsenceCounts(stateForApply.Accounts["9001"].AbsenceCounts)
	driftedCounts["public-model"] = 1
	if reflect.DeepEqual(driftedCounts, secondPlan.AbsenceCountsAfter) {
		t.Fatal("counter drift unexpectedly matched the frozen approval snapshot")
	}

	// Non-complete snapshots preserve the durable count, and a live reappearance
	// in a complete snapshot resets it.
	if got := ObserveAbsence(stateAfterFirst.Accounts["9001"].AbsenceCounts["public-model"], CompletenessUnknown, true, false); got != 1 {
		t.Fatalf("unknown snapshot changed persisted counter: %d", got)
	}
	if got := ObserveAbsence(1, CompletenessComplete, true, true); got != 0 {
		t.Fatalf("reappearing model did not reset absence counter: %d", got)
	}
}

func TestNormalizeKeepsCompletenessFailClosedAndReturnsPriorCounters(t *testing.T) {
	rules := baseRules()
	source := sourceFixture()
	prior := state.Account{
		ManagedMappings: map[string]state.ManagedMapping{
			"public-model": {OriginalValue: "old", LastAppliedValue: "missing-upstream", SourceFingerprint: SourceFingerprint(source)},
		},
		AbsenceCounts: map[string]int{"public-model": 1},
	}
	plan, err := Normalize(rules, Input{
		AccountID: 9001, Source: source, CurrentMapping: map[string]string{"public-model": "missing-upstream"},
		LiveModels: []string{"some-live-model"}, LiveListAvailable: true,
		Completeness: CompletenessComplete, CompletenessProfileID: "not-registered",
	}, prior)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Completeness != CompletenessUnknown || plan.AbsenceCountsBefore["public-model"] != 1 || plan.AbsenceCountsAfter["public-model"] != 1 {
		t.Fatalf("unregistered completeness must be downgraded without changing counters: completeness=%s before=%v after=%v", plan.Completeness, plan.AbsenceCountsBefore, plan.AbsenceCountsAfter)
	}
	if prior.AbsenceCounts["public-model"] != 1 {
		t.Fatal("Normalize mutated caller-owned prior state")
	}
	if len(plan.Changes) != 0 || plan.After["public-model"] != "missing-upstream" {
		t.Fatalf("unregistered completeness changed mapping: changes=%v after=%v", plan.Changes, plan.After)
	}
}
