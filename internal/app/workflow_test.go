package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"sub2api-model-catalog-manager/internal/adminapi"
	"sub2api-model-catalog-manager/internal/catalog"
	"sub2api-model-catalog-manager/internal/config"
	"sub2api-model-catalog-manager/internal/report"
	"sub2api-model-catalog-manager/internal/securecred"
	"sub2api-model-catalog-manager/internal/state"
)

func TestDiscoveryGatesBeforeCredentialOrAPI(t *testing.T) {
	t.Run("privacy gate", func(t *testing.T) {
		cfg, _, _ := testWorkflowConfig(t, false, true)
		credentialCalls, clientCalls := 0, 0
		_, err := (Discoverer{
			ReadCredential: func(config.CredentialConfig) (securecred.Value, error) {
				credentialCalls++
				return securecred.Value{}, nil
			},
			NewClient: func(string) (AdminAPI, error) { clientCalls++; return &workflowAPI{}, nil },
		}).Discover(context.Background(), cfg)
		if err == nil || credentialCalls != 0 || clientCalls != 0 {
			t.Fatalf("privacy gate did not stop before access: err=%v credentials=%d clients=%d", err, credentialCalls, clientCalls)
		}
	})

	t.Run("native sync side effect gate", func(t *testing.T) {
		cfg, _, _ := testWorkflowConfig(t, true, false)
		credentialCalls, clientCalls := 0, 0
		_, err := (Discoverer{
			ReadCredential: func(config.CredentialConfig) (securecred.Value, error) {
				credentialCalls++
				return securecred.Value{}, nil
			},
			NewClient: func(string) (AdminAPI, error) { clientCalls++; return &workflowAPI{}, nil },
		}).Discover(context.Background(), cfg)
		if err == nil || credentialCalls != 0 || clientCalls != 0 {
			t.Fatalf("side-effect gate did not stop before access: err=%v credentials=%d clients=%d", err, credentialCalls, clientCalls)
		}
	})
}

func TestDiscoveryRequiresExactSourceBuildAndAPIMatch(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	rules := workflowRules(account)
	rules.SourceProfiles[0].BuildID = "different-build"
	writeWorkflowRules(t, cfg.RulesFile, rules)
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	result, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if api.syncCalls != 0 || result.Plan != nil {
		t.Fatalf("mismatched profile reached sync or produced a plan: sync=%d plan=%#v", api.syncCalls, result.Plan)
	}
	if !hasCall(api.calls, "account:7") || hasCall(api.calls, "sync:7") {
		t.Fatalf("unexpected mocked API calls: %v", api.calls)
	}
}

func TestAllAccountDiscoveryCoversInventoryAndApplyChecksSnapshot(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	cfg.AccountScope = "all"
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.Accounts = nil
	rules := workflowRules(account)
	rules.SourceProfiles[0].APIContractID = config.APIContractAllAccountsV1
	writeWorkflowRules(t, cfg.RulesFile, rules)
	unsupported := adminapi.Account{ID: 8, Platform: "openai", Type: "apikey", Protocol: "openai", BaseURL: "https://unreviewed.example/v1", Status: "active", ModelMapping: map[string]string{"manual": "preserve"}, APIKeyPresent: boolPointer(true)}
	shadowParent := account.ID
	shadow := adminapi.Account{ID: 9, Platform: account.Platform, Type: account.Type, Protocol: account.Protocol, BaseURL: account.BaseURL, Status: "active", ParentAccountID: &shadowParent, ModelMapping: map[string]string{}, APIKeyPresent: boolPointer(true)}
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	api.accounts[unsupported.ID] = unsupported
	api.accounts[shadow.ID] = shadow
	api.status.Accounts = append(api.status.Accounts, adminapi.AccountRunStatus{AccountID: unsupported.ID, Status: "completed"}, adminapi.AccountRunStatus{AccountID: shadow.ID, Status: "completed"})
	discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("all-account discovery failed: plan=%#v err=%v", discovery.Plan, err)
	}
	if discovery.Plan.AccountScope != "all" || discovery.Plan.AccountInventoryCount != 3 || len(discovery.Report.Discovery) != 3 || len(discovery.Plan.Accounts) != 1 {
		t.Fatalf("unexpected all-account coverage/plan: scope=%q inventory=%d reports=%d plans=%d", discovery.Plan.AccountScope, discovery.Plan.AccountInventoryCount, len(discovery.Report.Discovery), len(discovery.Plan.Accounts))
	}
	if !hasCall(api.calls, "list_accounts") || !hasCall(api.calls, "sync:7") || hasCall(api.calls, "sync:8") || hasCall(api.calls, "sync:9") {
		t.Fatalf("unsupported/shadow accounts were synced: %v", api.calls)
	}
	statuses := map[int64]string{}
	for _, row := range discovery.Report.Discovery {
		statuses[row.ID] = row.Status
	}
	if statuses[8] != "skipped" || statuses[9] != "skipped_shadow" {
		t.Fatalf("unsupported/shadow accounts were not reported: %v", statuses)
	}

	apply, err := workflowApplier(api, now).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
	if err != nil || !reflect.DeepEqual(apply.AppliedIDs, []int64{account.ID}) {
		t.Fatalf("all-account mapping apply failed: result=%#v err=%v", apply, err)
	}

	cfg2, account2, now2 := testWorkflowConfig(t, true, true)
	cfg2.AccountScope = "all"
	cfg2.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	cfg2.AcceptAllCredentialResponseMemoryExposure = true
	cfg2.Accounts = nil
	rules2 := workflowRules(account2)
	rules2.SourceProfiles[0].APIContractID = config.APIContractAllAccountsV1
	writeWorkflowRules(t, cfg2.RulesFile, rules2)
	api2 := newWorkflowAPI(account2, now2, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	discovery2, err := workflowDiscoverer(api2, now2).Discover(context.Background(), cfg2)
	if err != nil || discovery2.Plan == nil {
		t.Fatalf("second inventory discovery failed: %v", err)
	}
	api2.accounts[88] = adminapi.Account{ID: 88, Platform: "other", Type: "apikey", BaseURL: "https://new.example", ModelMapping: map[string]string{}, APIKeyPresent: boolPointer(true)}
	result, err := workflowApplier(api2, now2).Apply(context.Background(), cfg2, *discovery2.Plan, discovery2.PlanSHA256, discovery2.PlanSHA256, false)
	if err == nil || len(result.AppliedIDs) != 0 || len(api2.bulkCalls) != 0 {
		t.Fatalf("inventory drift did not block all writes: result=%#v err=%v writes=%v", result, err, api2.bulkCalls)
	}
}

func TestDiscoverySkipsUnrestrictedMappingsBeforeNativeSync(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mapping map[string]string
	}{
		{name: "absent"},
		{name: "explicit empty", mapping: map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, account, now := testWorkflowConfig(t, true, true)
			account.ModelMapping = tc.mapping
			api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
			result, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if result.Plan != nil || api.syncCalls != 0 || len(api.bulkCalls) != 0 {
				t.Fatalf("unrestricted mapping was planned or synchronized: plan=%#v sync=%d writes=%v", result.Plan, api.syncCalls, api.bulkCalls)
			}
			if len(result.Report.Discovery) != 1 || result.Report.Discovery[0].Status != "skipped_unrestricted_mapping" {
				t.Fatalf("unrestricted mapping was not clearly reported: %#v", result.Report.Discovery)
			}
		})
	}
}

func TestDiscoveryReportsSnapshotLiveAndMappingDifferencesWithoutChangingMappings(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	rules, err := catalog.LoadRules(cfg.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	rules.SourceProfiles[0].IdentityAddPolicy = "report_only"
	writeWorkflowRules(t, cfg.RulesFile, rules)
	account.PublishedSnapshot = &adminapi.PublishedSnapshot{
		ContractStatus: adminapi.PublishedSnapshotContractStatusSupported,
		Status:         "stale",
		Source:         "upstream_models_endpoint",
		LastAttemptAt:  timePtr(now),
		NextRefreshAt:  timePtr(now.Add(time.Hour)),
		RawDigest:      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		RawModels:      []string{"gpt-5.2-chat-latest", "gpt-4o-audio-preview"},
		PublicModels:   []string{"gpt-5.2-chat-latest", "gpt-4o-audio-preview"},
		PublicToUpstream: map[string]string{
			"gpt-5.2-chat-latest":  "gpt-5.2-chat-latest",
			"gpt-4o-audio-preview": "gpt-4o-audio-preview",
		},
		RawCount: 2, PublicCount: 2, PublicToUpstreamCount: 2,
	}
	api := newWorkflowAPI(account, now, adminapi.Catalog{
		Models:            []string{"gpt-5.2-chat-latest", "gpt-4o-audio-preview", "gpt-4o-realtime-preview"},
		LiveListAvailable: true,
	})
	result, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan == nil || len(result.Plan.Accounts) != 1 {
		t.Fatalf("expected a preview plan for the exact account: %#v", result.Plan)
	}
	if len(result.Plan.Accounts[0].Changes) != 0 || len(result.Report.Discovery) != 1 || len(result.Report.Discovery[0].Changes) != 0 {
		t.Fatalf("catalog diagnostics unexpectedly created mapping changes: plan=%#v report=%#v", result.Plan.Accounts[0].Changes, result.Report.Discovery)
	}
	d := result.Report.Discovery[0].CatalogDiagnostics
	if d == nil || d.SnapshotContractStatus != adminapi.PublishedSnapshotContractStatusSupported || !d.HasLiveCatalog {
		t.Fatalf("snapshot/live catalog comparison missing: %#v", d)
	}
	if !reflect.DeepEqual(d.PublicOnlyVsMappingPublic, []string{"gpt-4o-audio-preview", "gpt-5.2-chat-latest"}) || !reflect.DeepEqual(d.LiveOnlyVsPublic, []string{"gpt-4o-realtime-preview"}) {
		t.Fatalf("exact snapshot/live/mapping differences are incorrect: %#v", d)
	}
	if api.syncCalls != 1 || len(api.bulkCalls) != 0 {
		t.Fatalf("diagnostic preview unexpectedly wrote account mappings: calls=%v writes=%v", api.calls, api.bulkCalls)
	}
}

func TestSnapshotSentinelsDoNotEscapeInspectOrDiscoverReports(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	account.PublishedSnapshot = &adminapi.PublishedSnapshot{
		ContractStatus:        adminapi.PublishedSnapshotContractStatusSupported,
		Status:                "SNAPSHOT_STATUS_SENTINEL_MUST_NOT_ESCAPE",
		Source:                "SNAPSHOT_SOURCE_SENTINEL_MUST_NOT_ESCAPE",
		RawDigest:             "SNAPSHOT_DIGEST_SENTINEL_MUST_NOT_ESCAPE",
		LastAttemptAt:         timePtr(now),
		NextRefreshAt:         timePtr(now.Add(time.Hour)),
		RawModels:             []string{"SNAPSHOT_MODEL_SENTINEL_MUST_NOT_ESCAPE"},
		PublicModels:          []string{"SNAPSHOT_MODEL_SENTINEL_MUST_NOT_ESCAPE"},
		PublicToUpstream:      map[string]string{"SNAPSHOT_MODEL_SENTINEL_MUST_NOT_ESCAPE": "SNAPSHOT_MODEL_SENTINEL_MUST_NOT_ESCAPE"},
		RawCount:              1,
		PublicCount:           1,
		PublicToUpstreamCount: 1,
	}
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	newClient := func(string) (AdminAPI, error) { return api, nil }
	inspectDoc, err := (Inspector{ReadCredential: workflowCredential, NewClient: newClient}).Inspect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("inspect failed: %v", err)
	}
	inspectDir := filepath.Join(t.TempDir(), "inspect")
	inspectPath, err := report.Write(inspectDir, inspectDoc)
	if err != nil {
		t.Fatalf("write inspect report: %v", err)
	}
	inspectBody, err := os.ReadFile(inspectPath)
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	discoverDir := filepath.Join(t.TempDir(), "discover")
	discoverPath, err := report.Write(discoverDir, discovery.Report)
	if err != nil {
		t.Fatalf("write discover report: %v", err)
	}
	discoverBody, err := os.ReadFile(discoverPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []string{
		"SNAPSHOT_STATUS_SENTINEL_MUST_NOT_ESCAPE",
		"SNAPSHOT_SOURCE_SENTINEL_MUST_NOT_ESCAPE",
		"SNAPSHOT_DIGEST_SENTINEL_MUST_NOT_ESCAPE",
		"SNAPSHOT_MODEL_SENTINEL_MUST_NOT_ESCAPE",
	} {
		if strings.Contains(string(inspectBody), sentinel) || strings.Contains(string(discoverBody), sentinel) {
			t.Fatalf("snapshot sentinel escaped inspect/discover report: %s", sentinel)
		}
	}
}

func TestSameAccountSourceDetectsMappingPresenceDrift(t *testing.T) {
	base := adminapi.Account{ID: 7, Platform: "openai", Type: "apikey", Protocol: "openai", BaseURL: "https://provider.example/v1", Status: "active"}
	explicitEmpty := base
	explicitEmpty.ModelMapping = map[string]string{}
	if sameAccountSource(base, explicitEmpty) || sameAccountSource(explicitEmpty, base) {
		t.Fatal("mapping presence drift was treated as an unchanged account source")
	}
}

func TestApplyBlocksAbsentOrEmptyMappingBeforeWrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mapping map[string]string
	}{
		{name: "absent"},
		{name: "explicit empty", mapping: map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, account, now := testWorkflowConfig(t, true, true)
			api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
			discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
			if err != nil || discovery.Plan == nil {
				t.Fatalf("fixture discovery failed: plan=%#v err=%v", discovery.Plan, err)
			}
			current := api.accounts[account.ID]
			current.ModelMapping = tc.mapping
			api.accounts[account.ID] = current
			result, err := workflowApplier(api, now).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
			if err == nil || len(result.AppliedIDs) != 0 || len(api.bulkCalls) != 0 {
				t.Fatalf("apply did not reject absent/empty mapping before write: result=%#v err=%v writes=%v", result, err, api.bulkCalls)
			}
		})
	}
}

func TestApplyRejectsPlanWithEmptyResultMappingBeforeAPI(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("fixture discovery failed: plan=%#v err=%v", discovery.Plan, err)
	}
	plan := *discovery.Plan
	plan.Accounts = append([]catalog.Plan(nil), discovery.Plan.Accounts...)
	plan.Accounts[0].After = map[string]string{}
	apiStart := len(api.calls)
	result, err := workflowApplier(api, now).Apply(context.Background(), cfg, plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
	if err == nil || !strings.Contains(err.Error(), "resulting model mapping is empty") || len(result.AppliedIDs) != 0 || len(api.bulkCalls) != 0 {
		t.Fatalf("empty resulting mapping was not rejected before write: result=%#v err=%v writes=%v", result, err, api.bulkCalls)
	}
	if len(api.calls) != apiStart {
		t.Fatalf("empty mapping plan contacted the API before rejection: %v", api.calls[apiStart:])
	}
}

func TestApplyRejectsInactiveAccountBeforeMappingWrite(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("fixture discovery failed: plan=%#v err=%v", discovery.Plan, err)
	}
	inactive := api.accounts[account.ID]
	inactive.Status = "disabled"
	api.accounts[account.ID] = inactive
	result, err := workflowApplier(api, now).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
	if err == nil || !strings.Contains(err.Error(), "account is not active") || len(result.AppliedIDs) != 0 || len(api.bulkCalls) != 0 {
		t.Fatalf("inactive account was not blocked before write: result=%#v err=%v writes=%v", result, err, api.bulkCalls)
	}
}

func TestAllAccountDiscoveryReportsReadFailureAndBlocksPartialPlanAndState(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	cfg.AccountScope = "all"
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.Accounts = nil
	rules := workflowRules(account)
	rules.SourceProfiles[0].APIContractID = config.APIContractAllAccountsV1
	writeWorkflowRules(t, cfg.RulesFile, rules)
	shadowParent := account.ID
	shadow := adminapi.Account{ID: 9, Platform: account.Platform, Type: account.Type, Protocol: account.Protocol, BaseURL: account.BaseURL, Status: "active", ParentAccountID: &shadowParent, ModelMapping: map[string]string{}, APIKeyPresent: boolPointer(true)}
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	api.accounts[shadow.ID] = shadow
	api.inventoryIDs = []int64{account.ID, 8, shadow.ID}
	discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Plan != nil || discovery.Report.AccountScanStatus != "partial" || len(discovery.Report.Discovery) != 3 {
		t.Fatalf("partial all-account discovery must report every ID and withhold its plan: plan=%#v report=%#v", discovery.Plan, discovery.Report)
	}
	statuses := map[int64]string{}
	for _, row := range discovery.Report.Discovery {
		statuses[row.ID] = row.Status
	}
	if statuses[account.ID] != "candidate_reported" || statuses[8] != "account_read_failed" || statuses[shadow.ID] != "skipped_shadow" {
		t.Fatalf("unexpected all-account discovery statuses: %v", statuses)
	}
	if !hasCall(api.calls, "account:9") || !hasCall(api.calls, "sync:7") {
		t.Fatalf("discovery did not continue after one account detail failure: %v", api.calls)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial inventory scan persisted local catalog state: err=%v", err)
	}
}

func TestApplyBlocksUnknownCatalogWarning(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	api := newWorkflowAPI(account, now, adminapi.Catalog{
		Models: []string{"upstream-known"}, LiveListAvailable: true,
		Warnings: []adminapi.CatalogWarning{{Code: "partial_page", Message: "opaque catalog warning"}},
	})
	discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("discovery failed: %#v %v", discovery.Plan, err)
	}
	if discovery.Plan.Accounts[0].ApplyEligible {
		t.Fatal("unknown catalog warning produced an apply-eligible plan")
	}
	apiStart := len(api.calls)
	result, err := workflowApplier(api, now).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
	if err == nil || len(result.AppliedIDs) != 0 || len(api.bulkCalls) != 0 {
		t.Fatalf("unknown warning was not fail-closed: result=%#v err=%v bulk=%v", result, err, api.bulkCalls)
	}
	if len(api.calls) <= apiStart {
		t.Fatal("apply did not reach account preflight")
	}
}

func TestDiscoveryPartialRefreshSkipsSelectedAccountThatFailed(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	api.status.RunStatus = "partial_failure"
	api.status.Accounts[0].Status = "failed"
	result, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan != nil || api.syncCalls != 0 || hasCall(api.calls, "account:7") {
		t.Fatalf("failed account was used after partial refresh: plan=%#v sync=%d calls=%v", result.Plan, api.syncCalls, api.calls)
	}
}

func TestManualDiscoveryOverridesStalePartialRefreshOnlyInAllAccountPreview(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	cfg.AccountScope = "all"
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.Accounts = nil
	rules := workflowRules(account)
	rules.Aliases = []catalog.AliasRule{}
	rules.SourceProfiles[0].APIContractID = config.APIContractAllAccountsV1
	rules.SourceProfiles[0].IdentityCatalogPolicy = "add_identity_from_live_list"
	writeWorkflowRules(t, cfg.RulesFile, rules)
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	previousDay := now.Add(-24 * time.Hour)
	api.status.RunStatus = "partial_failure"
	api.status.LastFinishedAt = &previousDay
	api.status.Accounts[0].Status = "failed"

	result, err := (Discoverer{
		ReadCredential:       workflowCredential,
		NewClient:            func(string) (AdminAPI, error) { return api, nil },
		Now:                  func() time.Time { return now },
		ManualSyncAuthorized: true,
	}).Discover(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Report.ManualNativeSyncOverride || result.Report.RefreshRunStatus != "partial_failure" || result.Report.RefreshFinishedAt == nil || !result.Report.RefreshFinishedAt.Equal(previousDay) {
		t.Fatalf("manual override was not recorded transparently: %#v", result.Report)
	}
	if api.syncCalls != 1 || api.bulkCalls != nil || result.Plan == nil {
		t.Fatalf("manual preview did not perform exactly one native sync without mapping writes: sync=%d bulk=%v plan=%#v", api.syncCalls, api.bulkCalls, result.Plan)
	}
	accountPlan := result.Plan.Accounts[0]
	if accountPlan.IdentityCatalogPolicy != "add_identity_from_live_list" || !accountPlan.ProductAvailabilityEnforced || accountPlan.ProductAvailabilitySHA256 == "" {
		t.Fatalf("manual-sync-authorized preview did not enter official-product identity screening: %#v", accountPlan)
	}
	if _, imported := accountPlan.After["upstream-known"]; imported || accountPlan.After["untouched"] != "keep-me" || len(accountPlan.Changes) != 0 {
		t.Fatalf("insufficient official product evidence changed the preview mapping: %#v", accountPlan)
	}
}

func TestDiscoveryPreflightBindsManualAuthorizationModeAndConfig(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	cfg.AccountScope = "all"
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.Accounts = nil
	rules := workflowRules(account)
	rules.Aliases = []catalog.AliasRule{}
	rules.SourceProfiles[0].APIContractID = config.APIContractAllAccountsV1
	rules.SourceProfiles[0].IdentityCatalogPolicy = "add_identity_from_live_list"
	writeWorkflowRules(t, cfg.RulesFile, rules)
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	credentialCalls, clientCalls := 0, 0
	d := Discoverer{
		ReadCredential: func(config.CredentialConfig) (securecred.Value, error) {
			credentialCalls++
			return securecred.Value{APIKey: []byte("test-admin-key")}, nil
		},
		NewClient: func(string) (AdminAPI, error) {
			clientCalls++
			return api, nil
		},
		Now: func() time.Time { return now }, ManualSyncAuthorized: true,
	}
	prepared, err := d.Preflight(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.ManualSyncAuthorized || prepared.ManualOnlyOnly || prepared.FullScreen || prepared.AccountScope != "all" || prepared.ApplyMode != "preview" || prepared.ConfigFingerprint == "" {
		t.Fatalf("manual authorized preflight did not bind the exact mode/config: %#v", prepared)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Discoverer, *config.Config)
	}{
		{name: "manual authorization removed", mutate: func(d *Discoverer, _ *config.Config) { d.ManualSyncAuthorized = false }},
		{name: "manual-only mode switched", mutate: func(d *Discoverer, _ *config.Config) { d.ManualOnlyOnly = true }},
		{name: "full-screen mode switched", mutate: func(d *Discoverer, _ *config.Config) { d.FullScreen = true }},
		{name: "account scope changed", mutate: func(_ *Discoverer, cfg *config.Config) { cfg.AccountScope = "selected" }},
		{name: "apply mode changed", mutate: func(_ *Discoverer, cfg *config.Config) { cfg.ApplyMode = "approved_rules" }},
		{name: "credential exposure acceptance changed", mutate: func(_ *Discoverer, cfg *config.Config) { cfg.AcceptAllCredentialResponseMemoryExposure = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changedDiscoverer, changedConfig := d, cfg
			tc.mutate(&changedDiscoverer, &changedConfig)
			_, err := changedDiscoverer.DiscoverPrepared(context.Background(), changedConfig, prepared)
			if err == nil || !strings.Contains(err.Error(), "authorization mode or configuration changed after preflight") {
				t.Fatalf("changed authorization snapshot was accepted: %v", err)
			}
			if credentialCalls != 0 || clientCalls != 0 || api.syncCalls != 0 {
				t.Fatalf("changed snapshot reached credentials or API: credentials=%d clients=%d sync=%d", credentialCalls, clientCalls, api.syncCalls)
			}
		})
	}

	result, err := d.DiscoverPrepared(context.Background(), cfg, prepared)
	if err != nil {
		t.Fatalf("unchanged manual authorized all-account preview was rejected: %v", err)
	}
	if result.Plan == nil || api.syncCalls != 1 || api.bulkCalls != nil {
		t.Fatalf("unchanged manual preview did not complete without mapping writes: plan=%#v sync=%d writes=%v", result.Plan, api.syncCalls, api.bulkCalls)
	}
}

func TestDiscoveryKeepsCompletenessUnknownAndNeverAddsUnknownIdentity(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known", "brand-new-opaque-id"}, LiveListAvailable: true})
	result, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan == nil || api.syncCalls != 1 {
		t.Fatalf("expected one mocked discovery and a candidate plan: sync=%d plan=%#v", api.syncCalls, result.Plan)
	}
	plan := result.Plan.Accounts[0]
	if plan.Completeness != catalog.CompletenessUnknown || plan.CompletenessProfileID != "" {
		t.Fatalf("completeness was inferred without an implemented profile: %#v", plan)
	}
	if got := plan.After["brand-new-opaque-id"]; got != "" {
		t.Fatalf("unknown identity was auto-added without proven completeness: %q", got)
	}
	if !reflect.DeepEqual(plan.UnreviewedModels, []string{"brand-new-opaque-id"}) {
		t.Fatalf("unknown catalog ID was not reported as unreviewed: %v", plan.UnreviewedModels)
	}
	if got := plan.After["canonical-name"]; got != "upstream-known" {
		t.Fatalf("exact reviewed alias missing from candidate: %q", got)
	}
	if !result.Report.NativeSyncSideEffect {
		t.Fatal("report did not disclose native sync metadata side effect")
	}
}

func TestDiscoveryFallbackEmptyAndWarningsDoNotCreateWritableCatalogPlan(t *testing.T) {
	cases := []struct {
		name              string
		catalog           adminapi.Catalog
		wantPlan          bool
		wantApplyEligible bool
	}{
		{name: "fallback", catalog: adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: false}},
		{name: "empty live", catalog: adminapi.Catalog{Models: []string{}, LiveListAvailable: true}},
		{name: "unknown warning", catalog: adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true, Warnings: []adminapi.CatalogWarning{{Code: "partial_page", Message: "opaque message"}}}, wantPlan: true},
		{name: "capability metadata incomplete", catalog: adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true, Warnings: []adminapi.CatalogWarning{{Code: warningModelMetadataIncomplete, Message: "Model IDs were synced, but capability metadata is incomplete."}}}, wantPlan: true, wantApplyEligible: true},
		{name: "capability metadata partial", catalog: adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true, Warnings: []adminapi.CatalogWarning{{Code: warningModelMetadataPartial, Message: "Some model capabilities were saved; remaining models are still incomplete."}}}, wantPlan: true, wantApplyEligible: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, account, now := testWorkflowConfig(t, true, true)
			api := newWorkflowAPI(account, now, tc.catalog)
			result, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if api.syncCalls != 1 {
				t.Fatalf("sync calls=%d, want one", api.syncCalls)
			}
			if !tc.wantPlan && result.Plan != nil {
				t.Fatalf("fallback/empty catalog produced a plan: %#v", result.Plan)
			}
			if tc.wantPlan {
				if result.Plan == nil {
					t.Fatal("live catalog did not produce a candidate plan")
				}
				plan := result.Plan.Accounts[0]
				if plan.ApplyEligible != tc.wantApplyEligible || len(plan.CatalogWarningCodes) != len(tc.catalog.Warnings) {
					t.Fatalf("unexpected warning handling: eligible=%v warnings=%v", plan.ApplyEligible, plan.CatalogWarningCodes)
				}
				if strings.Contains(tc.name, "capability metadata") && (plan.Completeness != catalog.CompletenessUnknown || len(plan.Changes) != 1) {
					t.Fatalf("metadata warning changed catalog completeness or blocked an exact reviewed mapping: %#v", plan)
				}
			}
			stored, err := state.Load(filepath.Join(cfg.StateDir, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			entry := stored.Accounts[catalog.AccountKey(account.ID)]
			if tc.name == "fallback" || tc.name == "empty live" {
				if entry.CatalogSnapshot != nil {
					t.Fatalf("fallback/empty catalog changed local snapshot state: %#v", entry.CatalogSnapshot)
				}
			}
		})
	}
}

func TestDiscoveryUses404tokenCatalogWithoutOfficialSelector(t *testing.T) {
	t.Run("missing snapshot does not block live catalog screening", func(t *testing.T) {
		cfg, account, now := testWorkflowConfig(t, true, true)
		rules := workflowRules(account)
		rules.OfficialSelectability = nil
		writeWorkflowRules(t, cfg.RulesFile, rules)
		api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known", "new-model"}, LiveListAvailable: true})
		result, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
		if err != nil || result.Plan == nil || !result.Plan.Accounts[0].ApplyEligible || result.Plan.Accounts[0].OfficialSelectabilitySHA256 != "" || result.Plan.Accounts[0].After["canonical-name"] != "upstream-known" || result.Plan.Accounts[0].After["new-model"] != "" {
			t.Fatalf("successful 404token catalog did not govern the discovery plan: plan=%#v err=%v", result.Plan, err)
		}
	})
	t.Run("expired snapshot does not block live catalog screening", func(t *testing.T) {
		cfg, account, now := testWorkflowConfig(t, true, true)
		rules := workflowRules(account)
		rules.OfficialSelectability[0].ObservedAt = now.UTC().Add(-48 * time.Hour)
		rules.OfficialSelectability[0].ExpiresAt = now.UTC().Add(-24 * time.Hour)
		writeWorkflowRules(t, cfg.RulesFile, rules)
		api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known", "new-model"}, LiveListAvailable: true})
		result, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
		if err != nil || result.Plan == nil || !result.Plan.Accounts[0].ApplyEligible || result.Plan.Accounts[0].OfficialSelectabilitySHA256 != "" || result.Plan.Accounts[0].After["canonical-name"] != "upstream-known" {
			t.Fatalf("expired unrelated snapshot blocked 404token catalog screening: plan=%#v err=%v", result.Plan, err)
		}
	})
	t.Run("rules change still invalidates an approved plan", func(t *testing.T) {
		cfg, account, now := testWorkflowConfig(t, true, true)
		api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
		discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
		if err != nil || discovery.Plan == nil || !discovery.Plan.Accounts[0].ApplyEligible {
			t.Fatalf("valid selector fixture did not produce an eligible plan: plan=%#v err=%v", discovery.Plan, err)
		}
		rules, err := catalog.LoadRules(cfg.RulesFile)
		if err != nil {
			t.Fatal(err)
		}
		rules.OfficialSelectability[0].ModelIDs = append(rules.OfficialSelectability[0].ModelIDs, "newly-selectable")
		writeWorkflowRules(t, cfg.RulesFile, rules)
		result, err := workflowApplier(api, now).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
		if err == nil || !strings.Contains(err.Error(), "raw rules hash drifted") || len(result.AppliedIDs) != 0 || len(api.bulkCalls) != 0 {
			t.Fatalf("changed selector snapshot did not invalidate the plan: result=%#v err=%v writes=%v", result, err, api.bulkCalls)
		}
	})
}

func TestApplyOneIDMappingOnlyWriteReadbackAndPlanConsumption(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	api := newWorkflowAPI(account, now, adminapi.Catalog{
		Models: []string{"upstream-known"}, LiveListAvailable: true,
		Warnings: []adminapi.CatalogWarning{{Code: warningModelMetadataIncomplete, Message: "Model IDs were synced, but capability metadata is incomplete."}},
	})
	discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("discovery failed: %#v %v", discovery.Plan, err)
	}
	plan := *discovery.Plan
	if !plan.Accounts[0].ApplyEligible || plan.Accounts[0].Completeness != catalog.CompletenessUnknown || !reflect.DeepEqual(plan.Accounts[0].CatalogWarningCodes, []string{warningModelMetadataIncomplete}) {
		t.Fatalf("metadata warning did not preserve the reviewed-plan boundary: %#v", plan.Accounts[0])
	}
	result, err := workflowApplier(api, now).Apply(context.Background(), cfg, plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Consumed || !reflect.DeepEqual(result.AppliedIDs, []int64{7}) || len(api.bulkCalls) != 1 {
		t.Fatalf("unexpected apply result/call count: %#v bulk=%v", result, api.bulkCalls)
	}
	if api.bulkCalls[0] != 7 || len(api.bulkMappings) != 1 || api.bulkMappings[0]["canonical-name"] != "upstream-known" || api.bulkMappings[0]["untouched"] != "keep-me" {
		t.Fatalf("write was not one-ID complete mapping-only payload: ids=%v mappings=%#v", api.bulkCalls, api.bulkMappings)
	}
	if got := api.accounts[7].ModelMapping["canonical-name"]; got != "upstream-known" {
		t.Fatalf("mapping was not read back: %q", got)
	}
	beforeCalls := len(api.calls)
	if _, err := workflowApplier(api, now).Apply(context.Background(), cfg, plan, discovery.PlanSHA256, discovery.PlanSHA256, false); err == nil {
		t.Fatal("consumed plan was accepted a second time")
	}
	if len(api.calls) != beforeCalls || len(api.bulkCalls) != 1 {
		t.Fatalf("consumed plan reached API: calls=%v bulk=%v", api.calls[beforeCalls:], api.bulkCalls)
	}
}

func TestDiscoveryPersistsReturnedAbsenceCountersInLocalState(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	source, err := catalog.SourceForAccount(account.Platform, account.Type, account.Protocol, account.BaseURL, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	prior := state.Empty()
	prior.Accounts[catalog.AccountKey(account.ID)] = state.Account{
		ManagedMappings: map[string]state.ManagedMapping{
			"untouched": {OriginalValue: "keep-me", LastAppliedValue: "keep-me", SourceFingerprint: catalog.SourceFingerprint(source)},
		},
		AbsenceCounts: map[string]int{"untouched": 1},
	}
	statePath := filepath.Join(cfg.StateDir, "state.json")
	if err := state.Save(statePath, prior); err != nil {
		t.Fatal(err)
	}
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	result, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil || result.Plan == nil {
		t.Fatalf("discovery failed: %#v %v", result.Plan, err)
	}
	stored, err := state.Load(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Accounts[catalog.AccountKey(account.ID)].AbsenceCounts["untouched"] != 1 {
		t.Fatalf("unknown catalog did not preserve returned absence count: %#v", stored.Accounts[catalog.AccountKey(account.ID)].AbsenceCounts)
	}
	if !reflect.DeepEqual(result.Plan.Accounts[0].AbsenceCountsBefore, map[string]int{"untouched": 1}) || !reflect.DeepEqual(result.Plan.Accounts[0].AbsenceCountsAfter, map[string]int{"untouched": 1}) {
		t.Fatalf("plan did not bind unchanged counter before/after: %#v", result.Plan.Accounts[0])
	}
}

func TestApplyPrivacyGateRunsBeforeCredentialOrAPI(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("discovery failed: %#v %v", discovery.Plan, err)
	}
	cfg.Accounts[0].AcceptCredentialResponseMemoryExposure = boolPointer(false)
	apiStart := len(api.calls)
	credentialCalls := 0
	_, err = (Applier{
		ReadCredential: func(config.CredentialConfig) (securecred.Value, error) {
			credentialCalls++
			return securecred.Value{}, nil
		},
		NewClient: func(string) (AdminAPI, error) { return api, nil },
		Now:       func() time.Time { return now },
	}).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
	if err == nil || credentialCalls != 0 || len(api.calls) != apiStart || len(api.bulkCalls) != 0 {
		t.Fatalf("privacy gate did not block before access: err=%v credentials=%d calls=%v", err, credentialCalls, api.calls[apiStart:])
	}
}

func TestApplyPreflightFailureHasNoBulkWrite(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*config.Config, *catalog.ApprovalPlan, *workflowAPI)
		confirm string
	}{
		{name: "confirmation mismatch", confirm: "wrong"},
		{name: "mapping drift", mutate: func(_ *config.Config, _ *catalog.ApprovalPlan, api *workflowAPI) {
			api.accounts[7].ModelMapping["untouched"] = "changed"
		}},
		{name: "account no longer active", mutate: func(_ *config.Config, _ *catalog.ApprovalPlan, api *workflowAPI) {
			a := api.accounts[7]
			a.Status = "disabled"
			api.accounts[7] = a
		}},
		{name: "source drift", mutate: func(_ *config.Config, _ *catalog.ApprovalPlan, api *workflowAPI) {
			a := api.accounts[7]
			a.BaseURL = "https://other.example/v1"
			api.accounts[7] = a
		}},
		{name: "rules hash drift", mutate: func(cfg *config.Config, _ *catalog.ApprovalPlan, _ *workflowAPI) {
			appendFixtureByte(t, cfg.RulesFile)
		}},
		{name: "state hash drift", mutate: func(cfg *config.Config, _ *catalog.ApprovalPlan, _ *workflowAPI) {
			appendFixtureByte(t, filepath.Join(cfg.StateDir, "state.json"))
		}},
		{name: "absence counter plan drift", mutate: func(_ *config.Config, plan *catalog.ApprovalPlan, _ *workflowAPI) {
			plan.Accounts[0].AbsenceCountsAfter["unexpected-counter"] = 1
		}},
		{name: "catalog content drift", mutate: func(_ *config.Config, plan *catalog.ApprovalPlan, _ *workflowAPI) {
			plan.Accounts[0].CatalogModels = append(plan.Accounts[0].CatalogModels, "unbound-catalog-id")
		}},
		{name: "target compatibility drift", mutate: func(cfg *config.Config, _ *catalog.ApprovalPlan, _ *workflowAPI) {
			cfg.Target.RuntimeCompatibility.BuildID = "other-build"
		}},
		{name: "expired plan", mutate: func(_ *config.Config, p *catalog.ApprovalPlan, _ *workflowAPI) {
			p.ExpiresAt = p.CreatedAt.Add(-time.Second)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, account, now := testWorkflowConfig(t, true, true)
			api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
			discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
			if err != nil || discovery.Plan == nil {
				t.Fatalf("discovery failed: %#v %v", discovery.Plan, err)
			}
			plan := *discovery.Plan
			confirm := discovery.PlanSHA256
			if tc.confirm != "" {
				confirm = tc.confirm
			}
			apiStart := len(api.calls)
			if tc.mutate != nil {
				tc.mutate(&cfg, &plan, api)
			}
			_, err = workflowApplier(api, now).Apply(context.Background(), cfg, plan, discovery.PlanSHA256, confirm, false)
			if err == nil || len(api.bulkCalls) != 0 {
				t.Fatalf("preflight did not fail closed: err=%v bulk=%v", err, api.bulkCalls)
			}
			if tc.name == "confirmation mismatch" || tc.name == "expired plan" || tc.name == "catalog content drift" {
				if len(api.calls) != apiStart {
					t.Fatalf("local approval/plan validation contacted API: %v", api.calls[apiStart:])
				}
			}
		})
	}
}

func TestSameCountMapTreatsEmptyPersistedMapAsCanonicalAndRejectsDrift(t *testing.T) {
	if !sameCountMap(nil, map[string]int{}) {
		t.Fatal("nil persisted counters and an approved empty counter map should be equivalent")
	}
	if sameCountMap(map[string]int{"model": 1}, map[string]int{"model": 2}) {
		t.Fatal("counter drift was accepted")
	}
	approved := catalog.Plan{AbsenceCountsBefore: map[string]int{"model": 1}, AbsenceCountsAfter: map[string]int{"model": 2}}
	drifted := approved
	drifted.AbsenceCountsAfter = map[string]int{"model": 1}
	if samePlanDelta(approved, drifted) {
		t.Fatal("plan delta equality ignored a changed after-counter snapshot")
	}
	approved = catalog.Plan{
		LifecycleScopes:         []string{"openai_codex_chatgpt_login"},
		LifecycleEvidenceSHA256: "semantic-evidence-digest",
		LifecycleExclusions: []catalog.LifecycleExclusion{{
			Scope: "openai_codex_chatgpt_login", ModelID: "gpt-5.4", Status: "retired", SourceID: "openai-codex-models",
			SourceURL: "https://developers.openai.com/codex/models", ContentSHA256: strings.Repeat("a", 64),
			RetrievedAt: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC),
		}},
	}
	drifted = approved
	drifted.LifecycleScopes = []string{"anthropic_claude_code_login"}
	if samePlanDelta(approved, drifted) {
		t.Fatal("plan delta equality ignored lifecycle scope drift")
	}
	drifted = approved
	drifted.LifecycleEvidenceSHA256 = "different-evidence-digest"
	if samePlanDelta(approved, drifted) {
		t.Fatal("plan delta equality ignored lifecycle evidence digest drift")
	}
	drifted = approved
	drifted.LifecycleExclusions = append([]catalog.LifecycleExclusion{}, approved.LifecycleExclusions...)
	drifted.LifecycleExclusions[0].RetrievedAt = drifted.LifecycleExclusions[0].RetrievedAt.Add(time.Minute)
	if !samePlanDelta(approved, drifted) {
		t.Fatal("304-only retrieval timestamp should not change semantic plan delta")
	}
}

func TestOwnerAvailabilityRuleSetIsExactlyPinnedToSevenModels(t *testing.T) {
	rules := ownerAvailabilityRulesFixture()
	if !exactOwnerAvailabilityRules(rules) {
		t.Fatal("the approved seven-rule set was rejected")
	}
	cases := []struct {
		name   string
		mutate func(*catalog.Rules)
	}{
		{name: "missing rule", mutate: func(r *catalog.Rules) { r.OwnerLifecycleExclusions = r.OwnerLifecycleExclusions[:6] }},
		{name: "extra rule", mutate: func(r *catalog.Rules) {
			r.OwnerLifecycleExclusions = append(r.OwnerLifecycleExclusions, catalog.OwnerLifecycleExclusion{Scope: ownerAvailabilityScope, ModelID: "gpt-extra", Decision: "approved", Evidence: "fixture", ReviewedAt: "2026-10-14"})
		}},
		{name: "duplicate rule", mutate: func(r *catalog.Rules) {
			r.OwnerLifecycleExclusions = append(r.OwnerLifecycleExclusions, r.OwnerLifecycleExclusions[0])
		}},
		{name: "changed scope", mutate: func(r *catalog.Rules) { r.OwnerLifecycleExclusions[0].Scope = "anthropic_claude_code_login" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := ownerAvailabilityRulesFixture()
			tc.mutate(&changed)
			if exactOwnerAvailabilityRules(changed) {
				t.Fatal("a changed owner-rule set was accepted")
			}
		})
	}
}

func TestOwnerOnlyLifecycleDeltaRejectsEveryNonOwnerChange(t *testing.T) {
	rules := ownerAvailabilityRulesFixture()
	ownerPlan := catalog.Plan{
		LifecycleScopes: []string{ownerAvailabilityScope},
		LifecycleExclusions: []catalog.LifecycleExclusion{{
			Scope: ownerAvailabilityScope, ModelID: "gpt-5.2", Status: "owner_confirmed_unavailable", OwnerRule: true,
		}},
		LiveListAvailable: true, ApplyEligible: true,
		Before:  map[string]string{"gpt-5.2": "gpt-5.2", "stable": "stable"},
		After:   map[string]string{"stable": "stable"},
		Changes: []catalog.Change{{Action: "remove", PublicID: "gpt-5.2", Before: "gpt-5.2", RuleKind: "product_lifecycle", Evidence: "owner-confirmed unavailable in " + ownerAvailabilityScope}},
	}
	if !ownerOnlyLifecycleDelta(rules, []string{ownerAvailabilityScope}, []string{ownerAvailabilityScope}, ownerPlan) {
		t.Fatal("an exact owner-only removal was rejected")
	}

	cases := []struct {
		name string
		plan catalog.Plan
	}{
		{name: "live-list addition", plan: func() catalog.Plan {
			p := clonePlanForTest(ownerPlan)
			p.After["new-model"] = "new-model"
			p.Changes = append(p.Changes, catalog.Change{Action: "add", PublicID: "new-model", After: "new-model", RuleKind: "identity_catalog"})
			return p
		}()},
		{name: "official retirement", plan: func() catalog.Plan {
			p := clonePlanForTest(ownerPlan)
			p.Changes[0].Evidence = "openai-codex-models; official evidence"
			return p
		}()},
		{name: "renamed public key", plan: func() catalog.Plan {
			p := clonePlanForTest(ownerPlan)
			delete(p.Before, "gpt-5.2")
			p.Before["local-gpt-alias"] = "gpt-5.2"
			p.After = map[string]string{"stable": "stable"}
			p.Changes[0].PublicID = "local-gpt-alias"
			return p
		}()},
		{name: "unrelated removal", plan: func() catalog.Plan {
			p := clonePlanForTest(ownerPlan)
			delete(p.Before, "stable")
			p.Changes = append(p.Changes, catalog.Change{Action: "remove", PublicID: "stable", Before: "stable", RuleKind: "absence_threshold"})
			return p
		}()},
		{name: "rename", plan: func() catalog.Plan {
			p := clonePlanForTest(ownerPlan)
			p.After["gpt-5.2"] = "renamed-model"
			return p
		}()},
		{name: "additional blocked scope", plan: clonePlanForTest(ownerPlan)},
		{name: "mapping conflict", plan: func() catalog.Plan {
			p := clonePlanForTest(ownerPlan)
			p.Conflicts = []string{"mapping ownership conflict"}
			return p
		}()},
		{name: "unowned owner edge", plan: func() catalog.Plan {
			p := clonePlanForTest(ownerPlan)
			p.ApplyEligible = false
			return p
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blockedScopes := []string{ownerAvailabilityScope}
			configuredScopes := []string{ownerAvailabilityScope}
			if tc.name == "additional blocked scope" {
				blockedScopes = append(blockedScopes, "anthropic_claude_code_login")
				configuredScopes = append(configuredScopes, "anthropic_claude_code_login")
			}
			if ownerOnlyLifecycleDelta(rules, configuredScopes, blockedScopes, tc.plan) {
				t.Fatal("a non-owner-only mapping delta was accepted")
			}
		})
	}
	noop := catalog.Plan{LifecycleScopes: []string{ownerAvailabilityScope}, LiveListAvailable: true, ApplyEligible: true, Before: map[string]string{"stable": "stable"}, After: map[string]string{"stable": "stable"}}
	if !ownerOnlyLifecycleDelta(rules, []string{ownerAvailabilityScope}, []string{ownerAvailabilityScope}, noop) {
		t.Fatal("a no-op plan was not accepted as non-mutating")
	}
}

func TestFullScreenPreservesMappingsWhenOfficialProductEvidenceIsUnavailable(t *testing.T) {
	cfg, account, api, now := ownerAvailabilityWorkflowFixture(t, true, []string{"stable"})
	discovery, err := (Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("full-screen owner exception discovery failed: plan=%#v err=%v", discovery.Plan, err)
	}
	plan := discovery.Plan.Accounts[0]
	if !plan.ApplyEligible || len(plan.Changes) != 0 || plan.After["gpt-5.2"] != "gpt-5.2" || !slices.Contains(plan.UnreviewedModels, "stable") {
		t.Fatalf("full-screen did not preserve the mapping and block unproven identity import: %#v", plan)
	}
	result, err := (Applier{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
	if err != nil || len(result.AppliedIDs) != 0 || len(api.bulkCalls) != 0 {
		t.Fatalf("full-screen changed mappings without official product evidence: result=%#v err=%v writes=%v", result, err, api.bulkCalls)
	}
	if api.accounts[account.ID].ModelMapping["gpt-5.2"] != "gpt-5.2" {
		t.Fatalf("blocked full-screen run changed the target mapping: %#v", api.accounts[account.ID].ModelMapping)
	}
}

func TestFullScreenPlansDeletionOnlyAfterAllRelevantExactProbesFail(t *testing.T) {
	cfg, _, api, now := ownerAvailabilityWorkflowFixture(t, true, []string{"stable"})
	api.probeOutcomes = map[string]string{"gpt-5.2": "failed", "stable": "succeeded"}
	discovery, err := (Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("full-screen probe discovery failed: plan=%#v err=%v", discovery.Plan, err)
	}
	plan := discovery.Plan.Accounts[0]
	if plan.After["stable"] != "stable" {
		t.Fatalf("successful model was not preserved: %#v", plan.After)
	}
	if _, ok := plan.After["gpt-5.2"]; ok {
		t.Fatalf("model with terminal probe failure was not removed: %#v", plan.After)
	}
	if len(discovery.Plan.ModelProbeDecisions) == 0 || discovery.Plan.ModelProbeSHA256 == "" {
		t.Fatalf("probe outcomes were not bound into the approval plan: %#v", discovery.Plan)
	}
	if err := discovery.Plan.ValidateShape(now); err != nil {
		t.Fatalf("cross-account probe plan failed validation: %v", err)
	}
}

func TestFullScreenProductScreeningDoesNotRequireRelayIdentityImportPolicy(t *testing.T) {
	cfg, _, api, now := ownerAvailabilityWorkflowFixture(t, true, []string{"stable"})
	rules, err := catalog.LoadRules(cfg.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	rules.SourceProfiles[0].IdentityCatalogPolicy = ""
	writeWorkflowRules(t, cfg.RulesFile, rules)

	discovery, err := (Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("full-screen product screening failed for an API-key relay profile: plan=%#v err=%v", discovery.Plan, err)
	}
	if !discovery.Plan.Accounts[0].ProductAvailabilityEnforced {
		t.Fatalf("full-screen product screening was still coupled to identity import policy: %#v", discovery.Plan.Accounts[0])
	}
	var gptProbe *catalog.ModelProbeDecision
	for i := range discovery.Plan.ModelProbeDecisions {
		if discovery.Plan.ModelProbeDecisions[i].ModelID == "gpt-5.2" {
			gptProbe = &discovery.Plan.ModelProbeDecisions[i]
		}
	}
	if gptProbe == nil || gptProbe.Status != "available" {
		t.Fatalf("insufficient evidence for an existing GPT mapping did not trigger the exact account probe: %#v calls=%v", discovery.Plan.ModelProbeDecisions, api.calls)
	}
	if discovery.Plan.Accounts[0].IdentityCatalogPolicy != "" || len(discovery.Plan.Accounts[0].Changes) != 0 {
		t.Fatalf("product screening unexpectedly enabled identity import or changed mappings: %#v", discovery.Plan.Accounts[0])
	}
}

func TestOwnerAvailabilityRulesDoNotBypassMissingUnionEvidence(t *testing.T) {
	for _, mode := range []string{"unowned", "drifted"} {
		t.Run(mode, func(t *testing.T) {
			cfg, account, api, now := ownerAvailabilityWorkflowFixture(t, true, []string{"stable"})
			statePath := filepath.Join(cfg.StateDir, "state.json")
			local, err := state.Load(statePath)
			if err != nil {
				t.Fatal(err)
			}
			entry := local.Accounts[catalog.AccountKey(account.ID)]
			if mode == "unowned" {
				delete(entry.ManagedMappings, "gpt-5.2")
			} else {
				managed := entry.ManagedMappings["gpt-5.2"]
				managed.LastAppliedValue = "gpt-5.2-old"
				entry.ManagedMappings["gpt-5.2"] = managed
			}
			local.Accounts[catalog.AccountKey(account.ID)] = entry
			if err := state.Save(statePath, local); err != nil {
				t.Fatal(err)
			}
			discovery, err := (Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}).Discover(context.Background(), cfg)
			if err != nil || discovery.Plan == nil || !discovery.Plan.Accounts[0].ApplyEligible || len(discovery.Plan.Accounts[0].Changes) != 0 || discovery.Plan.Accounts[0].After["gpt-5.2"] != "gpt-5.2" {
				t.Fatalf("insufficient union evidence must preserve the existing mapping regardless of ownership: plan=%#v err=%v", discovery.Plan, err)
			}
			result, err := (Applier{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
			if err != nil || len(result.AppliedIDs) != 0 || len(api.bulkCalls) != 0 {
				t.Fatalf("unproven owner edge changed mappings: result=%#v err=%v writes=%v", result, err, api.bulkCalls)
			}
		})
	}
}

func TestFullScreenDoesNotTreat404tokenCatalogAsOfficialEvidence(t *testing.T) {
	t.Run("404token candidate cannot qualify as official product evidence", func(t *testing.T) {
		cfg, account, api, now := ownerAvailabilityWorkflowFixture(t, true, []string{"stable", "new-model"})
		source, err := catalog.SourceForAccount(account.Platform, account.Type, account.Protocol, account.BaseURL, account.ID)
		if err != nil {
			t.Fatal(err)
		}
		rules, err := catalog.LoadRules(cfg.RulesFile)
		if err != nil {
			t.Fatal(err)
		}
		rules.VersionFamilies = []catalog.VersionFamily{{
			Source: source, PublicID: "gpt-5.2", PreferredUpstreamID: "gpt-5.2",
			Members:  []catalog.FamilyMember{{UpstreamID: "gpt-5.2", ExactIDAction: "keep"}, {UpstreamID: "gpt-5.2-2025-12-11", ExactIDAction: "hide"}},
			Decision: "approved", Evidence: "test-only family rule", ReviewedAt: "2026-10-14",
		}}
		writeWorkflowRules(t, cfg.RulesFile, rules)
		discovery, err := (Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}).Discover(context.Background(), cfg)
		if err != nil || discovery.Plan == nil || discovery.Plan.Accounts[0].ApplyEligible {
			t.Fatalf("explicit source-rule conflict should block changes: plan=%#v err=%v", discovery.Plan, err)
		}
		if len(discovery.Plan.Accounts[0].Changes) != 0 || discovery.Plan.Accounts[0].After["gpt-5.2"] != "gpt-5.2" || discovery.Plan.Accounts[0].After["new-model"] != "" {
			t.Fatalf("missing official product source changed an existing or new mapping: %#v", discovery.Plan.Accounts[0])
		}
		result, err := (Applier{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
		if err == nil || len(result.AppliedIDs) != 0 || len(api.bulkCalls) != 0 {
			t.Fatalf("mapping mutation was allowed without official evidence: result=%#v err=%v writes=%v", result, err, api.bulkCalls)
		}
	})

	t.Run("manual-only keeps its add-only mapping boundary", func(t *testing.T) {
		cfg, _, api, now := ownerAvailabilityWorkflowFixture(t, false, []string{"stable"})
		cfg.RequireManualOnlyMode = true
		api.status.Schedule = "04:00"
		api.status.StatusSource = "postgres"
		api.status.LastScheduledAt = timePtr(time.Date(2026, 10, 11, 4, 0, 0, 0, now.Location()))
		api.status.Accounts[0].SourceProfileID = "manual_only"
		api.status.Accounts[0].Status = "skipped"
		discovery, err := (Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, ManualOnlyOnly: true}).Discover(context.Background(), cfg)
		if err != nil || discovery.Plan == nil || !discovery.Plan.Accounts[0].ApplyEligible {
			t.Fatalf("fresh official selector was incorrectly blocked by lifecycle documents: plan=%#v err=%v", discovery.Plan, err)
		}
		_, err = (Applier{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, ManualOnlyOnly: true}).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
		if err != nil || len(api.bulkCalls) != 0 || api.accounts[7].ModelMapping["gpt-5.2"] != "gpt-5.2" {
			t.Fatalf("manual-only refresh changed a mapping outside its add-only boundary: err=%v writes=%v mapping=%#v", err, api.bulkCalls, api.accounts[7].ModelMapping)
		}
	})
}

func ownerAvailabilityRulesFixture() catalog.Rules {
	ids := []string{"gpt-5.2", "gpt-5.2-pro", "gpt-5.3-codex", "gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.4-mini", "gpt-5.4-openai-compact"}
	observed := time.Date(2026, 10, 10, 20, 10, 0, 0, time.UTC)
	rules := catalog.Rules{
		SchemaVersion: 1, Aliases: []catalog.AliasRule{}, VersionFamilies: []catalog.VersionFamily{}, RetiredModels: []catalog.RetiredRule{},
		SourceProfiles: []catalog.SourceProfile{}, CompleteCatalogProfiles: []catalog.CompleteCatalogProfile{},
		OfficialSelectability: []catalog.OfficialSelectability{{Scope: "official-account:test-owner-account", Complete: true, ModelIDs: []string{"stable", "upstream-known", "new-model"}, ObservedAt: observed, ExpiresAt: observed.Add(catalog.OfficialSelectabilityMaxAge), Evidence: "synthetic complete selector snapshot"}},
	}
	for _, id := range ids {
		rules.OwnerLifecycleExclusions = append(rules.OwnerLifecycleExclusions, catalog.OwnerLifecycleExclusion{Scope: ownerAvailabilityScope, ModelID: id, Decision: "approved", Evidence: "owner-confirmed unavailable for the user's ordinary Codex sign-in", ReviewedAt: "2026-10-14"})
	}
	return rules
}

func ownerAvailabilityWorkflowFixture(t *testing.T, fullScreen bool, liveModels []string) (config.Config, adminapi.Account, *workflowAPI, time.Time) {
	t.Helper()
	cfg, account, now := testWorkflowConfig(t, true, true)
	cfg.AccountScope = "all"
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.Accounts = nil
	cfg.AllowFullScreenMode = fullScreen
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	account.ModelMapping = map[string]string{"gpt-5.2": "gpt-5.2", "stable": "stable"}
	source, err := catalog.SourceForAccount(account.Platform, account.Type, account.Protocol, account.BaseURL, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	rules := ownerAvailabilityRulesFixture()
	rules.SourceProfiles = []catalog.SourceProfile{{
		Source: source, BuildID: "test-build", APIContractID: config.APIContractAllAccountsV1, Decision: "approved",
		OfficialSelectabilityScope: "official-account:test-owner-account", OfficialSelectabilityProduct: "ui",
		LifecycleScopes: []string{ownerAvailabilityScope}, IdentityAddPolicy: "add_exact", IdentityCatalogPolicy: "add_identity_from_live_list",
		Evidence: "mock source/build/API compatibility fixture", ReviewedAt: "2026-10-14",
	}}
	writeWorkflowRules(t, cfg.RulesFile, rules)
	fingerprint := catalog.SourceFingerprint(source)
	managed := state.State{Version: state.CurrentVersion, Accounts: map[string]state.Account{
		catalog.AccountKey(account.ID): {ManagedMappings: map[string]state.ManagedMapping{
			"gpt-5.2": {OriginalValue: "gpt-5.2", LastAppliedValue: "gpt-5.2", SourceFingerprint: fingerprint},
		}},
	}}
	if err := state.Save(filepath.Join(cfg.StateDir, "state.json"), managed); err != nil {
		t.Fatal(err)
	}
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: append([]string{}, liveModels...), LiveListAvailable: true})
	if !fullScreen {
		cfg.RequireManualOnlyMode = true
		api.status.Schedule = "04:00"
		api.status.StatusSource = "postgres"
		api.status.LastScheduledAt = timePtr(time.Date(2026, 10, 11, 4, 0, 0, 0, now.Location()))
		api.status.Accounts[0].SourceProfileID = "manual_only"
		api.status.Accounts[0].Status = "skipped"
	}
	return cfg, account, api, now
}

func clonePlanForTest(plan catalog.Plan) catalog.Plan {
	copyPlan := plan
	copyPlan.Before = cloneWorkflowMapping(plan.Before)
	copyPlan.After = cloneWorkflowMapping(plan.After)
	copyPlan.Changes = append([]catalog.Change{}, plan.Changes...)
	copyPlan.Conflicts = append([]string{}, plan.Conflicts...)
	copyPlan.LifecycleExclusions = append([]catalog.LifecycleExclusion{}, plan.LifecycleExclusions...)
	return copyPlan
}

func TestApplyTransportUncertaintyUsesOneReadbackNoBlindRetry(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("discovery failed: %#v %v", discovery.Plan, err)
	}
	api.bulkErr = errors.New("mock transport loss")
	api.applyBeforeError = true
	applyStart := len(api.calls)
	result, err := workflowApplier(api, now).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
	if err != nil {
		t.Fatalf("successful readback did not resolve uncertain result: result=%#v err=%v", result, err)
	}
	if len(api.bulkCalls) != 1 || countCall(api.calls[applyStart:], "account:7") != 3 {
		t.Fatalf("uncertain write was retried or not read back once: bulk=%v calls=%v", api.bulkCalls, api.calls)
	}
}

func TestApplyStopsOnReadbackMismatchOrUnexpectedBulkResult(t *testing.T) {
	for _, mode := range []string{"mapping mismatch", "key presence changed", "failed or unexpected account IDs"} {
		name := mode
		t.Run(name, func(t *testing.T) {
			cfg, account, now := testWorkflowConfig(t, true, true)
			api := newWorkflowAPI(account, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
			discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
			if err != nil || discovery.Plan == nil {
				t.Fatalf("discovery failed: %#v %v", discovery.Plan, err)
			}
			switch mode {
			case "failed or unexpected account IDs":
				api.unexpectedBulkResult = true
			case "mapping mismatch":
				api.ignoreBulkWrite = true
			case "key presence changed":
				api.flipAPIKeyPresenceOnBulk = true
			}
			_, err = workflowApplier(api, now).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
			if err == nil || len(api.bulkCalls) != 1 {
				t.Fatalf("unsafe write outcome did not stop: err=%v calls=%v", err, api.bulkCalls)
			}
			if len(api.bulkCalls) > 1 {
				t.Fatalf("write outcome triggered blind retry: %v", api.bulkCalls)
			}
		})
	}
}

func TestAccountKeyPresenceMustBeAvailableAndUnchangedForReadback(t *testing.T) {
	trueValue, falseValue := true, false
	cases := []struct {
		name  string
		prior *bool
		next  *bool
		want  bool
	}{
		{"true preserved", &trueValue, &trueValue, true},
		{"false preserved", &falseValue, &falseValue, true},
		{"marker missing", nil, nil, false},
		{"marker lost", &trueValue, nil, false},
		{"presence changed", &trueValue, &falseValue, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := adminapi.Account{ID: 7, Platform: "openai", Type: "apikey", Protocol: "openai", BaseURL: "https://provider.example/v1", Status: "active", APIKeyPresent: tc.prior, ModelMapping: map[string]string{}}
			after := before
			after.APIKeyPresent = tc.next
			if got := sameAccountSource(before, after); got != tc.want {
				t.Fatalf("sameAccountSource()=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestApplyRechecksEachAccountImmediatelyBeforeWriteAndReportsPartialSuccess(t *testing.T) {
	cfg, account1, now := testWorkflowConfig(t, true, true)
	account2 := adminapi.Account{ID: 8, Platform: account1.Platform, Type: account1.Type, Protocol: account1.Protocol, BaseURL: account1.BaseURL, Status: account1.Status, ModelMapping: map[string]string{"untouched": "keep-me"}, APIKeyPresent: boolPointer(true)}
	cfg.Accounts = append(cfg.Accounts, config.AccountConfig{ID: account2.ID, AcceptCredentialResponseMemoryExposure: boolPointer(true)})
	rules := workflowRules(account1)
	rules.Aliases[0].Source.AccountID = 0
	rules.SourceProfiles[0].Source.AccountID = 0
	writeWorkflowRules(t, cfg.RulesFile, rules)
	api := newWorkflowAPI(account1, now, adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true})
	api.accounts[account2.ID] = account2
	api.catalogs[account2.ID] = adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true}
	api.status.Accounts = append(api.status.Accounts, adminapi.AccountRunStatus{AccountID: account2.ID, Status: "completed"})
	discovery, err := workflowDiscoverer(api, now).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil || len(discovery.Plan.Accounts) != 2 {
		t.Fatalf("two-account discovery failed: %#v %v", discovery.Plan, err)
	}
	api.afterBulk = func(id int64, api *workflowAPI) {
		if id == account1.ID {
			a := api.accounts[account2.ID]
			a.ModelMapping["untouched"] = "external-edit"
			api.accounts[account2.ID] = a
		}
	}
	result, err := workflowApplier(api, now).Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, discovery.PlanSHA256, false)
	if err == nil || !result.Consumed || !reflect.DeepEqual(result.AppliedIDs, []int64{account1.ID}) {
		t.Fatalf("partial success was not recorded after account 2 drift: result=%#v err=%v", result, err)
	}
	if !reflect.DeepEqual(api.bulkCalls, []int64{account1.ID}) {
		t.Fatalf("drifted second account was written: bulk IDs=%v", api.bulkCalls)
	}
	if api.accounts[account2.ID].ModelMapping["untouched"] != "external-edit" {
		t.Fatalf("external edit was overwritten: %#v", api.accounts[account2.ID].ModelMapping)
	}
}

func TestApplyingRetirementClearsPersistedAbsenceCounter(t *testing.T) {
	s := state.Empty()
	s.Accounts["9001"] = state.Account{
		ManagedMappings: map[string]state.ManagedMapping{
			"public-model": {OriginalValue: "old", LastAppliedValue: "upstream-model", SourceFingerprint: "source-fingerprint"},
		},
		AbsenceCounts: map[string]int{"public-model": 2},
	}
	applyManagedChanges(&s, catalog.Plan{
		AccountID: 9001,
		Changes:   []catalog.Change{{Action: "remove", PublicID: "public-model", Before: "upstream-model", RuleKind: "complete_catalog_absence"}},
	})
	account := s.Accounts["9001"]
	if _, ok := account.ManagedMappings["public-model"]; ok {
		t.Fatal("applied retirement retained managed ownership")
	}
	if _, ok := account.AbsenceCounts["public-model"]; ok {
		t.Fatalf("applied retirement retained its absence counter: %v", account.AbsenceCounts)
	}
}

func TestNativeRefreshCurrentRequiresTodayShanghaiSuccess(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 11, 4, 10, 0, 0, loc)
	previous := now.AddDate(0, 0, -1)
	future := now.Add(time.Minute)
	for _, tc := range []struct {
		name   string
		status adminapi.RefreshStatus
		want   bool
	}{
		{"current complete", adminapi.RefreshStatus{Enabled: true, Timezone: "Asia/Shanghai", RunStatus: "completed", LastFinishedAt: timePtr(now.Add(-time.Minute))}, true},
		{"current partial", adminapi.RefreshStatus{Enabled: true, Timezone: "Asia/Shanghai", RunStatus: "partial_failure", LastFinishedAt: timePtr(now.Add(-time.Minute))}, true},
		{"previous day", adminapi.RefreshStatus{Enabled: true, Timezone: "Asia/Shanghai", RunStatus: "completed", LastFinishedAt: timePtr(previous)}, false},
		{"future", adminapi.RefreshStatus{Enabled: true, Timezone: "Asia/Shanghai", RunStatus: "completed", LastFinishedAt: timePtr(future)}, false},
		{"wrong timezone", adminapi.RefreshStatus{Enabled: true, Timezone: "UTC", RunStatus: "completed", LastFinishedAt: timePtr(now)}, false},
		{"running", adminapi.RefreshStatus{Enabled: true, Timezone: "Asia/Shanghai", RunStatus: "running", LastFinishedAt: timePtr(now)}, false},
		{"disabled", adminapi.RefreshStatus{Enabled: false, Timezone: "Asia/Shanghai", RunStatus: "completed", LastFinishedAt: timePtr(now)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NativeRefreshCurrent(tc.status, now); got != tc.want {
				t.Fatalf("NativeRefreshCurrent()=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestManualOnlyRefreshRequiresExactCompletedFourAMPostgresRun(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 12, 4, 10, 0, 0, loc)
	good := adminapi.RefreshStatus{Enabled: true, Schedule: "04:00", Timezone: "Asia/Shanghai", StatusSource: "postgres", RunStatus: "completed", LastScheduledAt: timePtr(time.Date(2026, 10, 12, 4, 0, 0, 0, loc)), LastFinishedAt: timePtr(time.Date(2026, 10, 12, 4, 2, 0, 0, loc))}
	if !ManualOnlyRefreshCurrent(good, now) {
		t.Fatal("current completed 04:00 PostgreSQL run was rejected")
	}
	cases := []struct {
		name   string
		change func(*adminapi.RefreshStatus)
	}{
		{"wrong schedule", func(s *adminapi.RefreshStatus) { s.Schedule = "05:00" }},
		{"wrong source", func(s *adminapi.RefreshStatus) { s.StatusSource = "memory" }},
		{"partial", func(s *adminapi.RefreshStatus) { s.RunStatus = "partial_failure" }},
		{"previous scheduled date", func(s *adminapi.RefreshStatus) { s.LastScheduledAt = timePtr(time.Date(2026, 10, 11, 4, 0, 0, 0, loc)) }},
		{"missing finish time", func(s *adminapi.RefreshStatus) { s.LastFinishedAt = nil }},
		{"finish before scheduled time", func(s *adminapi.RefreshStatus) { s.LastFinishedAt = timePtr(time.Date(2026, 10, 12, 3, 59, 0, 0, loc)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			copy := good
			tc.change(&copy)
			if ManualOnlyRefreshCurrent(copy, now) {
				t.Fatal("invalid native refresh state was accepted")
			}
		})
	}
}

func TestManualOnlySkippedAccountSelectionIsExactAndFailClosed(t *testing.T) {
	status := adminapi.RefreshStatus{Accounts: []adminapi.AccountRunStatus{
		{AccountID: 1, SourceProfileID: "manual_only", Status: "skipped"},
		{AccountID: 2, SourceProfileID: "openai-official", Status: "completed"},
		{AccountID: 3, SourceProfileID: "manual_only", Status: "failed"},
	}}
	ids, err := ManualOnlySkippedAccountIDs(status)
	if err != nil || len(ids) != 1 || ids[0] != 1 {
		t.Fatalf("unexpected selected manual-only IDs: ids=%v err=%v", ids, err)
	}
	status.Accounts = append(status.Accounts, status.Accounts[0])
	if _, err := ManualOnlySkippedAccountIDs(status); err == nil {
		t.Fatal("duplicate native account rows must fail closed")
	}
	status.Accounts = []adminapi.AccountRunStatus{{AccountID: 1, SourceProfileID: "manual_only", Status: "future_unknown_state"}}
	if _, err := ManualOnlySkippedAccountIDs(status); err == nil {
		t.Fatal("unknown native account refresh statuses must fail closed")
	}
}

func TestManualOnlyRunPlansOnlyExactSkippedAccountsAndPreservesUnprovenModels(t *testing.T) {
	cfg, selected, now := testWorkflowConfig(t, true, true)
	now = time.Date(2026, 10, 12, 4, 10, 0, 0, now.Location())
	selected.ModelMapping = map[string]string{"old-model": "old-model", "still-live": "still-live", "keep-alias": "provider-alias"}
	cfg.AccountScope = "all"
	cfg.Accounts = nil
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	cfg.ApplyMode = "preview"
	cfg.ApprovedRulesSHA256 = ""

	rules := workflowRules(selected)
	rules.OfficialSelectability[0].ObservedAt = now.UTC()
	rules.OfficialSelectability[0].ExpiresAt = now.UTC().Add(catalog.OfficialSelectabilityMaxAge)
	rules.Aliases = []catalog.AliasRule{}
	rules.SourceProfiles[0].APIContractID = config.APIContractAllAccountsV1
	rules.SourceProfiles[0].IdentityAddPolicy = "report_only"
	rules.SourceProfiles[0].IdentityCatalogPolicy = "replace_identity_from_live_list"
	writeWorkflowRules(t, cfg.RulesFile, rules)
	_, ruleHash, err := catalog.LoadRulesWithHash(cfg.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ApplyMode = "approved_rules"
	cfg.ApprovedRulesSHA256 = ruleHash
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	other := selected
	other.ID = 8
	other.ModelMapping = map[string]string{"other-model": "other-model"}
	api := &workflowAPI{
		status: adminapi.RefreshStatus{
			Enabled: true, Schedule: "04:00", Timezone: "Asia/Shanghai", StatusSource: "postgres", RunStatus: "completed",
			LastScheduledAt: timePtr(time.Date(2026, 10, 12, 4, 0, 0, 0, now.Location())),
			LastFinishedAt:  timePtr(time.Date(2026, 10, 12, 4, 2, 0, 0, now.Location())),
			Accounts: []adminapi.AccountRunStatus{
				{AccountID: selected.ID, SourceProfileID: "manual_only", Status: "skipped"},
				{AccountID: other.ID, SourceProfileID: "official", Status: "completed"},
			},
		},
		accounts: map[int64]adminapi.Account{selected.ID: selected, other.ID: other},
		catalogs: map[int64]adminapi.Catalog{selected.ID: {Models: []string{"new-model", "still-live"}, LiveListAvailable: true}},
	}
	discoverer := Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, ManualOnlyOnly: true}
	discovery, err := discoverer.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if api.syncCalls != 1 || discovery.Plan == nil || len(discovery.Plan.Accounts) != 1 || discovery.Plan.Accounts[0].AccountID != selected.ID {
		t.Fatalf("manual-only discovery selected wrong accounts: sync=%d plan=%#v", api.syncCalls, discovery.Plan)
	}
	if len(discovery.Report.Discovery) != 2 || discovery.Report.Discovery[1].Status != "skipped_not_manual_only" {
		t.Fatalf("non-manual account was not reported as skipped: %#v", discovery.Report.Discovery)
	}
	if api.bulkCalls != nil {
		t.Fatal("discovery must not write mapping before Apply")
	}

	apply := workflowApplier(api, now)
	apply.ManualOnlyOnly = true
	result, err := apply.Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AppliedIDs) != 0 || len(result.NoopIDs) != 1 || result.NoopIDs[0] != selected.ID || len(api.bulkCalls) != 0 {
		t.Fatalf("manual-only apply should preserve unproven models without writing: result=%#v calls=%v", result, api.bulkCalls)
	}
	updated := api.accounts[selected.ID].ModelMapping
	if updated["old-model"] != "old-model" || updated["new-model"] != "" || updated["still-live"] != "still-live" || updated["keep-alias"] != "provider-alias" {
		t.Fatalf("manual-only mapping did not preserve insufficient official evidence: %#v", updated)
	}
	if api.accounts[other.ID].ModelMapping["other-model"] != "other-model" || countCall(api.calls, "sync:8") != 0 {
		t.Fatal("non-manual account was probed or modified")
	}
}

func TestFullScreenBlocksLiveCatalogIdentityChangesWithoutOfficialProductScope(t *testing.T) {
	cfg, selected, now := testWorkflowConfig(t, true, true)
	clock := now
	advancingNow := func() time.Time {
		current := clock
		clock = clock.Add(time.Nanosecond)
		return current
	}
	cfg.AccountScope = "all"
	cfg.Accounts = nil
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.AllowFullScreenMode = true
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	cfg.ApplyMode = "approved_rules"
	selected.ModelMapping = map[string]string{"stale-model": "stale-model", "keep-model": "keep-model"}

	rules := workflowRules(selected)
	rules.Aliases = []catalog.AliasRule{}
	rules.SourceProfiles[0].APIContractID = config.APIContractAllAccountsV1
	rules.SourceProfiles[0].IdentityAddPolicy = "add_exact"
	rules.SourceProfiles[0].IdentityCatalogPolicy = "replace_identity_from_live_list"
	writeWorkflowRules(t, cfg.RulesFile, rules)
	source, err := catalog.SourceForAccount(selected.Platform, selected.Type, selected.Protocol, selected.BaseURL, selected.ID)
	if err != nil {
		t.Fatal(err)
	}
	local, err := state.Load(filepath.Join(cfg.StateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	accountState := local.Accounts[catalog.AccountKey(selected.ID)]
	if accountState.ManagedMappings == nil {
		accountState.ManagedMappings = map[string]state.ManagedMapping{}
	}
	accountState.ManagedMappings["stale-model"] = state.ManagedMapping{OriginalValue: "stale-model", LastAppliedValue: "stale-model", SourceFingerprint: catalog.SourceFingerprint(source)}
	local.Accounts[catalog.AccountKey(selected.ID)] = accountState
	if err := state.Save(filepath.Join(cfg.StateDir, "state.json"), local); err != nil {
		t.Fatal(err)
	}
	_, rulesHash, err := catalog.LoadRulesWithHash(cfg.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ApprovedRulesSHA256 = rulesHash

	unsupported := adminapi.Account{ID: 8, Platform: "anthropic", Type: "apikey", Protocol: "anthropic", BaseURL: "https://unreviewed.example/v1", Status: "active", ModelMapping: map[string]string{"manual": "preserve"}, APIKeyPresent: boolPointer(true)}
	inactive := selected
	inactive.ID = 9
	inactive.Status = "error"
	shadowParent := selected.ID
	shadow := selected
	shadow.ID = 10
	shadow.ParentAccountID = &shadowParent
	unrestricted := selected
	unrestricted.ID = 11
	unrestricted.ModelMapping = nil
	api := &workflowAPI{
		status:   adminapi.RefreshStatus{Enabled: true, Timezone: "Asia/Shanghai", RunStatus: "partial_failure", LastFinishedAt: timePtr(now.Add(-24 * time.Hour))},
		accounts: map[int64]adminapi.Account{selected.ID: selected, unsupported.ID: unsupported, inactive.ID: inactive, shadow.ID: shadow, unrestricted.ID: unrestricted},
		catalogs: map[int64]adminapi.Catalog{selected.ID: {Models: []string{"new-model", "keep-model"}, LiveListAvailable: true}},
	}
	discovery, err := (Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: advancingNow, FullScreen: true}).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("full-screen discovery failed: plan=%#v err=%v", discovery.Plan, err)
	}
	if got := discovery.Plan.ExpiresAt.Sub(discovery.Plan.CreatedAt); got != catalog.ApprovalPlanTTL {
		t.Fatalf("full-screen plan validity window = %s, want exactly %s", got, catalog.ApprovalPlanTTL)
	}
	if !discovery.Report.FullAccountScreen || discovery.Report.AccountScanStatus != "complete" || discovery.Report.AccountInventoryCount != 5 || len(discovery.Report.Discovery) != 5 {
		t.Fatalf("full-screen run did not cover the complete inventory: %#v", discovery.Report)
	}
	if countCall(api.calls, "status") != 1 || api.syncCalls != 1 || !hasCall(api.calls, "sync:7") || hasCall(api.calls, "sync:8") || hasCall(api.calls, "sync:9") || hasCall(api.calls, "sync:10") || hasCall(api.calls, "sync:11") {
		t.Fatalf("full-screen mode did not check native refresh once before discovery or synced ineligible accounts: calls=%v sync=%d", api.calls, api.syncCalls)
	}
	statuses := map[int64]string{}
	discoveryRows := map[int64]report.DiscoveryAccount{}
	for _, row := range discovery.Report.Discovery {
		statuses[row.ID] = row.Status
		discoveryRows[row.ID] = row
	}
	if statuses[8] != "skipped" || statuses[9] != "skipped_inactive" || statuses[10] != "skipped_shadow" || statuses[11] != "skipped_unrestricted_mapping" {
		t.Fatalf("full-screen did not report accounts outside its mutation gate: %v", statuses)
	}
	if len(api.bulkCalls) != 0 {
		t.Fatal("discovery unexpectedly changed a Sub2API mapping")
	}
	if discoveryRows[selected.ID].CurrentMappingStatus != "explicit_nonempty" || !containsReportMapping(discoveryRows[selected.ID].CurrentMappings, "stale-model", "stale-model") || discoveryRows[inactive.ID].CurrentMappingStatus != "explicit_nonempty" || !containsReportMapping(discoveryRows[inactive.ID].CurrentMappings, "keep-model", "keep-model") {
		t.Fatalf("full-screen discovery did not preserve mappings it had already read for the summary: selected=%#v inactive=%#v", discoveryRows[selected.ID], discoveryRows[inactive.ID])
	}
	if discoveryRows[unrestricted.ID].CurrentMappingStatus != "no_explicit_mapping" || len(discoveryRows[unrestricted.ID].CurrentMappings) != 0 || discoveryRows[10].CurrentMappingStatus != "explicit_nonempty" {
		t.Fatalf("summary mapping status collapsed unrestricted/empty or shadow accounts: unrestricted=%#v shadow=%#v", discoveryRows[unrestricted.ID], discoveryRows[10])
	}

	plan := discovery.Plan.Accounts[0]
	if !plan.ApplyEligible || len(plan.Changes) != 0 || plan.After["new-model"] != "" || plan.After["stale-model"] != "stale-model" || !slices.Contains(plan.UnreviewedModels, "new-model") {
		t.Fatalf("full-screen did not preserve mappings and block identity imports without official product evidence: %#v", plan)
	}
	// The full-account replay now requires every active account detail to
	// explicitly report its mapping field. Model the unrestricted account's
	// known empty mapping as an explicit empty object in the Apply-time detail.
	unrestrictedDetail := api.accounts[unrestricted.ID]
	unrestrictedDetail.ModelMapping = map[string]string{}
	unrestrictedDetail.ModelMappingPresent = true
	api.accounts[unrestricted.ID] = unrestrictedDetail
	applier := workflowApplier(api, clock)
	applier.FullScreen = true
	result, err := applier.Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, "", true)
	if err != nil || len(result.AppliedIDs) != 0 || len(api.bulkCalls) != 0 {
		t.Fatalf("full-screen wrote live identity changes without official product evidence: result=%#v err=%v calls=%v", result, err, api.bulkCalls)
	}
	if api.accounts[selected.ID].ModelMapping["stale-model"] != "stale-model" || api.accounts[selected.ID].ModelMapping["new-model"] != "" {
		t.Fatalf("blocked full-screen changed target mappings: %#v", api.accounts[selected.ID].ModelMapping)
	}
	if api.accounts[unsupported.ID].ModelMapping["manual"] != "preserve" || countCall(api.calls, "status") != 1 {
		t.Fatalf("full-screen changed an unsupported account or made an unexpected refresh check: calls=%v", api.calls)
	}
}

func TestNativeRefreshGateAllowsOnlyKnownNonRunningStates(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     adminapi.RefreshStatus
		statusErr  error
		wantReason string
	}{
		{name: "completed", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "completed"}},
		{name: "succeeded", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "succeeded"}},
		{name: "partial failure", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "partial_failure"}},
		{name: "never run", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "never_run"}},
		{name: "running", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "running"}, wantReason: "native_refresh_running"},
		{name: "stale running", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "stale_running"}, wantReason: "native_refresh_running"},
		{name: "unavailable", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "unavailable"}, wantReason: "native_refresh_status_unavailable"},
		{name: "empty", status: adminapi.RefreshStatus{Enabled: true}, wantReason: "native_refresh_status_unknown"},
		{name: "unknown", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "future_status"}, wantReason: "native_refresh_status_unknown"},
		{name: "disabled", status: adminapi.RefreshStatus{Enabled: false, RunStatus: "completed"}, wantReason: "native_refresh_status_unknown"},
		{name: "api error", statusErr: errors.New("mock API failure"), wantReason: "native_refresh_status_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &workflowAPI{status: tc.status, statusErr: tc.statusErr}
			_, err := CheckNativeRefreshGate(context.Background(), api)
			if tc.wantReason == "" {
				if err != nil {
					t.Fatalf("known non-running status blocked: %v", err)
				}
				return
			}
			var gate interface{ ReasonCode() string }
			if !errors.As(err, &gate) || gate.ReasonCode() != tc.wantReason {
				t.Fatalf("gate error=%v, want reason %s", err, tc.wantReason)
			}
		})
	}
}

func TestFullScreenDiscoveryRefreshGateStopsBeforeAccountDiscovery(t *testing.T) {
	cfg, _, now := testWorkflowConfig(t, true, true)
	cfg.AccountScope = "all"
	cfg.Accounts = nil
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.AllowFullScreenMode = true
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	for _, tc := range []struct {
		name      string
		status    adminapi.RefreshStatus
		statusErr error
	}{
		{name: "running", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "running"}},
		{name: "stale", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "stale_running"}},
		{name: "unavailable", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "unavailable"}},
		{name: "unknown", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "new_status"}},
		{name: "empty", status: adminapi.RefreshStatus{Enabled: true}},
		{name: "API error", statusErr: errors.New("mock API failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &workflowAPI{status: tc.status, statusErr: tc.statusErr}
			d := Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}
			_, err := d.Discover(context.Background(), cfg)
			if err == nil || !hasCall(api.calls, "status") || hasCall(api.calls, "list_accounts") || api.syncCalls != 0 || len(api.bulkCalls) != 0 {
				t.Fatalf("native refresh gate did not block discovery before account reads/sync: calls=%v err=%v", api.calls, err)
			}
		})
	}
}

func TestFullScreenApplyRechecksNativeRefreshBeforeEveryMappingWrite(t *testing.T) {
	cfg, account1, now := testWorkflowConfig(t, true, true)
	cfg.AccountScope = "all"
	cfg.Accounts = nil
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.AllowFullScreenMode = true
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	cfg.ApplyMode = "approved_rules"
	account1.ModelMapping = map[string]string{"old": "old"}
	account2 := account1
	account2.ID = 8
	rules := workflowRules(account1)
	rules.SourceProfiles[0].Source.AccountID = 0
	rules.SourceProfiles[0].APIContractID = config.APIContractAllAccountsV1
	// Use an existing exact mapped ID: with no official source fixture, the
	// approved account probe is the evidence that permits this alias.
	rules.Aliases = []catalog.AliasRule{{Source: rules.SourceProfiles[0].Source, UpstreamID: "old", PublicID: "canonical-new", Decision: "approved", Evidence: "exact synthetic test fixture", ReviewedAt: "2026-10-11"}}
	writeWorkflowRules(t, cfg.RulesFile, rules)
	_, hash, err := catalog.LoadRulesWithHash(cfg.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ApprovedRulesSHA256 = hash
	api := &workflowAPI{
		status:   adminapi.RefreshStatus{Enabled: true, RunStatus: "completed"},
		accounts: map[int64]adminapi.Account{account1.ID: account1, account2.ID: account2},
		catalogs: map[int64]adminapi.Catalog{
			account1.ID: {Models: []string{"old", "new-model"}, LiveListAvailable: true},
			account2.ID: {Models: []string{"old", "new-model"}, LiveListAvailable: true},
		},
	}
	discovery, err := (Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}).Discover(context.Background(), cfg)
	if err != nil || discovery.Plan == nil || len(discovery.Plan.Accounts) != 2 {
		t.Fatalf("full-screen setup failed: plan=%#v err=%v", discovery.Plan, err)
	}
	api.afterBulk = func(id int64, api *workflowAPI) {
		if id == account1.ID {
			api.status.RunStatus = "running"
		}
	}
	applier := workflowApplier(api, now)
	applier.FullScreen = true
	result, err := applier.Apply(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, "", true)
	var gate interface{ ReasonCode() string }
	if !errors.As(err, &gate) || gate.ReasonCode() != "native_refresh_running" {
		t.Fatalf("second mapping write was not blocked by newly-running refresh: plan=%#v result=%#v err=%v", discovery.Plan.Accounts, result, err)
	}
	if !reflect.DeepEqual(api.bulkCalls, []int64{account1.ID}) || !reflect.DeepEqual(result.AppliedIDs, []int64{account1.ID}) || result.FailedID != 0 || countCall(api.calls, "status") != 3 {
		t.Fatalf("refresh start was not checked before each mapping write: result=%#v bulk=%v calls=%v", result, api.bulkCalls, api.calls)
	}
}

func containsReportMapping(mappings []report.Mapping, publicID, upstreamID string) bool {
	for _, mapping := range mappings {
		if mapping.PublicID == publicID && mapping.UpstreamID == upstreamID {
			return true
		}
	}
	return false
}

func TestFullScreenGatesBeforeCredentialOrAPI(t *testing.T) {
	for _, tc := range []struct {
		name        string
		configure   func(*config.Config, *Discoverer)
		wantMessage string
	}{
		{name: "missing config opt-in", configure: func(_ *config.Config, d *Discoverer) { d.FullScreen = true }, wantMessage: "explicit all-account configuration gate"},
		{name: "manual mode combination", configure: func(c *config.Config, d *Discoverer) {
			c.AccountScope = "all"
			c.Accounts = nil
			c.AcceptAllCredentialResponseMemoryExposure = true
			c.AllowNativeSyncMetadataWrite = true
			c.AllowFullScreenMode = true
			c.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
			d.FullScreen = true
			d.ManualOnlyOnly = true
		}, wantMessage: "cannot be combined"},
		{name: "full config requires explicit flag", configure: func(c *config.Config, _ *Discoverer) {
			c.AccountScope = "all"
			c.Accounts = nil
			c.AcceptAllCredentialResponseMemoryExposure = true
			c.AllowNativeSyncMetadataWrite = true
			c.AllowFullScreenMode = true
			c.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
		}, wantMessage: "reserved for --full-screen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, _ := testWorkflowConfig(t, true, true)
			credentialCalls, clientCalls := 0, 0
			d := Discoverer{
				ReadCredential: func(config.CredentialConfig) (securecred.Value, error) {
					credentialCalls++
					return securecred.Value{}, nil
				},
				NewClient: func(string) (AdminAPI, error) { clientCalls++; return &workflowAPI{}, nil },
			}
			tc.configure(&cfg, &d)
			_, err := d.Discover(context.Background(), cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantMessage) || credentialCalls != 0 || clientCalls != 0 {
				t.Fatalf("full-screen gate did not reject before external access: err=%v credentials=%d clients=%d", err, credentialCalls, clientCalls)
			}
		})
	}
}

func TestManualOnlyRequiredConfigBlocksOrdinaryDiscoverAndApplyBeforeAccess(t *testing.T) {
	cfg, _, _ := testWorkflowConfig(t, true, true)
	cfg.AccountScope = "all"
	cfg.Accounts = nil
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.RequireManualOnlyMode = true
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	credentialCalls, clientCalls := 0, 0
	readCredential := func(config.CredentialConfig) (securecred.Value, error) {
		credentialCalls++
		return securecred.Value{APIKey: []byte("test-admin-key")}, nil
	}
	newClient := func(string) (AdminAPI, error) {
		clientCalls++
		return nil, errors.New("client should not be created")
	}
	if _, err := (Discoverer{ReadCredential: readCredential, NewClient: newClient}).Discover(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "requires manual-only mode") {
		t.Fatalf("ordinary discovery was not blocked: %v", err)
	}
	if _, err := (Applier{ReadCredential: readCredential, NewClient: newClient}).Apply(context.Background(), cfg, catalog.ApprovalPlan{}, "", "", false); err == nil || !strings.Contains(err.Error(), "requires manual-only mode") {
		t.Fatalf("ordinary apply was not blocked: %v", err)
	}
	if credentialCalls != 0 || clientCalls != 0 {
		t.Fatalf("manual-only mode gate ran after external access: credentials=%d clients=%d", credentialCalls, clientCalls)
	}
}

func TestLiveIdentityCatalogRulesRequireManualOnlyBeforeExternalAccess(t *testing.T) {
	cfg, account, now := testWorkflowConfig(t, true, true)
	rules := workflowRules(account)
	rules.SourceProfiles[0].IdentityCatalogPolicy = "replace_identity_from_live_list"
	writeWorkflowRules(t, cfg.RulesFile, rules)
	credentialCalls, clientCalls := 0, 0
	_, err := (Discoverer{
		ReadCredential: func(config.CredentialConfig) (securecred.Value, error) {
			credentialCalls++
			return securecred.Value{APIKey: []byte("test-admin-key")}, nil
		},
		NewClient: func(string) (AdminAPI, error) {
			clientCalls++
			return nil, errors.New("client should not be created")
		},
		Now: func() time.Time { return now },
	}).Discover(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "live identity catalog rules require manual-only, full-screen, or manual-sync-authorized mode") || credentialCalls != 0 || clientCalls != 0 {
		t.Fatalf("identity sync rules did not require manual-only mode before external access: err=%v credentials=%d clients=%d", err, credentialCalls, clientCalls)
	}
}

func testWorkflowConfig(t *testing.T, expose, syncSideEffect bool) (config.Config, adminapi.Account, time.Time) {
	t.Helper()
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 11, 4, 10, 0, 0, loc)
	account := adminapi.Account{ID: 7, Platform: "openai", Type: "apikey", Protocol: "openai", BaseURL: "https://provider.example/v1", Status: "active", ModelMapping: map[string]string{"untouched": "keep-me"}, APIKeyPresent: boolPointer(true)}
	base := t.TempDir()
	cfg := config.Config{
		Target:                       config.TargetConfig{BaseURL: "https://404token.xyz", RuntimeCompatibility: config.RuntimeCompatibility{BuildID: "test-build", APIContractID: "admin-catalog-v1", Evidence: "mock-only fixture", ReviewedAt: now.Format("2006-01-02")}},
		Accounts:                     []config.AccountConfig{{ID: 7, AcceptCredentialResponseMemoryExposure: boolPointer(expose)}},
		AllowNativeSyncMetadataWrite: syncSideEffect,
		ApplyMode:                    "preview",
		Credential:                   config.CredentialConfig{WindowsCredentialTarget: "mock-only"},
		StateDir:                     filepath.Join(base, "state"),
		ReportDir:                    filepath.Join(base, "reports"),
		BackupDir:                    filepath.Join(base, "backups"),
		RulesFile:                    filepath.Join(base, "model-rules.json"),
	}
	writeWorkflowRules(t, cfg.RulesFile, workflowRules(account))
	return cfg, account, now
}

func workflowRules(account adminapi.Account) catalog.Rules {
	source, _ := catalog.SourceForAccount(account.Platform, account.Type, account.Protocol, account.BaseURL, account.ID)
	return catalog.Rules{
		SchemaVersion:           1,
		Aliases:                 []catalog.AliasRule{{Source: source, UpstreamID: "upstream-known", PublicID: "canonical-name", Decision: "approved", Evidence: "exact reviewed fixture", ReviewedAt: "2026-10-11"}},
		SourceProfiles:          []catalog.SourceProfile{{Source: source, BuildID: "test-build", APIContractID: "admin-catalog-v1", Decision: "approved", OfficialSelectabilityScope: "official-account:test-openai-account", OfficialSelectabilityProduct: "ui", IdentityAddPolicy: "add_exact", Evidence: "mock source/build/API compatibility fixture", ReviewedAt: "2026-10-11"}},
		OfficialSelectability:   []catalog.OfficialSelectability{{Scope: "official-account:test-openai-account", Complete: true, ModelIDs: []string{"upstream-known", "canonical-name", "gpt-5.2", "gpt-5.2-pro", "gpt-5.4", "new-model", "model", "stable", "existing", "unreviewed", "unknown", "brand-new-opaque-id", "claude-haiku-4-5-20251001", "preferred", "snapshot", "canonical", "other", "keep", "keep-me", "still-live", "provider-alias", "old-model", "stale-model", "keep-model", "old"}, ObservedAt: time.Date(2026, 10, 10, 20, 10, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 10, 11, 20, 10, 0, 0, time.UTC), Evidence: "synthetic official account selector fixture"}},
		CompleteCatalogProfiles: []catalog.CompleteCatalogProfile{},
		VersionFamilies:         []catalog.VersionFamily{},
		RetiredModels:           []catalog.RetiredRule{},
	}
}

func writeWorkflowRules(t *testing.T, path string, rules catalog.Rules) {
	t.Helper()
	body, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func appendFixtureByte(t *testing.T, path string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write([]byte(" "))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("could not mutate fixture: write=%v close=%v", writeErr, closeErr)
	}
}

func newWorkflowAPI(account adminapi.Account, now time.Time, catalogResult adminapi.Catalog) *workflowAPI {
	return &workflowAPI{
		status:   adminapi.RefreshStatus{Enabled: true, Timezone: "Asia/Shanghai", RunStatus: "completed", LastFinishedAt: timePtr(now.Add(-time.Minute)), Accounts: []adminapi.AccountRunStatus{{AccountID: account.ID, Status: "completed"}}},
		accounts: map[int64]adminapi.Account{account.ID: account}, catalogs: map[int64]adminapi.Catalog{account.ID: catalogResult},
	}
}

func workflowDiscoverer(api *workflowAPI, now time.Time) Discoverer {
	return Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }}
}

func workflowApplier(api *workflowAPI, now time.Time) Applier {
	return Applier{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }}
}

func workflowCredential(config.CredentialConfig) (securecred.Value, error) {
	return securecred.Value{APIKey: []byte("test-admin-key")}, nil
}

func (f *workflowAPI) SetAPIKey([]byte) error {
	f.calls = append(f.calls, "api_key")
	return nil
}

func (f *workflowAPI) RefreshStatus(context.Context) (adminapi.RefreshStatus, error) {
	f.calls = append(f.calls, "status")
	return f.status, f.statusErr
}

func (f *workflowAPI) ListAllAccounts(context.Context) ([]adminapi.AccountSummary, error) {
	f.calls = append(f.calls, "list_accounts")
	ids := append([]int64(nil), f.inventoryIDs...)
	if f.inventoryIDs == nil {
		ids = make([]int64, 0, len(f.accounts))
		for id := range f.accounts {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	items := make([]adminapi.AccountSummary, 0, len(ids))
	for _, id := range ids {
		account := f.accounts[id]
		items = append(items, adminapi.AccountSummary{ID: id, Platform: account.Platform, Type: account.Type, Status: account.Status, ParentAccountID: account.ParentAccountID})
	}
	return items, nil
}

func (f *workflowAPI) Account(_ context.Context, id int64) (adminapi.Account, error) {
	f.calls = append(f.calls, "account:"+intString(id))
	a, ok := f.accounts[id]
	if !ok {
		return adminapi.Account{}, errors.New("mock account missing")
	}
	a.ModelMapping = cloneWorkflowMapping(a.ModelMapping)
	return a, nil
}

func (f *workflowAPI) AccountWithPublishedSnapshot(ctx context.Context, id int64, _, _ string) (adminapi.Account, error) {
	return f.Account(ctx, id)
}

func (f *workflowAPI) SyncUpstream(_ context.Context, id int64) (adminapi.Catalog, error) {
	f.calls = append(f.calls, "sync:"+intString(id))
	f.syncCalls++
	result, ok := f.catalogs[id]
	if !ok {
		return adminapi.Catalog{}, errors.New("mock catalog missing")
	}
	result.Models = append([]string{}, result.Models...)
	result.Warnings = append([]adminapi.CatalogWarning{}, result.Warnings...)
	return result, nil
}

func (f *workflowAPI) ProbeModel(_ context.Context, id int64, modelID string) (adminapi.ModelProbeResult, error) {
	f.calls = append(f.calls, "probe:"+intString(id)+":"+modelID)
	if f.probeErrsByAccount != nil && f.probeErrsByAccount[id] != nil {
		return adminapi.ModelProbeResult{}, f.probeErrsByAccount[id]
	}
	if f.probeErrs != nil && f.probeErrs[modelID] != nil {
		return adminapi.ModelProbeResult{}, f.probeErrs[modelID]
	}
	if f.probeOutcomes != nil {
		if outcome, ok := f.probeOutcomes[modelID]; ok {
			return adminapi.ModelProbeResult{ModelID: modelID, Outcome: outcome}, nil
		}
	}
	return adminapi.ModelProbeResult{ModelID: modelID, Outcome: "succeeded"}, nil
}

func (f *workflowAPI) BulkUpdateMapping(_ context.Context, id int64, mapping map[string]string) (adminapi.BulkUpdateResult, error) {
	f.calls = append(f.calls, "bulk:"+intString(id))
	f.bulkCalls = append(f.bulkCalls, id)
	f.bulkMappings = append(f.bulkMappings, cloneWorkflowMapping(mapping))
	if f.applyBeforeError {
		a := f.accounts[id]
		a.ModelMapping = cloneWorkflowMapping(mapping)
		f.accounts[id] = a
	}
	if f.unexpectedBulkResult {
		return adminapi.BulkUpdateResult{}, adminapi.ErrUnexpectedBulkResult
	}
	if f.bulkErr != nil {
		return adminapi.BulkUpdateResult{}, f.bulkErr
	}
	if !f.ignoreBulkWrite {
		a := f.accounts[id]
		a.ModelMapping = cloneWorkflowMapping(mapping)
		f.accounts[id] = a
	}
	if f.flipAPIKeyPresenceOnBulk {
		a := f.accounts[id]
		value := false
		a.APIKeyPresent = &value
		f.accounts[id] = a
	}
	if f.afterBulk != nil {
		f.afterBulk(id, f)
	}
	return adminapi.BulkUpdateResult{SuccessIDs: []int64{id}, FailedIDs: []int64{}}, nil
}

func (f *workflowAPI) Close() {}

func TestResolveInsufficientEvidenceUsesFirstExactSuccessAcrossAccounts(t *testing.T) {
	plans := []catalog.Plan{
		{AccountID: 9, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "gpt-5.5", Status: "available"}}, Before: map[string]string{"gpt-5.5": "gpt-5.5"}},
		{AccountID: 3, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "gpt-5.5", Status: "insufficient_evidence"}}, Before: map[string]string{"gpt-5.5": "gpt-5.5"}},
	}
	api := &workflowAPI{}
	rows := []report.DiscoveryAccount{{ID: 3, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "gpt-5.5"}}}, {ID: 9, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "gpt-5.5"}}}}
	decisions, err := resolveInsufficientEvidence(context.Background(), api, plans, rows, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || decisions[0].Status != "available" || len(decisions[0].Accounts) != 1 {
		t.Fatalf("unexpected aggregate: %#v", decisions)
	}
	if decisions[0].Accounts[0].AccountID != 3 || decisions[0].Accounts[0].Outcome != "succeeded" {
		t.Fatalf("accounts were not sorted or probing did not stop after success: %#v", decisions[0].Accounts)
	}
	if len(api.calls) != 1 || api.calls[0] != "probe:3:gpt-5.5" {
		t.Fatalf("unexpected probe calls: %v", api.calls)
	}
	if err := applyModelProbeEvidence(&plans[1], decisions[0], time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("successful probe did not update the insufficient account: %v", err)
	}
	if plans[1].ProductAvailability[0].Status != "available" || plans[1].ProductAvailability[0].MatchKind != "account_probe_success" {
		t.Fatalf("probe success did not update its own uncertain evidence: %#v", plans[1].ProductAvailability[0])
	}
	if err := applyModelProbeEvidence(&plans[0], decisions[0], time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("probe success overrode an already official available decision")
	}
}

func TestResolveInsufficientEvidenceStopsAfterSuccessAcrossThreeAccounts(t *testing.T) {
	plans := []catalog.Plan{
		{AccountID: 3, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "gpt-6-sol", Provider: "openai", Status: "insufficient_evidence"}}, Before: map[string]string{"gpt-6-sol": "gpt-6-sol"}},
		{AccountID: 9, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "gpt-6-sol", Provider: "openai", Status: "insufficient_evidence"}}, Before: map[string]string{"gpt-6-sol": "gpt-6-sol"}},
		{AccountID: 12, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "gpt-6-sol", Provider: "openai", Status: "insufficient_evidence"}}, Before: map[string]string{"gpt-6-sol": "gpt-6-sol"}},
	}
	rows := []report.DiscoveryAccount{
		{ID: 3, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "gpt-6-sol"}}},
		{ID: 9, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "gpt-6-sol"}}},
		{ID: 12, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "gpt-6-sol"}}},
	}
	api := &workflowAPI{probeOutcomes: map[string]string{"gpt-6-sol": "succeeded"}}
	decisions, err := resolveInsufficientEvidence(context.Background(), api, plans, rows, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(api.calls) != 1 || api.calls[0] != "probe:3:gpt-6-sol" {
		t.Fatalf("probing continued after exact success: %v", api.calls)
	}
	if len(decisions) != 1 || decisions[0].Status != "available" || len(decisions[0].Accounts) != 3 {
		t.Fatalf("unexpected aggregate: %#v", decisions)
	}
	wantOutcomes := []catalog.ModelProbeOutcome{
		{AccountID: 3, Outcome: "succeeded"},
		{AccountID: 9, Outcome: "not_attempted_after_success"},
		{AccountID: 12, Outcome: "not_attempted_after_success"},
	}
	for i, want := range wantOutcomes {
		if decisions[0].Accounts[i] != want {
			t.Fatalf("account outcomes = %#v, want %#v", decisions[0].Accounts, wantOutcomes)
		}
	}
	if _, err := catalog.ModelProbeDigest(decisions); err != nil {
		t.Fatalf("valid one-success decision with remaining accounts marked not attempted was rejected: %v", err)
	}
}

func TestResolveInsufficientEvidenceRequiresEveryRelevantAccountToFail(t *testing.T) {
	plans := []catalog.Plan{
		{AccountID: 3, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "grok-4.5", Status: "insufficient_evidence"}}, Before: map[string]string{"grok-4.5": "grok-4.5"}},
		{AccountID: 9, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "grok-4.5", Status: "unavailable"}}, Before: map[string]string{"grok-4.5": "grok-4.5"}},
	}
	api := &workflowAPI{probeOutcomes: map[string]string{"grok-4.5": "failed"}}
	rows := []report.DiscoveryAccount{{ID: 3, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "grok-4.5"}}}, {ID: 9, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "grok-4.5"}}}}
	decisions, err := resolveInsufficientEvidence(context.Background(), api, plans, rows, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || decisions[0].Status != "unavailable" || len(decisions[0].Accounts) != 1 || decisions[0].Accounts[0].AccountID != 3 || decisions[0].Accounts[0].Outcome != "failed" {
		t.Fatalf("model was not marked unavailable after complete failure: %#v", decisions)
	}
	if len(api.calls) != 1 || api.calls[0] != "probe:3:grok-4.5" {
		t.Fatalf("officially unavailable account was probed: %v", api.calls)
	}
	if err := applyModelProbeEvidence(&plans[0], decisions[0], time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("terminal probe failure was not attached to the insufficient account: %v", err)
	}
	if plans[0].ProductAvailability[0].Status != "unavailable" || plans[0].ProductAvailability[0].MatchKind != "all_account_probes_failed" {
		t.Fatalf("probe failure did not update its uncertain evidence: %#v", plans[0].ProductAvailability[0])
	}
	if plans[1].ProductAvailability[0].Status != "unavailable" {
		t.Fatalf("probe failure overwrote official unavailability: %#v", plans[1].ProductAvailability[0])
	}
}

func TestUnavailableProbeCascadesToEqualOrLowerMappedVersions(t *testing.T) {
	when := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	plan := catalog.Plan{ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{
		{ModelID: "gpt-5.4", Provider: "openai", Status: "available", MatchKind: "exact", SourceIDs: []string{"openai-chatgpt-models"}, SourceURLs: []string{"https://chatgpt.com/models"}, ContentSHA256: []string{strings.Repeat("a", 64)}, RetrievedAt: when},
		{ModelID: "gpt-5.5", Provider: "openai", Status: "insufficient_evidence", MatchKind: "none"},
		{ModelID: "gpt-5.5-fast", Provider: "openai", Status: "insufficient_evidence", MatchKind: "account_probe_ignored", SourceIDs: []string{"404token-account-probe-v1"}, SourceURLs: []string{"https://404token.xyz/api/v1/admin/accounts/{account_id}/test"}, ContentSHA256: []string{strings.Repeat("b", 64)}, RetrievedAt: when},
		{ModelID: "gpt-5.5-openai-compact", Provider: "openai", Status: "insufficient_evidence", MatchKind: "account_probe_ignored", SourceIDs: []string{"404token-account-probe-v1"}, SourceURLs: []string{"https://404token.xyz/api/v1/admin/accounts/{account_id}/test"}, ContentSHA256: []string{strings.Repeat("c", 64)}, RetrievedAt: when},
		{ModelID: "gpt-5.6-fast", Provider: "openai", Status: "available", MatchKind: "exact", SourceIDs: []string{"openai-chatgpt-models"}, SourceURLs: []string{"https://chatgpt.com/models"}, ContentSHA256: []string{strings.Repeat("d", 64)}, RetrievedAt: when},
	}}
	decision := catalog.ModelProbeDecision{Provider: "openai", ModelID: "gpt-5.5", Status: "unavailable", Accounts: []catalog.ModelProbeOutcome{{AccountID: 3, Outcome: "failed"}}}
	if err := applyModelProbeEvidence(&plan, decision, when); err != nil {
		t.Fatalf("failed probe did not cascade: %v", err)
	}
	availability := make(map[string]catalog.ProductModelAvailability, len(plan.ProductAvailability))
	for _, item := range plan.ProductAvailability {
		availability[item.ModelID] = item
	}
	if got := availability["gpt-5.4"]; got.Status != "unavailable" || got.MatchKind != "lower_than_unavailable_version" || got.VersionFloorModelID != "gpt-5.5" {
		t.Fatalf("lower GPT version was not marked unavailable: %+v", got)
	}
	for _, id := range []string{"gpt-5.5-fast", "gpt-5.5-openai-compact"} {
		if got := availability[id]; got.Status != "unavailable" || got.MatchKind != "lower_than_unavailable_version" || got.VersionFloorModelID != "gpt-5.5" {
			t.Fatalf("equal-version GPT variant %s was not marked unavailable: %+v", id, got)
		}
	}
	if got := availability["gpt-5.5"]; got.Status != "unavailable" || got.MatchKind != "all_account_probes_failed" {
		t.Fatalf("the direct unavailable trigger was not preserved as evidence: %+v", got)
	}
	if got := availability["gpt-5.6-fast"]; got.Status != "available" {
		t.Fatalf("strictly higher GPT version was incorrectly marked unavailable: %+v", got)
	}
	if _, err := catalog.ProductAvailabilityDigest(plan.ProductAvailability); err != nil {
		t.Fatalf("cascaded evidence is not digestible/valid: %v", err)
	}
}

func TestGlobalUnavailableProbeCascadesAcrossAccountPlans(t *testing.T) {
	when := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	otherAccountAvailability := []catalog.ProductModelAvailability{{
		ModelID: "gpt-5.4", Provider: "openai", Status: "available", MatchKind: "exact",
		SourceIDs: []string{"openai-chatgpt-models"}, SourceURLs: []string{"https://chatgpt.com/models"},
		ContentSHA256: []string{strings.Repeat("b", 64)}, RetrievedAt: when,
	}}
	decisions := []catalog.ModelProbeDecision{{
		Provider: "openai", ModelID: "gpt-5.5", Status: "unavailable",
		Accounts: []catalog.ModelProbeOutcome{{AccountID: 3, Outcome: "failed"}, {AccountID: 9, Outcome: "failed"}},
	}}
	changed, err := applyGlobalProbeVersionFloors(otherAccountAvailability, decisions, when)
	if err != nil || !changed {
		t.Fatalf("global higher-version failure did not propagate: changed=%t err=%v", changed, err)
	}
	got := otherAccountAvailability[0]
	if got.Status != "unavailable" || got.MatchKind != "lower_than_unavailable_version" || got.VersionFloorModelID != "gpt-5.5" {
		t.Fatalf("lower version on another account did not inherit global failure: %+v", got)
	}
	if _, err := catalog.ProductAvailabilityDigest(otherAccountAvailability); err != nil {
		t.Fatalf("globally cascaded evidence is not valid: %v", err)
	}
}

func TestOfficialPositiveScopePreventsProbeFailureFromBecomingGlobalFloor(t *testing.T) {
	when := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	plans := []catalog.Plan{
		{AccountID: 3, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "gpt-5.5", Provider: "openai", Status: "insufficient_evidence"}}, Before: map[string]string{"gpt-5.5": "gpt-5.5"}},
		{AccountID: 9, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "gpt-5.5", Provider: "openai", Status: "available", MatchKind: "exact", SourceIDs: []string{"openai-chatgpt-models"}, SourceURLs: []string{"https://chatgpt.com/models"}, ContentSHA256: []string{strings.Repeat("c", 64)}, RetrievedAt: when}}, Before: map[string]string{"gpt-5.5": "gpt-5.5"}},
	}
	rows := []report.DiscoveryAccount{
		{ID: 3, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "gpt-5.5"}}},
		{ID: 9, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "gpt-5.5"}}},
	}
	api := &workflowAPI{probeOutcomes: map[string]string{"gpt-5.5": "failed"}}
	decisions, err := resolveInsufficientEvidence(context.Background(), api, plans, rows, true)
	if err != nil || len(decisions) != 1 || decisions[0].Status != "ignored" {
		t.Fatalf("failed probes overrode a positive exact-ID account scope: decisions=%+v err=%v", decisions, err)
	}
	if _, err := catalog.ModelProbeDigest(decisions); err != nil {
		t.Fatalf("ignored mixed official/probe evidence was not digestible: %v", err)
	}
}

func TestResolveInsufficientEvidenceSeparatesProvidersWithSameModelID(t *testing.T) {
	plans := []catalog.Plan{
		{AccountID: 3, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "shared-id", Provider: "openai", Status: "insufficient_evidence"}}, Before: map[string]string{"a": "shared-id"}},
		{AccountID: 9, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "shared-id", Provider: "volcengine", Status: "insufficient_evidence"}}, Before: map[string]string{"b": "shared-id"}},
	}
	api := &workflowAPI{probeOutcomes: map[string]string{"shared-id": "failed"}}
	rows := []report.DiscoveryAccount{{ID: 3, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "shared-id"}}}, {ID: 9, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "shared-id"}}}}
	decisions, err := resolveInsufficientEvidence(context.Background(), api, plans, rows, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 2 || decisions[0].Provider == decisions[1].Provider {
		t.Fatalf("same model ID was not separated by provider: %#v", decisions)
	}
	for _, decision := range decisions {
		if len(decision.Accounts) != 1 || decision.Accounts[0].Outcome != "failed" || len(decision.ScopeAccounts) != 2 || decision.ScopeAccounts[0].Reason == decision.ScopeAccounts[1].Reason {
			t.Fatalf("provider decision crossed account scopes: %#v", decision)
		}
		matched := 0
		for i := range plans {
			err := applyModelProbeEvidence(&plans[i], decision, time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC))
			if plans[i].ProductAvailability[0].Provider == decision.Provider {
				if err != nil {
					t.Fatalf("matching provider evidence was not updated: %v", err)
				}
				matched++
			} else if err == nil {
				t.Fatal("probe evidence was attached to a different provider")
			}
		}
		if matched != 1 {
			t.Fatalf("provider decision updated %d plans", matched)
		}
	}
}

func TestResolveInsufficientEvidenceIgnoresIncompleteModelAndContinues(t *testing.T) {
	plans := []catalog.Plan{
		{AccountID: 3, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "codex-auto-review", Status: "insufficient_evidence", MatchKind: "none"}, {ModelID: "gpt-6-sol", Status: "insufficient_evidence", MatchKind: "none"}}, Before: map[string]string{"codex-auto-review": "codex-auto-review", "gpt-6-sol": "gpt-6-sol"}},
		{AccountID: 9, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "codex-auto-review", Status: "insufficient_evidence", MatchKind: "none"}}, Before: map[string]string{"codex-auto-review": "codex-auto-review"}},
	}
	api := &workflowAPI{probeErrs: map[string]error{"codex-auto-review": errors.New("probe endpoint unavailable")}}
	rows := []report.DiscoveryAccount{
		{ID: 3, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "codex-auto-review"}, {UpstreamID: "gpt-6-sol"}}},
		{ID: 9, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "codex-auto-review"}}},
	}
	decisions, err := resolveInsufficientEvidence(context.Background(), api, plans, rows, true)
	if err != nil {
		t.Fatalf("incomplete candidate stopped the screening run: %v", err)
	}
	if len(decisions) != 2 || decisions[0].ModelID != "codex-auto-review" || decisions[0].Status != "ignored" || decisions[1].ModelID != "gpt-6-sol" || decisions[1].Status != "available" {
		t.Fatalf("incomplete candidate was not isolated from later screening: %#v", decisions)
	}
	if len(api.calls) != 3 || api.calls[0] != "probe:3:codex-auto-review" || api.calls[1] != "probe:9:codex-auto-review" || api.calls[2] != "probe:3:gpt-6-sol" {
		t.Fatalf("unexpected probe sequence after incomplete results: %v", api.calls)
	}
	for i := range plans {
		if err := applyModelProbeEvidence(&plans[i], decisions[0], time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)); err != nil {
			t.Fatalf("ignored evidence was not attached to account %d: %v", plans[i].AccountID, err)
		}
		if plans[i].ProductAvailability[0].Status != "insufficient_evidence" || plans[i].ProductAvailability[0].MatchKind != "account_probe_ignored" {
			t.Fatalf("ignored candidate was treated as available or unavailable for account %d: %#v", plans[i].AccountID, plans[i].ProductAvailability[0])
		}
	}
}

func TestResolveInsufficientEvidenceSkipsIncompleteCandidateAndContinues(t *testing.T) {
	plans := []catalog.Plan{{AccountID: 3, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "grok-4.5", Status: "insufficient_evidence"}, {ModelID: "gpt-6-sol", Status: "insufficient_evidence"}}, Before: map[string]string{"grok-4.5": "grok-4.5", "gpt-6-sol": "gpt-6-sol"}}}
	rows := []report.DiscoveryAccount{{ID: 3, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "grok-4.5"}, {UpstreamID: "gpt-6-sol"}}}, {ID: 9, Status: "sync_failed", CurrentMappings: []report.Mapping{{UpstreamID: "grok-4.5"}}}}
	api := &workflowAPI{probeOutcomes: map[string]string{"gpt-6-sol": "succeeded"}}
	decisions, err := resolveInsufficientEvidence(context.Background(), api, plans, rows, true)
	if err != nil || len(decisions) != 1 || decisions[0].ModelID != "gpt-6-sol" || decisions[0].Status != "available" || len(api.calls) != 1 || api.calls[0] != "probe:3:gpt-6-sol" {
		t.Fatalf("incomplete candidate scope stopped or contaminated other screening: decisions=%#v err=%v calls=%v", decisions, err, api.calls)
	}
}

func TestResolveInsufficientEvidenceBlocksAllowlistBeforeProbes(t *testing.T) {
	plans := []catalog.Plan{{AccountID: 3, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "gpt-5.5", Status: "insufficient_evidence"}}, Before: map[string]string{"gpt-5.5": "gpt-5.5"}}}
	rows := []report.DiscoveryAccount{{ID: 3, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "gpt-5.5"}}}}
	api := &workflowAPI{}
	decisions, err := resolveInsufficientEvidence(context.Background(), api, plans, rows, false)
	if err != nil || len(decisions) != 0 || len(api.calls) != 0 {
		t.Fatalf("incomplete allowlist scope was probed or yielded a decision: decisions=%#v err=%v calls=%v", decisions, err, api.calls)
	}
}

func TestResolveInsufficientEvidenceIncompleteThenSuccessIsAvailable(t *testing.T) {
	plans := []catalog.Plan{
		{AccountID: 3, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "gpt-5.5", Status: "insufficient_evidence"}}, Before: map[string]string{"gpt-5.5": "gpt-5.5"}},
		{AccountID: 9, ProductAvailabilityEnforced: true, ProductAvailability: []catalog.ProductModelAvailability{{ModelID: "gpt-5.5", Status: "insufficient_evidence"}}, Before: map[string]string{"gpt-5.5": "gpt-5.5"}},
	}
	api := &workflowAPI{probeErrsByAccount: map[int64]error{3: errors.New("temporary transport failure")}, probeOutcomes: map[string]string{"gpt-5.5": "succeeded"}}
	rows := []report.DiscoveryAccount{{ID: 3, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "gpt-5.5"}}}, {ID: 9, Status: "candidate_reported", CurrentMappings: []report.Mapping{{UpstreamID: "gpt-5.5"}}}}
	decisions, err := resolveInsufficientEvidence(context.Background(), api, plans, rows, true)
	if err != nil {
		t.Fatalf("incomplete account probe stopped screening: %v", err)
	}
	if len(decisions) != 1 || decisions[0].Status != "available" || decisions[0].Accounts[0].Outcome != "incomplete" || decisions[0].Accounts[1].Outcome != "succeeded" {
		t.Fatalf("later successful account did not establish availability: %#v", decisions)
	}
}

func TestApplyRevalidatesExactModelAccountScopeWithoutReprobing(t *testing.T) {
	parentID := int64(3)
	api := &workflowAPI{accounts: map[int64]adminapi.Account{
		3:  {ID: 3, Status: "active", ModelMapping: map[string]string{"gpt-5.5": "gpt-5.5"}},
		9:  {ID: 9, Status: "active", ModelMapping: map[string]string{"alias": "gpt-5.5"}},
		11: {ID: 11, Status: "inactive", ModelMapping: map[string]string{"gpt-5.5": "gpt-5.5"}},
		12: {ID: 12, Status: "active", ParentAccountID: &parentID, ModelMapping: map[string]string{"gpt-5.5": "gpt-5.5"}},
	}}
	inventory := []adminapi.AccountSummary{{ID: 3}, {ID: 9}, {ID: 11}, {ID: 12}}
	decisions := []catalog.ModelProbeDecision{{ModelID: "gpt-5.5", Status: "unavailable", ScopeAccounts: []catalog.ModelProbeScopeAccount{{AccountID: 3, Reason: "probe"}, {AccountID: 9, Reason: "probe"}}, Accounts: []catalog.ModelProbeOutcome{{AccountID: 3, Outcome: "failed"}, {AccountID: 9, Outcome: "failed"}}}}
	if err := verifyModelProbeScope(context.Background(), api, inventory, decisions); err != nil {
		t.Fatalf("unchanged active/non-shadow scope was rejected: %v", err)
	}
	changed := api.accounts[11]
	changed.Status = "active"
	api.accounts[11] = changed
	if err := verifyModelProbeScope(context.Background(), api, inventory, decisions); err == nil {
		t.Fatal("newly active mapped account was omitted from the approved probe scope")
	}
	changed.Status = "inactive"
	api.accounts[11] = changed
	api.accounts[13] = adminapi.Account{ID: 13, Status: "active"}
	inventory = append(inventory, adminapi.AccountSummary{ID: 13})
	if err := verifyModelProbeScope(context.Background(), api, inventory, decisions); err == nil {
		t.Fatal("active account with an omitted model_mapping field was accepted as an empty mapping")
	}
}

type workflowAPI struct {
	status                   adminapi.RefreshStatus
	statusErr                error
	accounts                 map[int64]adminapi.Account
	inventoryIDs             []int64
	catalogs                 map[int64]adminapi.Catalog
	probeOutcomes            map[string]string
	probeErrs                map[string]error
	probeErrsByAccount       map[int64]error
	calls                    []string
	syncCalls                int
	bulkCalls                []int64
	bulkMappings             []map[string]string
	bulkErr                  error
	applyBeforeError         bool
	ignoreBulkWrite          bool
	unexpectedBulkResult     bool
	afterBulk                func(int64, *workflowAPI)
	flipAPIKeyPresenceOnBulk bool
}

func cloneWorkflowMapping(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func timePtr(v time.Time) *time.Time { return &v }

func hasCall(calls []string, want string) bool { return countCall(calls, want) > 0 }

func countCall(calls []string, want string) int {
	n := 0
	for _, call := range calls {
		if call == want {
			n++
		}
	}
	return n
}

func TestModelIDBelongsToProductScope(t *testing.T) {
	tests := []struct {
		scope, modelID string
		want           bool
	}{
		{"openai_codex_chatgpt_login", "gpt-5.2", true},
		{"openai_codex_chatgpt_login", "deepseek-flash", false},
		{"anthropic_claude_code_login", "claude-opus-4-5", true},
		{"anthropic_claude_code_login", "gpt-5.2", false},
		{"kimi_code_login", "k3-256k", true},
		{"kimi_code_login", "kimi-for-coding", true},
		{"kimi_code_login", "glm-5.3", false},
	}
	for _, test := range tests {
		if got := modelIDBelongsToProductScope(test.scope, test.modelID); got != test.want {
			t.Errorf("modelIDBelongsToProductScope(%q, %q)=%t want %t", test.scope, test.modelID, got, test.want)
		}
	}
}
