package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"sub2api-model-catalog-manager/internal/adminapi"
	"sub2api-model-catalog-manager/internal/app"
	"sub2api-model-catalog-manager/internal/catalog"
	"sub2api-model-catalog-manager/internal/config"
	"sub2api-model-catalog-manager/internal/inventorysummary"
	"sub2api-model-catalog-manager/internal/mergereview"
	"sub2api-model-catalog-manager/internal/officialcatalog"
	"sub2api-model-catalog-manager/internal/securecred"
	"sub2api-model-catalog-manager/internal/state"
)

func TestPlanLoaderBindsRawHashAndRejectsUnknownSecretFields(t *testing.T) {
	dir := t.TempDir()
	plan := validApprovalPlan()
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, digest, err := loadPlan(path)
	if err != nil || loaded.Accounts[0].AccountID != 9001 || digest == "" {
		t.Fatalf("valid plan rejected: %#v %q %v", loaded, digest, err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSuffix(string(data), "}")+`,"provider_api_key":"TOP-SECRET"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPlan(path); err == nil {
		t.Fatal("plan with an unknown credential-like field was accepted")
	}
}

func TestOfficialReviewCommandIsReadOnlyAndUsesWhitelistInput(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "inspect.json")
	outputDir := filepath.Join(dir, "reviews")
	const sentinel = "OFFICIAL-REVIEW-SECRET-SENTINEL"
	input := `{"mode":"inspect","accounts":[{"account_id":9001,"platform":"openai","account_type":"apikey","api_protocol":"openai","source_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","base_url":"https://user:` + sentinel + `@example.invalid/v1?token=` + sentinel + `#` + sentinel + `","admin_key":"` + sentinel + `","mappings":[{"public_id":"public-model","upstream_id":"upstream-model","headers":"` + sentinel + `"}]}]}`
	if err := os.WriteFile(inputPath, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	doer := &mainNeverDoer{}
	envCalls, clientCalls, syncCalls := 0, 0, 0
	base := officialcatalog.StartupSyncOptions{
		CacheDir:  filepath.Join(dir, "cache"),
		LookupEnv: func(string) (string, bool) { envCalls++; return "unexpected", true },
		NewDoer:   func() officialcatalog.HTTPDoer { clientCalls++; return doer },
		Now:       time.Now,
		Offline:   true,
	}
	syncer := func(options officialcatalog.StartupSyncOptions) officialcatalog.StartupSyncResult {
		syncCalls++
		return officialcatalog.SyncStartup(context.Background(), options)
	}
	err := runWithStartup([]string{"official-review", "--offline-official-lifecycle", "--input", inputPath, "--out-dir", outputDir}, base, syncer)
	if err != nil {
		t.Fatal(err)
	}
	if len(doer.requests) != 0 || syncCalls != 1 || clientCalls != 0 {
		t.Fatalf("offline official-review must reuse one startup result: requests=%d sync=%d clients=%d", len(doer.requests), syncCalls, clientCalls)
	}
	if envCalls != 0 {
		t.Fatal("official lifecycle sync must not inspect the environment")
	}
	files, err := filepath.Glob(filepath.Join(outputDir, "official-review-*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("official-review output was not written once: %v %v", files, err)
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), sentinel) || strings.Contains(string(body), "example.invalid") || strings.Contains(string(body), "token=") || strings.Contains(string(body), "user:") {
		t.Fatalf("official-review report contains unapproved input fields: %s", body)
	}
	validEnvCalls := envCalls
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	// Go's chmod does not set a Windows DACL; Windows deployments must keep the
	// output directory ACL private. On POSIX, verify owner-only output mode.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("report permissions are broader than owner-only: %v", info.Mode().Perm())
	}
	if err := runWithStartup([]string{"official-review", "--input", inputPath, "--out-dir", outputDir, "--base-url", "https://attacker.invalid"}, base, syncer); err == nil {
		t.Fatal("official-review accepted a caller-supplied endpoint")
	}
	if syncCalls != 1 || envCalls != validEnvCalls {
		t.Fatal("invalid official-review flag crossed the preflight boundary")
	}
}

func TestInventorySummaryCommandReadsOnlyPairedLocalReports(t *testing.T) {
	dir := t.TempDir()
	inspectPath := filepath.Join(dir, "inspect.json")
	discoverPath := filepath.Join(dir, "discover.json")
	outDir := filepath.Join(dir, "summary")
	hash, err := catalog.AccountIDsDigest([]int64{9001, 9002})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("a", 64)
	inspect := `{"mode":"inspect","created_at":"2026-10-12T11:00:00Z","account_scope":"all","account_scan_status":"complete","account_inventory_count":2,"account_inventory_sha256":"` + hash + `","target_build_fingerprint":"build-test","accounts":[{"account_id":9001,"platform":"openai","account_type":"apikey","api_protocol":"openai","source_fingerprint":"` + fingerprint + `","base_url":"https://SECRET-SENTINEL.invalid/v1?token=SECRET-SENTINEL","mappings":[{"public_id":"gpt","upstream_id":"gpt-a"}]},{"account_id":9002,"platform":"anthropic","account_type":"apikey","api_protocol":"anthropic","source_fingerprint":"` + strings.Repeat("b", 64) + `","mappings":[{"public_id":"gpt","upstream_id":"gpt-b"}]}]}`
	discover := `{"mode":"discover","created_at":"2026-10-12T11:05:00Z","account_scope":"all","account_scan_status":"complete","account_inventory_count":2,"account_inventory_sha256":"` + hash + `","target_build_fingerprint":"build-test","discovery":[{"account_id":9001,"source_fingerprint":"` + fingerprint + `","status":"candidate_reported","live_list_available":true,"models":["shared","only-9001"]},{"account_id":9002,"source_fingerprint":"` + strings.Repeat("b", 64) + `","status":"candidate_reported","live_list_available":true,"models":["shared"]}]}`
	if err := os.WriteFile(inspectPath, []byte(inspect), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(discoverPath, []byte(discover), 0600); err != nil {
		t.Fatal(err)
	}
	startupCalls := 0
	if err := runInventorySummaryWithStartup([]string{"--inspect", inspectPath, "--discover", discoverPath, "--out-dir", outDir}, func() officialcatalog.StartupSyncResult {
		startupCalls++
		return officialcatalog.StartupSyncResult{}
	}); err != nil {
		t.Fatal(err)
	}
	if startupCalls != 1 {
		t.Fatalf("inventory-summary startup passes=%d, want 1", startupCalls)
	}
	files, err := filepath.Glob(filepath.Join(outDir, "inventory-summary-*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("summary report was not written once: %v %v", files, err)
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "SECRET-SENTINEL") || strings.Contains(string(body), "base_url") || strings.Contains(string(body), "secret.invalid") {
		t.Fatal("summary report contains unapproved input data")
	}
	var report inventorysummary.Report
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Counts.Accounts != 2 || len(report.PublicIDRoutes) != 1 || len(report.DiscoveredIDReuse) != 1 || report.CatalogCoverage != "all_accounts_returned_live_lists" {
		t.Fatalf("unexpected summary result: %#v", report)
	}
}

func TestInventorySummaryRejectsPartialInputBeforePublishing(t *testing.T) {
	dir := t.TempDir()
	inspectPath := filepath.Join(dir, "inspect.json")
	discoverPath := filepath.Join(dir, "discover.json")
	outDir := filepath.Join(dir, "summary")
	hash, _ := catalog.AccountIDsDigest([]int64{9001})
	inspect := `{"mode":"inspect","created_at":"2026-10-12T11:00:00Z","account_scope":"all","account_scan_status":"partial","account_inventory_count":1,"account_inventory_sha256":"` + hash + `","target_build_fingerprint":"build-test","accounts":[{"account_id":9001,"platform":"openai","account_type":"apikey","source_fingerprint":"` + strings.Repeat("a", 64) + `","mappings":[]}]}`
	discover := `{"mode":"discover","created_at":"2026-10-12T11:05:00Z","account_scope":"all","account_scan_status":"complete","account_inventory_count":1,"account_inventory_sha256":"` + hash + `","target_build_fingerprint":"build-test","discovery":[{"account_id":9001,"source_fingerprint":"` + strings.Repeat("a", 64) + `","status":"skipped","live_list_available":false,"models":[]}]}`
	if err := os.WriteFile(inspectPath, []byte(inspect), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(discoverPath, []byte(discover), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runInventorySummary([]string{"--inspect", inspectPath, "--discover", discoverPath, "--out-dir", outDir}); err == nil {
		t.Fatal("partial all-account inspect was accepted")
	}
	files, err := filepath.Glob(filepath.Join(outDir, "inventory-summary-*.json"))
	if err != nil || len(files) != 0 {
		t.Fatalf("partial input left a summary report: %v %v", files, err)
	}
}

func TestMergeReviewCommandUsesOnlyLocalFilesAndWritesCandidateReport(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	rulesPath := filepath.Join(dir, "rules.json")
	inspectPath := filepath.Join(dir, "inspect.json")
	discoverPath := filepath.Join(dir, "discover.json")
	outDir := filepath.Join(dir, "merge-review")
	source, err := catalog.SourceForAccount("openai", "apikey", "openai", "https://provider.example/v1", 9001)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := catalog.SourceFingerprint(source)
	idsHash, _ := catalog.AccountIDsDigest([]int64{9001})
	mapping := map[string]string{"model": "model"}
	mappingHash, _ := catalog.MappingHash(mapping)
	configBody, err := json.Marshal(map[string]any{
		"target":        map[string]any{"base_url": "https://404token.xyz", "runtime_compatibility": map[string]any{"build_id": "build-test", "api_contract_id": "admin-catalog-all-v1", "evidence": "local-test", "reviewed_at": "2026-10-12"}},
		"account_scope": "all", "accept_all_credential_response_memory_exposure": true, "accounts": []any{},
		"allow_native_sync_metadata_write": false, "apply_mode": "preview",
		"credential": map[string]any{"windows_credential_target": "unused-test-credential"},
		"state_dir":  filepath.Join(dir, "state"), "report_dir": filepath.Join(dir, "reports"),
		"backup_dir": filepath.Join(dir, "backups"), "rules_file": rulesPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	rulesBody := `{"schema_version":1,"aliases":[],"version_families":[],"retired_models":[],"source_profiles":[],"complete_catalog_profiles":[]}`
	if err := os.WriteFile(configPath, configBody, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulesPath, []byte(rulesBody), 0600); err != nil {
		t.Fatal(err)
	}
	const sentinel = "MERGE-REVIEW-CLI-SECRET-SENTINEL"
	inspect := `{"run_id":"inspect-test","created_at":"2026-10-12T11:00:00Z","mode":"inspect","account_scope":"all","account_scan_status":"complete","account_inventory_count":1,"account_inventory_sha256":"` + idsHash + `","target_build_fingerprint":"build-test","accounts":[{"account_id":9001,"platform":"openai","account_type":"apikey","api_protocol":"openai","base_url":"https://provider.example/v1","source_fingerprint":"` + fingerprint + `","mapping_sha256":"` + mappingHash + `","mapping_status":"explicit_nonempty","credential_shadow":false,"mappings":[{"public_id":"model","upstream_id":"model"}],"credentials":{"api_key":"` + sentinel + `"},"headers":{"authorization":"` + sentinel + `"}}]}`
	discover := `{"run_id":"discover-test","created_at":"2026-10-12T11:01:00Z","mode":"discover","account_scope":"all","account_scan_status":"complete","account_inventory_count":1,"account_inventory_sha256":"` + idsHash + `","target_build_fingerprint":"build-test","discovery":[{"account_id":9001,"source_fingerprint":"` + fingerprint + `","status":"candidate_reported","live_list_available":true,"models":["model","model-20261012"],"product_availability":[{"model_id":"model","provider":"openai","status":"available","match_kind":"exact"},{"model_id":"model-20261012","provider":"openai","status":"available","match_kind":"exact"}]}]}`
	for path, body := range map[string]string{inspectPath: inspect, discoverPath: discover} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	startupCalls := 0
	if err := runMergeReviewWithStartup([]string{"--config", configPath, "--inspect", inspectPath, "--discover", discoverPath, "--out-dir", outDir}, func() officialcatalog.StartupSyncResult {
		startupCalls++
		return officialcatalog.StartupSyncResult{}
	}); err != nil {
		t.Fatal(err)
	}
	if startupCalls != 1 {
		t.Fatalf("merge-review startup passes=%d, want 1", startupCalls)
	}
	files, err := filepath.Glob(filepath.Join(outDir, "merge-review-*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("merge-review output was not written once: %v %v", files, err)
	}
	body, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), sentinel) || strings.Contains(string(body), "base_url") || strings.Contains(string(body), "provider.example") {
		t.Fatal("merge-review output contains credentials or source URL")
	}
	var value mergereview.Report
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	if value.Summary.DateFamilyCandidates != 1 || value.Summary.CandidatesWithNoRule != 1 || value.Accounts[0].DateFamilies[0].Action != "none" {
		t.Fatalf("unexpected candidate-only output: %#v", value)
	}
	if _, err := os.Stat(filepath.Join(dir, "state", "state.json")); !os.IsNotExist(err) {
		t.Fatalf("read-only merge-review changed state: %v", err)
	}
	statePath := filepath.Join(dir, "state", "state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte(`{"version":1`), 0600); err != nil {
		t.Fatal(err)
	}
	blockedOutDir := filepath.Join(dir, "blocked-merge-review")
	if err := runMergeReview([]string{"--config", configPath, "--inspect", inspectPath, "--discover", discoverPath, "--out-dir", blockedOutDir}); err == nil {
		t.Fatal("merge-review accepted corrupt state")
	}
	blockedFiles, err := filepath.Glob(filepath.Join(blockedOutDir, "merge-review-*.json"))
	if err != nil || len(blockedFiles) != 0 {
		t.Fatalf("corrupt state left a merge-review report: %v %v", blockedFiles, err)
	}
}

type mainNeverDoer struct{ requests []*http.Request }

func (d *mainNeverDoer) Do(request *http.Request) (*http.Response, error) {
	d.requests = append(d.requests, request)
	return nil, errors.New("network access was not expected")
}

func TestPlanLoaderRejectsOversizeAndTrailingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1} {}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPlan(path); err == nil {
		t.Fatal("trailing JSON value was accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", maxPlanBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPlan(path); err == nil {
		t.Fatal("oversized plan was accepted")
	}
}

func TestPlanLoaderRejectsExpiredApproval(t *testing.T) {
	plan := validApprovalPlan()
	plan.CreatedAt = time.Now().UTC().Add(-time.Hour)
	plan.ExpiresAt = plan.CreatedAt.Add(-time.Second)
	body, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "expired-plan.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPlan(path); err == nil {
		t.Fatal("expired plan was accepted")
	}
}

func TestCLIStartupGlobalOfflineFlagAndLocalPreflightOrder(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "inspect.json")
	input := `{"mode":"inspect","accounts":[{"account_id":9001,"platform":"openai","account_type":"apikey","api_protocol":"openai","source_fingerprint":"` + strings.Repeat("a", 64) + `","mappings":[{"public_id":"gpt","upstream_id":"gpt"}]}]}`
	if err := os.WriteFile(inputPath, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	blockedOutput := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blockedOutput, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	envCalls, clientCalls, syncCalls := 0, 0, 0
	base := officialcatalog.StartupSyncOptions{
		LookupEnv: func(string) (string, bool) { envCalls++; return "", false },
		NewDoer:   func() officialcatalog.HTTPDoer { clientCalls++; return &mainNeverDoer{} },
	}
	var seenOffline bool
	syncer := func(options officialcatalog.StartupSyncOptions) officialcatalog.StartupSyncResult {
		syncCalls++
		seenOffline = options.Offline
		return officialcatalog.StartupSyncResult{}
	}
	for _, args := range [][]string{
		{"--offline-official-lifecycle", "official-review", "--input", inputPath, "--out-dir", filepath.Join(dir, "review-before")},
		{"official-review", "--offline-official-lifecycle", "--input", inputPath, "--out-dir", filepath.Join(dir, "review-after")},
	} {
		if err := runWithStartup(args, base, syncer); err != nil {
			t.Fatalf("valid offline official-review failed: %v", err)
		}
	}
	if syncCalls != 2 || !seenOffline {
		t.Fatalf("startup pass count/options mismatch: calls=%d offline=%v", syncCalls, seenOffline)
	}
	if envCalls != 0 || clientCalls != 0 {
		t.Fatalf("injected startup sync unexpectedly touched environment/client: env=%d client=%d", envCalls, clientCalls)
	}

	for _, args := range [][]string{
		{"--help"}, {"official-review", "--help"}, {"unknown"},
		{"official-review", "--offline-official-lifecycle", "--offline-official-lifecycle"},
		{"official-review", "--offline-official-lifecycle=true"},
		{"official-review", "--input", inputPath, "--offline-official-lifecycle"},
		{"official-review", "--input", filepath.Join(dir, "missing.json"), "--out-dir", filepath.Join(dir, "missing")},
		{"official-review", "--input", inputPath, "--out-dir", blockedOutput},
	} {
		if err := runWithStartup(args, base, syncer); err == nil && args[0] != "--help" && !(len(args) > 1 && args[1] == "--help") {
			t.Fatalf("invalid command unexpectedly succeeded: %v", args)
		}
	}
	if syncCalls != 2 || envCalls != 0 || clientCalls != 0 {
		t.Fatalf("invalid/help command crossed the public-source boundary: sync=%d env=%d client=%d", syncCalls, envCalls, clientCalls)
	}
}

func TestManualApplyRawPlanHashMismatchStopsBeforeCredentialRead(t *testing.T) {
	configPath, _, _ := automaticFixture(t, strings.Repeat("0", 64))
	plan := validApprovalPlan()
	planBytes, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planPath, planBytes, 0600); err != nil {
		t.Fatal(err)
	}
	err = runApply([]string{"--config", configPath, "--plan", planPath, "--confirm-plan-sha256", strings.Repeat("0", 64)})
	if err == nil || !strings.Contains(err.Error(), "does not match the plan file raw bytes") {
		t.Fatalf("raw plan hash mismatch was not rejected before apply: %v", err)
	}
}

func TestValidOperationalCommandHelpersRunOneStartupPass(t *testing.T) {
	makeStartup := func(counter *int) startupPass {
		return func() officialcatalog.StartupSyncResult {
			*counter++
			return officialcatalog.StartupSyncResult{}
		}
	}
	makeAPI := func(t *testing.T) (string, *mainWorkflowAPI) {
		t.Helper()
		configPath, api, _ := automaticFixture(t, "")
		return configPath, api
	}

	t.Run("inspect", func(t *testing.T) {
		configPath, api := makeAPI(t)
		calls := 0
		err := runInspectPreparedWithStartup([]string{"--config", configPath}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil }, makeStartup(&calls))
		if err != nil || calls != 1 {
			t.Fatalf("inspect err=%v startup=%d", err, calls)
		}
	})
	t.Run("adopt", func(t *testing.T) {
		configPath, api := makeAPI(t)
		cfg, err := config.Load(configPath)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		keysPath := filepath.Join(dir, "keys.json")
		if err := os.WriteFile(keysPath, []byte(`["manual"]`), 0600); err != nil {
			t.Fatal(err)
		}
		mappingHash, _ := catalog.MappingFingerprint(api.account.ModelMapping)
		calls := 0
		args := []string{"--config", configPath, "--account-id", "9001", "--keys-file", keysPath, "--expected-mapping-hash", mappingHash}
		err = runAdoptPreparedWithStartup(args, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil }, makeStartup(&calls))
		if err != nil || calls != 1 {
			t.Fatalf("adopt err=%v startup=%d", err, calls)
		}
		if _, err := state.Load(filepath.Join(cfg.StateDir, "state.json")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("discover", func(t *testing.T) {
		configPath, api := makeAPI(t)
		calls := 0
		err := runDiscoverPreparedWithStartup([]string{"--config", configPath}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil }, makeStartup(&calls))
		if err != nil || calls != 1 {
			t.Fatalf("discover err=%v startup=%d", err, calls)
		}
	})
	t.Run("run", func(t *testing.T) {
		configPath, api := makeAPI(t)
		calls := 0
		err := runAutomaticPreparedWithStartup([]string{"--config", configPath}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil }, makeStartup(&calls))
		if err != nil || calls != 1 {
			t.Fatalf("run err=%v startup=%d", err, calls)
		}
	})
	t.Run("apply", func(t *testing.T) {
		configPath, api := makeAPI(t)
		cfg, err := config.Load(configPath)
		if err != nil {
			t.Fatal(err)
		}
		discoverer := app.Discoverer{ReadCredential: mockCredentialReader, NewClient: func(string) (app.AdminAPI, error) { return api, nil }}
		preflight, err := discoverer.Preflight(cfg)
		if err != nil {
			t.Fatal(err)
		}
		result, err := discoverer.DiscoverPrepared(context.Background(), cfg, preflight)
		if err != nil || result.Plan == nil {
			t.Fatalf("test plan setup failed: plan=%v err=%v", result.Plan != nil, err)
		}
		planPath := filepath.Join(t.TempDir(), "plan.json")
		body, err := json.MarshalIndent(result.Plan, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(planPath, body, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		planHash := hex.EncodeToString(digest[:])
		calls := 0
		args := []string{"--config", configPath, "--plan", planPath, "--confirm-plan-sha256", planHash}
		err = runApplyPreparedWithStartup(args, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil }, makeStartup(&calls))
		if err != nil || calls != 1 {
			t.Fatalf("apply err=%v startup=%d", err, calls)
		}
	})
}

func TestDiscoverAndRunFailClosedWithoutRulesOrSideEffectApproval(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	configBody := `{"target":{"base_url":"https://404token.xyz","runtime_compatibility":{"build_id":"verified-image","api_contract_id":"admin-catalog-v1","evidence":"target-verification","reviewed_at":"2026-10-11"}},"accounts":[{"id":9001,"accept_credential_response_memory_exposure":true}],"allow_native_sync_metadata_write":false,"apply_mode":"approved_rules","approved_rules_sha256":"` + strings.Repeat("a", 64) + `","credential":{"windows_credential_target":"test"},"state_dir":"state","report_dir":"reports","backup_dir":"backups","rules_file":"rules.json"}`
	if err := os.WriteFile(configPath, []byte(configBody), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runDiscover([]string{"--config", configPath}); err == nil || !strings.Contains(err.Error(), "native sync metadata side effect is disabled") {
		t.Fatalf("discovery did not fail closed: %v", err)
	}
	if err := runAutomatic([]string{"--config", configPath}); err == nil || !strings.Contains(err.Error(), "native sync metadata side effect is disabled") {
		t.Fatalf("automatic run did not fail closed: %v", err)
	}
}

func TestManualDiscoverRequiresAllAccountPreview(t *testing.T) {
	configPath, _, _ := automaticFixture(t, "")
	credentialCalls, clientCalls := 0, 0
	err := runDiscoverWith([]string{"--config", configPath, "--manual-sync-authorized"}, func(config.CredentialConfig) (securecred.Value, error) {
		credentialCalls++
		return securecred.Value{APIKey: []byte("test-admin-key")}, nil
	}, func(string) (app.AdminAPI, error) {
		clientCalls++
		return nil, errors.New("client should not be created")
	})
	if err == nil || !strings.Contains(err.Error(), "requires account_scope=all and apply_mode=preview") || credentialCalls != 0 || clientCalls != 0 {
		t.Fatalf("manual discover did not reject allowlist scope before credential/API access: err=%v credentials=%d clients=%d", err, credentialCalls, clientCalls)
	}
}

func TestAutomaticRunRulesHashMismatchPreviewsWithoutWrite(t *testing.T) {
	configPath, api, rawRulesHash := automaticFixture(t, strings.Repeat("0", 64))
	if err := runAutomaticWith([]string{"--config", configPath}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil }); err != nil {
		t.Fatal(err)
	}
	if api.bulkCalls != 0 || api.syncCalls != 1 {
		t.Fatalf("hash mismatch did not preview only: bulk=%d sync=%d current_rules_sha=%s", api.bulkCalls, api.syncCalls, rawRulesHash)
	}
}

func TestAutomaticRunMatchingRawRulesHashAppliesOnlyReviewedDelta(t *testing.T) {
	configPath, api, rawRulesHash := automaticFixture(t, "")
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ApplyMode = "approved_rules"
	cfg.ApprovedRulesSHA256 = rawRulesHash
	configBytes, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runAutomaticWith([]string{"--config", configPath}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil }); err != nil {
		t.Fatal(err)
	}
	if api.bulkCalls != 1 || api.lastBulkID != 9001 || api.lastMapping["canonical-name"] != "upstream-known" || api.lastMapping["manual"] != "keep" {
		t.Fatalf("approved run did not apply exactly the reviewed mapping: bulk=%d id=%d mapping=%v", api.bulkCalls, api.lastBulkID, api.lastMapping)
	}
}

func TestFullScreenRunAppliesApprovedRuleWithStructuredTerminalResult(t *testing.T) {
	configPath, api := fullScreenFixture(t, false)
	api.status.RunStatus = "partial_failure"
	stdout, err := captureStdout(t, func() error {
		return runAutomaticWith([]string{"--config", configPath, "--full-screen"}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil })
	})
	if err != nil {
		t.Fatal(err)
	}
	if api.syncCalls != 1 || api.bulkCalls != 1 || api.statusCalls != 2 || api.lastBulkID != 9001 || api.lastMapping["canonical-name"] != "upstream-known" {
		t.Fatalf("full-screen did not sync/apply under its own catalog pass: sync=%d bulk=%d status=%d id=%d mapping=%v", api.syncCalls, api.bulkCalls, api.statusCalls, api.lastBulkID, api.lastMapping)
	}
	var terminal fullScreenResult
	if !strings.HasSuffix(stdout, "\n") || strings.Count(strings.TrimSuffix(stdout, "\n"), "\n") != 0 || json.Unmarshal([]byte(stdout), &terminal) != nil || terminal.Status != "succeeded" || terminal.ReasonCode != "completed" || terminal.PlannedCount != 1 || terminal.AppliedCount != 1 || terminal.NoopCount != 0 || terminal.FailedCount != 0 || terminal.NotAttemptedCount != 0 || !screenSummaryBasenamePattern.MatchString(terminal.SummaryBasename) {
		t.Fatalf("full-screen stdout did not contain exactly one valid terminal result: %q decoded=%#v", stdout, terminal)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	summaries, err := filepath.Glob(filepath.Join(cfg.ReportDir, "screen-summary-*.md"))
	if err != nil || len(summaries) != 1 {
		t.Fatalf("successful full-screen run did not write one summary: files=%v err=%v", summaries, err)
	}
	summaryBytes, err := os.ReadFile(summaries[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(summaryBytes), "已应用") || !strings.Contains(string(summaryBytes), "`canonical-name` → `upstream-known`") || !strings.Contains(string(summaryBytes), "write_readback_verified") {
		t.Fatalf("successful full-screen summary is missing verified resulting mapping:\n%s", string(summaryBytes))
	}
}

func TestRequestsFullScreenFollowsGoBooleanFlagSemantics(t *testing.T) {
	for _, tc := range []struct {
		arg  string
		want bool
	}{
		{arg: "--full-screen", want: true},
		{arg: "-full-screen", want: true},
		{arg: "--full-screen=true", want: true},
		{arg: "-full-screen=1", want: true},
		{arg: "--full-screen=T", want: true},
		{arg: "--full-screen=TRUE", want: true},
		{arg: "--full-screen=false", want: false},
		{arg: "-full-screen=0", want: false},
		{arg: "--full-screen=not-a-bool", want: false},
		{arg: "--", want: false},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			if got := requestsFullScreen([]string{tc.arg}); got != tc.want {
				t.Fatalf("requestsFullScreen(%q)=%t, want %t", tc.arg, got, tc.want)
			}
		})
	}
	if requestsFullScreen([]string{"--", "--full-screen"}) {
		t.Fatal("full-screen flag after -- must be treated as positional input")
	}
	if !requestsFullScreen([]string{"--full-screen=false", "--full-screen"}) {
		t.Fatal("last full-screen=true flag should win after false")
	}
	if requestsFullScreen([]string{"--full-screen", "--full-screen=false"}) {
		t.Fatal("last full-screen=false flag should win after true")
	}
	if enabled, invalid := fullScreenFlagState([]string{"--full-screen=TRUE"}); !enabled || invalid {
		t.Fatal("Go bool alias TRUE should enable full-screen without a parse error")
	}
	if _, invalid := fullScreenFlagState([]string{"--full-screen=bad"}); !invalid {
		t.Fatal("invalid bool value must be distinguished from an ordinary false flag")
	}
}

func TestFullScreenFalseKeepsOrdinaryOutputAndRefreshBehavior(t *testing.T) {
	configPath, api, _ := automaticFixture(t, "")
	stdout, err := captureStdout(t, func() error {
		return runAutomaticWith([]string{"--config", configPath, "--full-screen=true", "--full-screen=false"}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil })
	})
	if err != nil {
		t.Fatalf("ordinary run with --full-screen=false failed: %v", err)
	}
	if stdout == "" || strings.HasPrefix(strings.TrimSpace(stdout), "{") || strings.Contains(stdout, `"schema_version"`) || !strings.Contains(stdout, "run complete: manual_only=false full_screen=false") {
		t.Fatalf("--full-screen=false did not retain ordinary CLI output: %q", stdout)
	}
	if api.statusCalls != 1 || api.syncCalls != 1 || api.bulkCalls != 1 {
		t.Fatalf("ordinary refresh/discovery behavior changed: status=%d sync=%d writes=%d", api.statusCalls, api.syncCalls, api.bulkCalls)
	}
}

func TestInvalidFullScreenBooleanEmitsConfigurationInvalidWithoutRunning(t *testing.T) {
	configPath, api := fullScreenFixture(t, false)
	stdout, err := captureStdout(t, func() error {
		return runAutomaticWith([]string{"--config", configPath, "--full-screen=invalid"}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil })
	})
	if err == nil {
		t.Fatal("invalid boolean flag unexpectedly ran successfully")
	}
	var terminal fullScreenResult
	if json.Unmarshal([]byte(stdout), &terminal) != nil || terminal.Status != "failed" || terminal.ReasonCode != "configuration_invalid" || api.statusCalls != 0 || api.syncCalls != 0 || api.bulkCalls != 0 {
		t.Fatalf("invalid full-screen bool did not fail structurally before external work: stdout=%q terminal=%#v status=%d sync=%d writes=%d", stdout, terminal, api.statusCalls, api.syncCalls, api.bulkCalls)
	}
}

func TestFullScreenRulesHashDriftAfterDiscoveryBlocksApplyAndWritesBlockedSummary(t *testing.T) {
	configPath, api := fullScreenFixture(t, false)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	api.afterSync = func() {
		body, readErr := os.ReadFile(cfg.RulesFile)
		if readErr != nil {
			t.Errorf("read mock rules for drift: %v", readErr)
			return
		}
		if writeErr := os.WriteFile(cfg.RulesFile, append(body, '\n'), 0600); writeErr != nil {
			t.Errorf("change mock rules after discovery started: %v", writeErr)
		}
	}
	stdout, err := captureStdout(t, func() error {
		return runAutomaticPreparedWithStartup([]string{"--config", configPath, "--full-screen"}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil }, nil)
	})
	if err == nil {
		t.Fatal("blocked full-screen run returned a successful exit status")
	}
	if api.syncCalls != 1 || api.bulkCalls != 0 {
		t.Fatalf("rules drift after discovery did not fail closed: sync=%d bulk=%d", api.syncCalls, api.bulkCalls)
	}
	summaries, err := filepath.Glob(filepath.Join(cfg.ReportDir, "screen-summary-*.md"))
	if err != nil || len(summaries) != 1 {
		t.Fatalf("rules drift did not write a status summary: files=%v err=%v", summaries, err)
	}
	summaryBytes, err := os.ReadFile(summaries[0])
	if err != nil {
		t.Fatal(err)
	}
	summary := string(summaryBytes)
	if !strings.Contains(summary, "BLOCKED AFTER DISCOVERY / 未应用映射") || !strings.Contains(summary, "`manual` → `keep`") || strings.Contains(summary, "PREVIEW ONLY") {
		t.Fatalf("rules drift summary did not distinguish current mapping from explicit preview:\n%s", summary)
	}
	var terminal fullScreenResult
	if json.Unmarshal([]byte(stdout), &terminal) != nil || terminal.Status != "blocked" || terminal.ReasonCode != "approved_rules_blocked" || terminal.PlannedCount != 1 || terminal.NotAttemptedCount != 1 || terminal.AppliedCount != 0 || terminal.FailedCount != 0 {
		t.Fatalf("blocked full-screen result is inconsistent: stdout=%q terminal=%#v", stdout, terminal)
	}
}

func TestFullScreenApplyErrorIncludesVerifiedIDsAndArtifactPaths(t *testing.T) {
	err := fullScreenApplyError(app.ApplyResult{AppliedIDs: []int64{9003, 9001}, NoopIDs: []int64{9002}, Consumed: true}, "reports/discover.json", "reports/plan.json", errors.New("mock apply failure"))
	if err == nil {
		t.Fatal("apply error formatter returned nil")
	}
	for _, want := range []string{"applied_ids=[9001 9003]", "no_op_ids=[9002]", "reports/discover.json", "reports/plan.json", "partially succeeded", "do not blindly rerun"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("apply error omitted %q: %v", want, err)
		}
	}
}

func TestFullScreenApplyFailureDoesNotWriteSuccessSummary(t *testing.T) {
	configPath, api := fullScreenFixture(t, false)
	api.bulkErr = adminapi.ErrUnexpectedBulkResult
	stdout, err := captureStdout(t, func() error {
		return runAutomaticWith([]string{"--config", configPath, "--full-screen"}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil })
	})
	if err == nil {
		t.Fatal("full-screen apply failure was reported as success")
	}
	var terminal fullScreenResult
	if json.Unmarshal([]byte(stdout), &terminal) != nil || terminal.Status != "failed" || terminal.ReasonCode != "apply_failed" || terminal.PlannedCount != 1 || terminal.AppliedCount != 0 || terminal.NoopCount != 0 || terminal.FailedCount != 1 || terminal.NotAttemptedCount != 0 || terminal.SummaryBasename != "" {
		t.Fatalf("failed apply result is inconsistent: stdout=%q terminal=%#v", stdout, terminal)
	}
	for _, want := range []string{"apply may have partially succeeded", "applied_ids=[]", "report=", "plan=", "do not blindly rerun"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("full-screen apply error omitted %q: %v", want, err)
		}
	}
	cfg, loadErr := config.Load(configPath)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	summaries, globErr := filepath.Glob(filepath.Join(cfg.ReportDir, "screen-summary-*.md"))
	if globErr != nil || len(summaries) != 0 {
		t.Fatalf("failed apply produced a success summary: files=%v err=%v", summaries, globErr)
	}
	for _, pattern := range []string{"discover-*.json", "plan-*.json"} {
		files, globErr := filepath.Glob(filepath.Join(cfg.ReportDir, pattern))
		if globErr != nil || len(files) != 1 || !strings.Contains(err.Error(), files[0]) {
			t.Fatalf("apply error omitted its %s artifact path: files=%v err=%v", pattern, files, err)
		}
	}
}

func TestFullScreenAutomaticHashMismatchStopsBeforeCredentialOrAPI(t *testing.T) {
	configPath, _ := fullScreenFixture(t, true)
	credentialCalls, clientCalls := 0, 0
	err := runAutomaticWith([]string{"--config", configPath, "--full-screen"}, func(config.CredentialConfig) (securecred.Value, error) {
		credentialCalls++
		return securecred.Value{APIKey: []byte("test-admin-key")}, nil
	}, func(string) (app.AdminAPI, error) {
		clientCalls++
		return nil, errors.New("client should not be created")
	})
	if err == nil || !strings.Contains(err.Error(), "before credentials/API access") || credentialCalls != 0 || clientCalls != 0 {
		t.Fatalf("full-screen hash drift was not rejected before external access: err=%v credentials=%d clients=%d", err, credentialCalls, clientCalls)
	}
}

func TestFullScreenPreviewOnlyDoesNotApplyEvenWithMatchingApproval(t *testing.T) {
	configPath, api := fullScreenFixture(t, false)
	stdout, err := captureStdout(t, func() error {
		return runAutomaticWith([]string{"--config", configPath, "--full-screen", "--preview-only"}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil })
	})
	if err != nil {
		t.Fatalf("successful preview-only full-screen run returned an error: %v", err)
	}
	if api.syncCalls != 1 || api.bulkCalls != 0 || api.statusCalls != 1 {
		t.Fatalf("preview-only full screen crossed the mapping-write boundary: sync=%d bulk=%d status=%d", api.syncCalls, api.bulkCalls, api.statusCalls)
	}
	var terminal fullScreenResult
	if json.Unmarshal([]byte(stdout), &terminal) != nil || terminal.Status != "preview" || terminal.ReasonCode != "preview_only" || terminal.AppliedCount != 0 || terminal.FailedCount != 0 || terminal.NotAttemptedCount != 1 {
		t.Fatalf("preview-only full-screen result is inconsistent: stdout=%q terminal=%#v", stdout, terminal)
	}
}

func TestFullScreenNativeRefreshGateProducesBlockedTerminalResult(t *testing.T) {
	configPath, api := fullScreenFixture(t, false)
	api.status.RunStatus = "running"
	stdout, err := captureStdout(t, func() error {
		return runAutomaticWith([]string{"--config", configPath, "--full-screen"}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil })
	})
	if err == nil || api.syncCalls != 0 || api.bulkCalls != 0 || api.statusCalls != 1 {
		t.Fatalf("running native refresh was not blocked before discovery: err=%v sync=%d writes=%d status=%d", err, api.syncCalls, api.bulkCalls, api.statusCalls)
	}
	var terminal fullScreenResult
	if json.Unmarshal([]byte(stdout), &terminal) != nil || terminal.Status != "blocked" || terminal.ReasonCode != "native_refresh_running" || terminal.PlannedCount != 0 || terminal.AppliedCount != 0 || terminal.FailedCount != 0 || terminal.NotAttemptedCount != 0 {
		t.Fatalf("native refresh block result is inconsistent: stdout=%q terminal=%#v", stdout, terminal)
	}
}

func TestFullScreenApplyFailureMapsManagerLockToBlockedOrPartial(t *testing.T) {
	lockErr := errors.New("another run may be active or a prior lock needs manual review")
	for _, tc := range []struct {
		name       string
		result     app.ApplyResult
		wantStatus string
		wantReason string
	}{
		{name: "no verified writes", wantStatus: "blocked", wantReason: "manager_lock_requires_review"},
		{name: "prior verified write", result: app.ApplyResult{AppliedIDs: []int64{9001}}, wantStatus: "partial", wantReason: "apply_partial"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, reason := fullScreenApplyFailure(lockErr, tc.result)
			if status != tc.wantStatus || reason != tc.wantReason {
				t.Fatalf("manager lock terminal=%s/%s, want %s/%s", status, reason, tc.wantStatus, tc.wantReason)
			}
		})
	}
}

func TestFullScreenPartialAfterVerifiedWritePreservesNativeRefreshGateReason(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     adminapi.RefreshStatus
		wantReason string
	}{
		{name: "running", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "running"}, wantReason: "native_refresh_running"},
		{name: "unknown", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "future_status"}, wantReason: "native_refresh_status_unknown"},
		{name: "unavailable", status: adminapi.RefreshStatus{Enabled: true, RunStatus: "unavailable"}, wantReason: "native_refresh_status_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath, api := fullScreenFixture(t, false)
			cfg, err := config.Load(configPath)
			if err != nil {
				t.Fatal(err)
			}
			rules, err := catalog.LoadRules(cfg.RulesFile)
			if err != nil {
				t.Fatal(err)
			}
			rules.SourceProfiles[0].Source.AccountID = 0
			rules.Aliases[0].Source.AccountID = 0
			rulesBytes, err := json.MarshalIndent(rules, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfg.RulesFile, rulesBytes, 0600); err != nil {
				t.Fatal(err)
			}
			rulesHash := sha256.Sum256(rulesBytes)
			cfg.ApprovedRulesSHA256 = hex.EncodeToString(rulesHash[:])
			configBytes, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
				t.Fatal(err)
			}

			account1 := api.account
			account2 := account1
			account2.ID = 9002
			api.accounts = map[int64]adminapi.Account{account1.ID: account1, account2.ID: account2}
			api.catalog.Models = append(api.catalog.Models, "new-model")
			api.catalogs = map[int64]adminapi.Catalog{
				account1.ID: api.catalog,
				account2.ID: api.catalog,
			}
			api.afterBulk = func(int64) { api.status = tc.status }
			stdout, runErr := captureStdout(t, func() error {
				return runAutomaticWith([]string{"--config", configPath, "--full-screen"}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil })
			})
			if runErr == nil {
				t.Fatal("partial full-screen result returned a successful exit status")
			}
			if api.syncCalls != 2 || api.bulkCalls != 1 || api.statusCalls != 3 {
				t.Fatalf("test did not verify one mapping write followed by a refresh gate: sync=%d writes=%d status=%d", api.syncCalls, api.bulkCalls, api.statusCalls)
			}
			var terminal fullScreenResult
			if json.Unmarshal([]byte(stdout), &terminal) != nil || terminal.Status != "partial" || terminal.ReasonCode != tc.wantReason || terminal.PlannedCount != 2 || terminal.AppliedCount != 1 || terminal.NoopCount != 0 || terminal.FailedCount != 0 || terminal.NotAttemptedCount != 1 {
				t.Fatalf("partial result after verified write lost its native refresh reason or counts: stdout=%q result=%#v", stdout, terminal)
			}
		})
	}
}

func TestFullScreenNoPlanAndPartialScanHaveDistinctTerminalResults(t *testing.T) {
	t.Run("complete no plan", func(t *testing.T) {
		configPath, api := fullScreenFixture(t, false)
		api.catalog = adminapi.Catalog{Models: []string{}, LiveListAvailable: false}
		stdout, err := captureStdout(t, func() error {
			return runAutomaticWith([]string{"--config", configPath, "--full-screen"}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil })
		})
		if err != nil {
			t.Fatalf("complete no-plan run should exit successfully: %v", err)
		}
		var terminal fullScreenResult
		if json.Unmarshal([]byte(stdout), &terminal) != nil || terminal.Status != "no_plan" || terminal.ReasonCode != "no_applicable_plan" || terminal.PlannedCount != 0 || terminal.AppliedCount != 0 || terminal.FailedCount != 0 || terminal.NotAttemptedCount != 0 {
			t.Fatalf("complete no-plan result is inconsistent: stdout=%q result=%#v", stdout, terminal)
		}
	})
	t.Run("partial account detail scan", func(t *testing.T) {
		configPath, api := fullScreenFixture(t, false)
		api.accountErr = errors.New("synthetic account read failure")
		stdout, err := captureStdout(t, func() error {
			return runAutomaticWith([]string{"--config", configPath, "--full-screen"}, mockCredentialReader, func(string) (app.AdminAPI, error) { return api, nil })
		})
		if err == nil {
			t.Fatal("partial account scan must not return a successful exit status")
		}
		var terminal fullScreenResult
		if json.Unmarshal([]byte(stdout), &terminal) != nil || terminal.Status != "partial" || terminal.ReasonCode != "account_scan_partial" || terminal.PlannedCount != 0 || terminal.AppliedCount != 0 || terminal.FailedCount != 0 || terminal.NotAttemptedCount != 0 || terminal.SummaryBasename == "" {
			t.Fatalf("partial account scan result is inconsistent: stdout=%q result=%#v", stdout, terminal)
		}
	})
}

func captureStdout(t *testing.T, run func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	runErr := run()
	_ = writer.Close()
	os.Stdout = previous
	data, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(data), runErr
}

func TestFullScreenConfigRequiresFlagAndRejectsConflictingFlagsBeforeAccess(t *testing.T) {
	configPath, _ := fullScreenFixture(t, false)
	for _, args := range [][]string{
		{"--config", configPath},
		{"--config", configPath, "--full-screen", "--manual-only"},
		{"--config", configPath, "--preview-only"},
	} {
		credentialCalls, clientCalls := 0, 0
		err := runAutomaticWith(args, func(config.CredentialConfig) (securecred.Value, error) {
			credentialCalls++
			return securecred.Value{APIKey: []byte("test-admin-key")}, nil
		}, func(string) (app.AdminAPI, error) {
			clientCalls++
			return nil, errors.New("client should not be created")
		})
		if err == nil || credentialCalls != 0 || clientCalls != 0 {
			t.Fatalf("invalid full-screen args crossed external access boundary: args=%v err=%v credentials=%d clients=%d", args, err, credentialCalls, clientCalls)
		}
	}
}

func TestAutomaticRunConfigRequiresManualOnlyFlagBeforeCredentialOrAPI(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "manual-only-config.json")
	configBody := `{"target":{"base_url":"https://404token.xyz","runtime_compatibility":{"build_id":"verified-image","api_contract_id":"admin-catalog-all-v1","evidence":"test fixture","reviewed_at":"2026-10-12"}},"account_scope":"all","accept_all_credential_response_memory_exposure":true,"require_manual_only_mode":true,"accounts":[],"allow_native_sync_metadata_write":true,"apply_mode":"approved_rules","approved_rules_sha256":"` + strings.Repeat("a", 64) + `","credential":{"windows_credential_target":"test"},"state_dir":"state","report_dir":"reports","backup_dir":"backups","rules_file":"rules.json"}`
	if err := os.WriteFile(configPath, []byte(configBody), 0600); err != nil {
		t.Fatal(err)
	}
	credentialCalls, clientCalls := 0, 0
	err := runAutomaticWith([]string{"--config", configPath}, func(config.CredentialConfig) (securecred.Value, error) {
		credentialCalls++
		return securecred.Value{APIKey: []byte("test-admin-key")}, nil
	}, func(string) (app.AdminAPI, error) {
		clientCalls++
		return nil, errors.New("client should not be created")
	})
	if err == nil || !strings.Contains(err.Error(), "requires --manual-only") || credentialCalls != 0 || clientCalls != 0 {
		t.Fatalf("scheduled config did not enforce the manual-only flag before external access: err=%v credentials=%d clients=%d", err, credentialCalls, clientCalls)
	}
}

func automaticFixture(t *testing.T, approvedHash string) (string, *mainWorkflowAPI, string) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	date := now.In(loc).Format("2006-01-02")
	account := adminapi.Account{ID: 9001, Platform: "openai", Type: "apikey", Protocol: "openai", BaseURL: "https://provider.example/v1", Status: "active", ModelMapping: map[string]string{"manual": "keep"}, APIKeyPresent: mainBoolPointer(true)}
	source, err := catalog.SourceForAccount(account.Platform, account.Type, account.Protocol, account.BaseURL, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	rules := catalog.Rules{
		SchemaVersion:         1,
		Aliases:               []catalog.AliasRule{{Source: source, UpstreamID: "upstream-known", PublicID: "canonical-name", Decision: "approved", Evidence: "reviewed exact mock rule", ReviewedAt: date}},
		SourceProfiles:        []catalog.SourceProfile{{Source: source, BuildID: "verified-image", APIContractID: "admin-catalog-v1", Decision: "approved", IdentityAddPolicy: "add_exact", OfficialSelectabilityScope: "official-account:test-openai-account", OfficialSelectabilityProduct: "ui", Evidence: "mock-only build/API scope", ReviewedAt: date}},
		OfficialSelectability: []catalog.OfficialSelectability{{Scope: "official-account:test-openai-account", Complete: true, ModelIDs: []string{"upstream-known", "new-model", "canonical-name", "keep", "raw-v2"}, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(23 * time.Hour), Evidence: "synthetic complete selector fixture"}},
		VersionFamilies:       []catalog.VersionFamily{}, RetiredModels: []catalog.RetiredRule{}, CompleteCatalogProfiles: []catalog.CompleteCatalogProfile{},
	}
	rulesBytes, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulesPath, rulesBytes, 0600); err != nil {
		t.Fatal(err)
	}
	rulesSum := sha256.Sum256(rulesBytes)
	rulesHash := hex.EncodeToString(rulesSum[:])
	if approvedHash == "" {
		approvedHash = rulesHash
	}
	cfg := config.Config{
		Target:                       config.TargetConfig{BaseURL: "https://404token.xyz", RuntimeCompatibility: config.RuntimeCompatibility{BuildID: "verified-image", APIContractID: "admin-catalog-v1", Evidence: "mock-only test fixture", ReviewedAt: date}},
		Accounts:                     []config.AccountConfig{{ID: 9001, AcceptCredentialResponseMemoryExposure: mainBoolPointer(true)}},
		AllowNativeSyncMetadataWrite: true, ApplyMode: "approved_rules", ApprovedRulesSHA256: approvedHash,
		Credential: config.CredentialConfig{WindowsCredentialTarget: "mock-only"}, StateDir: filepath.Join(dir, "state"), ReportDir: filepath.Join(dir, "reports"), BackupDir: filepath.Join(dir, "backups"), RulesFile: rulesPath,
	}
	configBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	api := &mainWorkflowAPI{
		account: account,
		status:  adminapi.RefreshStatus{Enabled: true, Timezone: "Asia/Shanghai", RunStatus: "completed", LastFinishedAt: timePtrMain(now), Accounts: []adminapi.AccountRunStatus{{AccountID: 9001, Status: "completed"}}},
		catalog: adminapi.Catalog{Models: []string{"upstream-known"}, LiveListAvailable: true},
	}
	return configPath, api, rulesHash
}

func fullScreenFixture(t *testing.T, mismatch bool) (string, *mainWorkflowAPI) {
	t.Helper()
	configPath, api, _ := automaticFixture(t, "")
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config.Config
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.AccountScope = "all"
	cfg.Accounts = nil
	cfg.AcceptAllCredentialResponseMemoryExposure = true
	cfg.AllowFullScreenMode = true
	cfg.Target.RuntimeCompatibility.APIContractID = config.APIContractAllAccountsV1
	rules, err := catalog.LoadRules(cfg.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	rules.SourceProfiles[0].APIContractID = config.APIContractAllAccountsV1
	rulesBytes, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.RulesFile, rulesBytes, 0600); err != nil {
		t.Fatal(err)
	}
	rulesSum := sha256.Sum256(rulesBytes)
	approved := hex.EncodeToString(rulesSum[:])
	if mismatch {
		approved = strings.Repeat("0", 64)
	}
	cfg.ApprovedRulesSHA256 = approved
	configBytes, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	api.status.RunStatus = "partial_failure"
	// Full-screen absence pruning uses the native 404token list as its source
	// of truth. Keep the fixture's existing unmanaged mapping in that list so
	// these apply-path tests exercise the approved addition instead of the
	// intentional unmanaged-missing-ID conflict boundary.
	api.catalog.Models = append(api.catalog.Models, "keep")
	return configPath, api
}

func mockCredentialReader(config.CredentialConfig) (securecred.Value, error) {
	return securecred.Value{APIKey: []byte("test-admin-key")}, nil
}

type mainWorkflowAPI struct {
	account     adminapi.Account
	accountErr  error
	accounts    map[int64]adminapi.Account
	status      adminapi.RefreshStatus
	catalog     adminapi.Catalog
	catalogs    map[int64]adminapi.Catalog
	afterSync   func()
	afterBulk   func(int64)
	bulkErr     error
	syncCalls   int
	bulkCalls   int
	statusCalls int
	lastBulkID  int64
	lastMapping map[string]string
}

func (m *mainWorkflowAPI) SetAPIKey([]byte) error { return nil }
func (m *mainWorkflowAPI) RefreshStatus(context.Context) (adminapi.RefreshStatus, error) {
	m.statusCalls++
	return m.status, nil
}
func (m *mainWorkflowAPI) ListAllAccounts(context.Context) ([]adminapi.AccountSummary, error) {
	if m.accounts != nil {
		ids := make([]int64, 0, len(m.accounts))
		for id := range m.accounts {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		rows := make([]adminapi.AccountSummary, 0, len(ids))
		for _, id := range ids {
			account := m.accounts[id]
			rows = append(rows, adminapi.AccountSummary{ID: id, Platform: account.Platform, Type: account.Type, Status: account.Status, ParentAccountID: account.ParentAccountID})
		}
		return rows, nil
	}
	return []adminapi.AccountSummary{{ID: m.account.ID, Platform: m.account.Platform, Type: m.account.Type, Status: m.account.Status, ParentAccountID: m.account.ParentAccountID}}, nil
}
func (m *mainWorkflowAPI) Account(_ context.Context, id int64) (adminapi.Account, error) {
	if m.accountErr != nil {
		return adminapi.Account{}, m.accountErr
	}
	account, ok := m.account, id == m.account.ID
	if m.accounts != nil {
		account, ok = m.accounts[id]
	}
	if !ok {
		return adminapi.Account{}, errors.New("unexpected mock account id")
	}
	copy := account
	copy.ModelMapping = make(map[string]string, len(account.ModelMapping))
	for key, value := range account.ModelMapping {
		copy.ModelMapping[key] = value
	}
	return copy, nil
}
func (m *mainWorkflowAPI) SyncUpstream(_ context.Context, id int64) (adminapi.Catalog, error) {
	if m.accounts != nil {
		if _, ok := m.accounts[id]; !ok {
			return adminapi.Catalog{}, errors.New("unexpected sync id")
		}
	} else if id != m.account.ID {
		return adminapi.Catalog{}, errors.New("unexpected sync id")
	}
	m.syncCalls++
	if m.afterSync != nil {
		m.afterSync()
	}
	if m.catalogs != nil {
		catalog, ok := m.catalogs[id]
		if !ok {
			return adminapi.Catalog{}, errors.New("unexpected sync catalog id")
		}
		return catalog, nil
	}
	return m.catalog, nil
}
func (m *mainWorkflowAPI) ProbeModel(_ context.Context, id int64, modelID string) (adminapi.ModelProbeResult, error) {
	return adminapi.ModelProbeResult{ModelID: modelID, Outcome: "succeeded"}, nil
}
func (m *mainWorkflowAPI) BulkUpdateMapping(_ context.Context, id int64, mapping map[string]string) (adminapi.BulkUpdateResult, error) {
	m.bulkCalls++
	m.lastBulkID = id
	if m.bulkErr != nil {
		return adminapi.BulkUpdateResult{}, m.bulkErr
	}
	m.lastMapping = map[string]string{}
	for key, value := range mapping {
		m.lastMapping[key] = value
	}
	if m.accounts != nil {
		account, ok := m.accounts[id]
		if !ok {
			return adminapi.BulkUpdateResult{}, errors.New("unexpected bulk-update id")
		}
		account.ModelMapping = m.lastMapping
		m.accounts[id] = account
	} else {
		m.account.ModelMapping = m.lastMapping
	}
	if m.afterBulk != nil {
		m.afterBulk(id)
	}
	return adminapi.BulkUpdateResult{SuccessIDs: []int64{id}, FailedIDs: []int64{}}, nil
}
func (m *mainWorkflowAPI) Close() {}

func mainBoolPointer(v bool) *bool       { return &v }
func timePtrMain(v time.Time) *time.Time { return &v }

func validApprovalPlan() catalog.ApprovalPlan {
	now := time.Now().UTC()
	source := catalog.Source{Platform: "openai", AccountType: "apikey", APIProtocol: "openai", BaseURL: "https://provider.example/v1", AccountID: 9001}
	models := []string{"raw-v2"}
	directoryHash, _ := catalog.DirectoryDigest(models, true, nil)
	lifecycleDigest, _ := catalog.LifecycleEvidenceDigest([]string{}, []catalog.LifecycleExclusion{})
	return catalog.ApprovalPlan{
		SchemaVersion: catalog.ApprovalPlanSchemaVersion,
		CreatedAt:     now,
		ExpiresAt:     now.Add(catalog.ApprovalPlanTTL),
		Target:        catalog.TargetBinding{Origin: "https://404token.xyz", BuildID: "verified-image", APIContractID: "admin-catalog-v1"},
		AccountScope:  "allowlist",
		RulesSHA256:   strings.Repeat("a", 64),
		StateSHA256:   strings.Repeat("b", 64),
		Accounts: []catalog.Plan{{
			AccountID: 9001, Source: source, SourceFingerprint: catalog.SourceFingerprint(source),
			DirectoryHash: directoryHash, CatalogObservedAt: now, RulesHash: strings.Repeat("c", 64),
			OfficialSelectabilityScope: "official-account:test-openai-account", OfficialSelectabilitySHA256: strings.Repeat("d", 64), OfficialSelectabilityObservedAt: now.Add(-time.Minute), OfficialSelectabilityExpiresAt: now.Add(23 * time.Hour),
			LifecycleScopes: []string{}, LifecycleExclusions: []catalog.LifecycleExclusion{}, LifecycleEvidenceSHA256: lifecycleDigest,
			Completeness: catalog.CompletenessUnknown, LiveListAvailable: true,
			AbsenceCountsBefore: map[string]int{}, AbsenceCountsAfter: map[string]int{},
			Before: map[string]string{"manual": "raw"}, After: map[string]string{"manual": "raw", "public": "raw-v2"},
			Changes:   []catalog.Change{{Action: "add", PublicID: "public", After: "raw-v2", RuleKind: "alias", Reason: "reviewed exact rule"}},
			Conflicts: []string{}, UnreviewedModels: []string{}, CatalogModels: models, CatalogWarningCodes: []string{}, ApplyEligible: true,
		}},
	}
}
