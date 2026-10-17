package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sub2api-model-catalog-manager/internal/catalog"
	"sub2api-model-catalog-manager/internal/config"
	"sub2api-model-catalog-manager/internal/officialselectability"
	"sub2api-model-catalog-manager/internal/securecred"
)

type officialSnapshotDoer func(*http.Request) (*http.Response, error)

func (f officialSnapshotDoer) Do(request *http.Request) (*http.Response, error) { return f(request) }

func TestOfficialSnapshotOverlaysConfiguredAPIScopeWithoutChangingRulesApproval(t *testing.T) {
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	root := t.TempDir()
	cfg := config.Config{
		RulesFile: filepath.Join(root, "rules.json"), StateDir: filepath.Join(root, "state"),
		OfficialSelectabilitySources: []config.OfficialSelectabilitySource{{
			Scope: "official-account:api-account", Provider: "openai-api", Product: "api",
			Credential: config.CredentialConfig{WindowsCredentialTarget: "openai-api-account"},
		}},
	}
	rules := catalog.Rules{
		SchemaVersion: 1, Aliases: []catalog.AliasRule{}, VersionFamilies: []catalog.VersionFamily{}, RetiredModels: []catalog.RetiredRule{},
		SourceProfiles: []catalog.SourceProfile{
			{Source: catalog.Source{Platform: "openai", AccountType: "api_key", APIProtocol: "openai", BaseURL: "https://api.openai.com"}, BuildID: "build", APIContractID: "admin-catalog-v1", Decision: "approved", OfficialSelectabilityScope: "official-account:api-account", OfficialSelectabilityProduct: "api", OfficialSelectabilityProvider: "openai-api", Evidence: "approved API fixture", ReviewedAt: "2026-10-17"},
			{Source: catalog.Source{Platform: "openai", AccountType: "chatgpt_login", APIProtocol: "web", BaseURL: "https://chatgpt.com"}, BuildID: "build", APIContractID: "admin-catalog-v1", Decision: "approved", OfficialSelectabilityScope: "official-account:ui-account", OfficialSelectabilityProduct: "ui", Evidence: "approved UI fixture", ReviewedAt: "2026-10-17"},
		},
		CompleteCatalogProfiles: []catalog.CompleteCatalogProfile{},
		OfficialSelectability: []catalog.OfficialSelectability{
			{Scope: "official-account:api-account", Complete: true, ModelIDs: []string{"old-api-model"}, ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(23 * time.Hour), Evidence: "previous API snapshot"},
			{Scope: "official-account:ui-account", Complete: true, ModelIDs: []string{"ui-selected-model"}, ObservedAt: now.Add(-time.Hour), ExpiresAt: now.Add(23 * time.Hour), Evidence: "manual UI selector capture"},
		},
	}
	encoded, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.RulesFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	_, expectedRulesHash, err := catalog.LoadRulesWithHash(cfg.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	missingSource := cfg
	missingSource.OfficialSelectabilitySources = nil
	if _, _, _, err := loadRulesWithOfficialSnapshot(missingSource, now); err == nil {
		t.Fatal("API scope without configured collector was not blocked")
	}
	wrongProvider := cfg
	wrongProvider.OfficialSelectabilitySources = append([]config.OfficialSelectabilitySource(nil), cfg.OfficialSelectabilitySources...)
	wrongProvider.OfficialSelectabilitySources[0].Provider = "anthropic-api"
	if _, _, _, err := loadRulesWithOfficialSnapshot(wrongProvider, now); err == nil {
		t.Fatal("API scope with mismatched provider was not blocked")
	}
	readSecret := func(config.CredentialConfig) (securecred.Value, error) {
		return securecred.Value{APIKey: []byte("api-test-secret")}, nil
	}
	doer := officialSnapshotDoer(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":[{"id":"new-api-model"}]}`)), Header: make(http.Header)}, nil
	})
	if err := officialselectability.Refresh(context.Background(), cfg.OfficialSelectabilityFile(), cfg.OfficialSelectabilitySources, readSecret, doer, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	loaded, rulesHash, snapshotHash, err := loadRulesWithOfficialSnapshot(cfg, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rulesHash != expectedRulesHash {
		t.Fatalf("dynamic refresh changed the static rules approval hash: got %s want %s", rulesHash, expectedRulesHash)
	}
	if snapshotHash == "" || len(snapshotHash) != 64 {
		t.Fatalf("dynamic snapshot digest is missing or invalid: %q", snapshotHash)
	}
	byScope := map[string][]string{}
	for _, item := range loaded.OfficialSelectability {
		byScope[item.Scope] = item.ModelIDs
	}
	if len(byScope) != 2 || len(byScope["official-account:api-account"]) != 1 || byScope["official-account:api-account"][0] != "new-api-model" {
		t.Fatalf("configured API evidence did not replace the stale static snapshot: %#v", byScope)
	}
	if len(byScope["official-account:ui-account"]) != 1 || byScope["official-account:ui-account"][0] != "ui-selected-model" {
		t.Fatalf("manual UI selector evidence was not preserved: %#v", byScope)
	}
	if _, _, _, err := loadRulesWithOfficialSnapshot(cfg, now.Add(officialselectability.MaxAge)); err == nil {
		t.Fatal("expired API snapshot was accepted")
	}
}

func TestDynamicSnapshotDigestIsBoundAcrossDiscoveryAndApplyPreflight(t *testing.T) {
	cfg, _, api, now := ownerAvailabilityWorkflowFixture(t, true, []string{"stable"})
	rules, err := catalog.LoadRules(cfg.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	rules.SourceProfiles[0].OfficialSelectabilityProduct = "api"
	rules.SourceProfiles[0].OfficialSelectabilityProvider = "openai-api"
	writeWorkflowRules(t, cfg.RulesFile, rules)
	cfg.OfficialSelectabilitySources = []config.OfficialSelectabilitySource{{
		Scope: "official-account:test-owner-account", Provider: "openai-api", Product: "api",
		Credential: config.CredentialConfig{WindowsCredentialTarget: "official-api-test"},
	}}
	cfg.ApplyMode = "approved_rules"
	_, approvedRulesHash, err := catalog.LoadRulesWithHash(cfg.RulesFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ApprovedRulesSHA256 = approvedRulesHash
	models := `{"data":[{"id":"stable"}]}`
	readSecret := func(config.CredentialConfig) (securecred.Value, error) {
		return securecred.Value{APIKey: []byte("test-api-key")}, nil
	}
	doer := officialSnapshotDoer(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(models)), Header: make(http.Header)}, nil
	})
	snapshotPath := cfg.OfficialSelectabilityFile()
	if err := officialselectability.Refresh(context.Background(), snapshotPath, cfg.OfficialSelectabilitySources, readSecret, doer, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	discoverer := Discoverer{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return now }, FullScreen: true}
	discoveryPreflight, err := discoverer.Preflight(cfg)
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := discoverer.DiscoverPrepared(context.Background(), cfg, discoveryPreflight)
	if err != nil || discovery.Plan == nil {
		t.Fatalf("dynamic official snapshot did not produce a discovery plan: plan=%#v err=%v", discovery.Plan, err)
	}
	if len(discovery.Plan.Accounts) == 0 || discoveryPreflight.OfficialSelectabilitySHA256 == "" || discovery.Plan.Accounts[0].OfficialSelectabilitySHA256 == "" {
		t.Fatal("discovery did not bind the official snapshot digest into its preflight and plan")
	}
	currentNow := now
	applier := Applier{ReadCredential: workflowCredential, NewClient: func(string) (AdminAPI, error) { return api, nil }, Now: func() time.Time { return currentNow }, FullScreen: true}
	applyPreflight, err := applier.Preflight(cfg, *discovery.Plan, discovery.PlanSHA256, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if applyPreflight.OfficialSelectabilitySHA256 != discoveryPreflight.OfficialSelectabilitySHA256 {
		t.Fatal("apply preflight was computed against a different official snapshot")
	}
	models = `{"data":[{"id":"different-snapshot"}]}`
	currentNow = now.Add(time.Minute)
	if err := officialselectability.Refresh(context.Background(), snapshotPath, cfg.OfficialSelectabilitySources, readSecret, doer, func() time.Time { return currentNow }); err != nil {
		t.Fatal(err)
	}
	if _, err := applier.ApplyPrepared(context.Background(), cfg, *discovery.Plan, discovery.PlanSHA256, "", true, applyPreflight); err == nil {
		t.Fatal("apply proceeded after the bound official snapshot changed")
	}
	if len(api.bulkCalls) != 0 {
		t.Fatalf("snapshot drift reached the mapping write: %v", api.bulkCalls)
	}
}
