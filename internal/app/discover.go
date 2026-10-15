package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"time"
	_ "time/tzdata"

	"sub2api-model-catalog-manager/internal/adminapi"
	"sub2api-model-catalog-manager/internal/catalog"
	"sub2api-model-catalog-manager/internal/config"
	"sub2api-model-catalog-manager/internal/officialcatalog"
	"sub2api-model-catalog-manager/internal/report"
	"sub2api-model-catalog-manager/internal/state"
)

type DiscoveryResult struct {
	Report     report.Document
	Plan       *catalog.ApprovalPlan
	PlanPath   string
	PlanSHA256 string
}

// DiscoveryPreflight contains the exact validated local rules/state snapshots
// carried across the startup OEM sync boundary.
type DiscoveryPreflight struct {
	Rules      catalog.Rules
	RulesHash  string
	LocalState state.State
	StateHash  string
	FullScreen bool
}

type Discoverer struct {
	ReadCredential CredentialReader
	NewClient      ClientFactory
	Now            func() time.Time
	WaitForRefresh bool
	// ManualOnlyOnly gates this run to rows explicitly skipped by today's
	// completed native refresh with source_profile_id=manual_only. Together
	// with FullScreen, it permits identity_catalog_policy changes.
	ManualOnlyOnly bool
	// FullScreen performs an explicit operator-triggered all-account screen.
	// It syncs each eligible account directly and does not depend on the daily
	// scheduled refresh status.
	FullScreen bool
	// ManualSyncAuthorized permits an explicitly authorized all-account
	// preview to call native SyncUpstream even when today's scheduled refresh
	// has not completed. It also retries accounts marked failed by the prior
	// scheduled run; it never enables mapping apply.
	ManualSyncAuthorized bool
	Sleep                func(context.Context, time.Duration) error
	RefreshWait          time.Duration
	PollInterval         time.Duration
	LifecycleStartup     officialcatalog.StartupSyncResult
}

// NativeRefreshGateError is a deliberately small, secret-free classification
// for a best-effort check of Sub2API's native model-catalog refresh state.
// ReasonCode returns only one of the fixed values consumed by the license
// admin runner.
type NativeRefreshGateError struct {
	code string
}

func (e *NativeRefreshGateError) Error() string {
	if e == nil {
		return "native refresh state is unavailable"
	}
	return "native refresh gate blocked: " + e.code
}

func (e *NativeRefreshGateError) ReasonCode() string {
	if e == nil {
		return "native_refresh_status_unknown"
	}
	return e.code
}

// CheckNativeRefreshGate returns only for a known non-running native refresh
// status. It does not claim an atomic lock: a refresh can start immediately
// after this read.
func CheckNativeRefreshGate(ctx context.Context, client AdminAPI) (adminapi.RefreshStatus, error) {
	status, err := client.RefreshStatus(ctx)
	if err != nil {
		return adminapi.RefreshStatus{}, &NativeRefreshGateError{code: "native_refresh_status_unavailable"}
	}
	if status.RunStatus == "running" || status.RunStatus == "stale_running" {
		return status, &NativeRefreshGateError{code: "native_refresh_running"}
	}
	if status.RunStatus == "unavailable" {
		return status, &NativeRefreshGateError{code: "native_refresh_status_unavailable"}
	}
	if !status.Enabled {
		return status, &NativeRefreshGateError{code: "native_refresh_status_unknown"}
	}
	switch status.RunStatus {
	case "completed", "succeeded", "partial_failure", "never_run":
		return status, nil
	default:
		return status, &NativeRefreshGateError{code: "native_refresh_status_unknown"}
	}
}

var safeWarningCodePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)

const (
	// These native Sub2API warnings describe capability metadata enrichment,
	// not failure or truncation of the model-ID list.
	warningModelMetadataIncomplete = "upstream_model_metadata_incomplete"
	warningModelMetadataPartial    = "upstream_model_metadata_partial"
	ownerAvailabilityScope         = "openai_codex_chatgpt_login"
)

var ownerAvailabilityModelIDs = map[string]struct{}{
	"gpt-5.2":                {},
	"gpt-5.2-pro":            {},
	"gpt-5.3-codex":          {},
	"gpt-5.3-codex-spark":    {},
	"gpt-5.4":                {},
	"gpt-5.4-mini":           {},
	"gpt-5.4-openai-compact": {},
}

func (d Discoverer) Discover(ctx context.Context, cfg config.Config) (DiscoveryResult, error) {
	prepared, err := d.Preflight(cfg)
	if err != nil {
		return DiscoveryResult{}, err
	}
	return d.DiscoverPrepared(ctx, cfg, prepared)
}

func (d Discoverer) Preflight(cfg config.Config) (DiscoveryPreflight, error) {
	var prepared DiscoveryPreflight
	if err := cfg.Validate(); err != nil {
		return prepared, err
	}
	if !cfg.RuntimeCompatible() {
		return prepared, errors.New("discovery blocked: target runtime compatibility is not verified")
	}
	if cfg.RequireManualOnlyMode && !d.ManualOnlyOnly {
		return prepared, errors.New("discovery blocked: this config requires manual-only mode")
	}
	if d.FullScreen {
		if !cfg.AllowFullScreenMode || !cfg.AllAccounts() || cfg.RequireManualOnlyMode {
			return prepared, errors.New("full-screen discovery requires its explicit all-account configuration gate")
		}
		if d.ManualOnlyOnly || d.ManualSyncAuthorized {
			return prepared, errors.New("full-screen discovery cannot be combined with another refresh mode")
		}
	} else if cfg.AllowFullScreenMode {
		return prepared, errors.New("this config is reserved for --full-screen")
	}
	if d.ManualSyncAuthorized && (!cfg.AllAccounts() || cfg.ApplyModeValue() != "preview") {
		return prepared, errors.New("manual discovery requires all-account scope and preview-only mode")
	}
	if d.ManualOnlyOnly && (!cfg.AllAccounts() || d.ManualSyncAuthorized) {
		return prepared, errors.New("manual-only refresh requires account_scope=all and cannot use manual-sync override")
	}
	if !cfg.AllowNativeSyncMetadataWrite {
		return prepared, errors.New("discovery blocked: native sync metadata side effect is disabled")
	}
	rules, rulesHash, err := catalog.LoadRulesWithHash(cfg.RulesFile)
	if err != nil {
		return prepared, err
	}
	if !d.ManualOnlyOnly && !d.FullScreen {
		for _, profile := range rules.SourceProfiles {
			if profile.IdentityCatalogPolicy != "" {
				return prepared, errors.New("discovery blocked: live identity catalog rules require manual-only or full-screen mode")
			}
		}
	}
	eligible := cfg.EligibleAccountIDs()
	if !cfg.AllAccounts() && len(eligible) == 0 {
		return prepared, errors.New("discovery blocked: no account passed the credential-response memory gate")
	}
	if cfg.AllAccounts() {
		if !cfg.AcceptAllCredentialResponseMemoryExposure {
			return prepared, errors.New("discovery blocked: all-account credential-response memory exposure was not explicitly accepted")
		}
	} else if err := cfg.ExposureGateFor(eligible); err != nil {
		return prepared, err
	}
	if d.ReadCredential == nil || d.NewClient == nil {
		return prepared, errors.New("discovery dependencies are unavailable")
	}
	localState, err := state.Load(filepath.Join(cfg.StateDir, "state.json"))
	if err != nil {
		return prepared, err
	}
	stateHash, err := optionalStateHash(filepath.Join(cfg.StateDir, "state.json"))
	if err != nil {
		return prepared, err
	}
	prepared = DiscoveryPreflight{Rules: rules, RulesHash: rulesHash, LocalState: localState, StateHash: stateHash, FullScreen: d.FullScreen}
	return prepared, nil
}

func (d Discoverer) DiscoverPrepared(ctx context.Context, cfg config.Config, prepared DiscoveryPreflight) (DiscoveryResult, error) {
	var result DiscoveryResult
	if prepared.RulesHash == "" || prepared.LocalState.Accounts == nil || prepared.FullScreen != d.FullScreen {
		return result, errors.New("discovery preflight snapshot is unavailable")
	}
	rules, rulesHash := prepared.Rules, prepared.RulesHash
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	lock, err := state.AcquireLock(filepath.Join(cfg.StateDir, "run.lock"))
	if err != nil {
		return result, err
	}
	defer lock.Release()
	statePath := filepath.Join(cfg.StateDir, "state.json")
	currentStateHash, hashErr := optionalStateHash(statePath)
	if hashErr != nil || currentStateHash != prepared.StateHash {
		return result, errors.New("discovery stopped: local state changed after preflight")
	}
	localState := prepared.LocalState
	if currentRules, currentHash, rulesErr := catalog.LoadRulesWithHash(cfg.RulesFile); rulesErr != nil || currentHash != prepared.RulesHash {
		return result, errors.New("discovery stopped: local rules changed after preflight")
	} else {
		_ = currentRules
	}
	cred, err := d.ReadCredential(cfg.Credential)
	if err != nil {
		return result, errors.New("administrator credential could not be read from the configured OS store")
	}
	defer cred.Clear()
	client, err := d.NewClient(cfg.Target.BaseURL)
	if err != nil {
		return result, err
	}
	defer client.Close()
	if err := client.SetAPIKey(cred.APIKey); err != nil {
		return result, err
	}
	var status adminapi.RefreshStatus
	if d.FullScreen {
		status, err = CheckNativeRefreshGate(ctx, client)
		if err != nil {
			return result, err
		}
	} else {
		status, err = client.RefreshStatus(ctx)
		if err != nil {
			return result, err
		}
		if d.WaitForRefresh {
			if d.ManualOnlyOnly {
				status, err = d.waitForManualOnlyRefresh(ctx, client, status, now)
			} else {
				status, err = d.waitForCurrentRefresh(ctx, client, status, now)
			}
		}
		if err != nil {
			return result, err
		}
	}
	if d.ManualOnlyOnly && !ManualOnlyRefreshCurrent(status, now()) {
		return result, errors.New("manual-only refresh blocked: today's completed 04:00 Asia/Shanghai PostgreSQL run is not verified")
	}
	if !d.FullScreen && !NativeRefreshCurrent(status, now()) && !d.ManualSyncAuthorized {
		return result, errors.New("discovery blocked: today's Asia/Shanghai native refresh is not complete; no account sync was sent")
	}
	refreshRows := make(map[int64]adminapi.AccountRunStatus, len(status.Accounts))
	if d.ManualOnlyOnly {
		var valid bool
		refreshRows, valid = manualOnlySkippedRows(status)
		if !valid {
			return result, errors.New("manual-only refresh blocked: native account status rows are incomplete or duplicated")
		}
	}
	scope, err := resolveAccountScope(ctx, cfg, client)
	if err != nil {
		return result, err
	}
	doc, err := report.New("discover")
	if err != nil {
		return result, err
	}
	doc.TargetFingerprint = cfg.Target.RuntimeCompatibility.BuildID
	doc.AccountScope = cfg.AccountScopeValue()
	if cfg.AllAccounts() {
		doc.AccountScanStatus = "complete"
	}
	doc.AccountInventoryCount = scope.Count
	doc.AccountInventorySHA256 = scope.SHA256
	doc.RefreshRunStatus = safeStatus(status.RunStatus)
	doc.RefreshFinishedAt = status.LastFinishedAt
	doc.NativeSyncSideEffect = true
	doc.ManualNativeSyncOverride = d.ManualSyncAuthorized
	doc.FullAccountScreen = d.FullScreen
	accountsByID := make(map[int64]adminapi.AccountRunStatus, len(status.Accounts))
	for _, item := range status.Accounts {
		accountsByID[item.AccountID] = item
	}
	createdAt := now().UTC()
	approval := catalog.ApprovalPlan{
		SchemaVersion: catalog.ApprovalPlanSchemaVersion,
		CreatedAt:     createdAt,
		ExpiresAt:     createdAt.Add(catalog.ApprovalPlanTTL),
		Target:        catalog.TargetBinding{Origin: normalizedOrigin(cfg.Target.BaseURL), BuildID: cfg.Target.RuntimeCompatibility.BuildID, APIContractID: cfg.Target.RuntimeCompatibility.APIContractID},
		AccountScope:  cfg.AccountScopeValue(),
		RulesSHA256:   rulesHash,
	}
	if cfg.AllAccounts() {
		approval.AccountInventoryCount = scope.Count
		approval.AccountInventorySHA256 = scope.SHA256
	}
	accountIDs := cfg.IDs()
	if cfg.AllAccounts() {
		accountIDs = scope.IDs
	}
	accountReadFailure := false
	for _, accountID := range accountIDs {
		if d.ManualOnlyOnly {
			row, found := refreshRows[accountID]
			if !found || row.SourceProfileID != "manual_only" || row.Status != "skipped" {
				reason := "account was not marked manual_only/skipped by today's native refresh"
				if !found {
					reason = "account was not present in today's native refresh result"
				}
				doc.Discovery = append(doc.Discovery, report.DiscoveryAccount{ID: accountID, NativeRefreshProfile: row.SourceProfileID, NativeRefreshStatus: row.Status, SourceProfileStatus: "not_checked", Status: "skipped_not_manual_only", Reason: reason, CatalogCompleteness: string(catalog.CompletenessUnknown)})
				continue
			}
		}
		if !cfg.AllAccounts() && !cfg.AcceptsCredentialMemoryExposure(accountID) {
			doc.Discovery = append(doc.Discovery, report.DiscoveryAccount{ID: accountID, SourceProfileStatus: "not_checked", Status: "blocked", Reason: "credential-response memory exposure was not accepted", CatalogCompleteness: string(catalog.CompletenessUnknown)})
			continue
		}
		if status.RunStatus == "partial_failure" && !d.ManualSyncAuthorized && !d.FullScreen {
			row, found := accountsByID[accountID]
			if !found || (row.Status != "completed" && row.Status != "succeeded") {
				doc.Discovery = append(doc.Discovery, report.DiscoveryAccount{ID: accountID, SourceProfileStatus: "not_checked", Status: "skipped_refresh_failure", Reason: "selected account did not report a successful native refresh", CatalogCompleteness: string(catalog.CompletenessUnknown)})
				continue
			}
		}
		account, err := accountForCatalogDiagnostics(ctx, client, accountID, cfg)
		if err != nil {
			if cfg.AllAccounts() {
				accountReadFailure = true
				doc.AccountScanStatus = "partial"
				doc.Discovery = append(doc.Discovery, report.DiscoveryAccount{
					ID: accountID, CurrentMappingStatus: "account_read_failed", CurrentMappings: []report.Mapping{}, SourceProfileStatus: "not_checked", Status: "account_read_failed",
					Reason:              "account details could not be read; no plan will be generated for a partial all-account scan",
					CatalogCompleteness: string(catalog.CompletenessUnknown),
				})
				continue
			}
			return result, err
		}
		baseRow := report.DiscoveryAccount{ID: accountID, SourceProfileStatus: "not_checked", Status: "skipped", CatalogCompleteness: string(catalog.CompletenessUnknown)}
		switch {
		case !account.HasModelMapping():
			baseRow.CurrentMappingStatus = "no_explicit_mapping"
		case len(account.ModelMapping) == 0:
			baseRow.CurrentMappingStatus = "explicit_empty"
		default:
			baseRow.CurrentMappingStatus = "explicit_nonempty"
		}
		baseRow.CurrentMappings = make([]report.Mapping, 0, len(account.ModelMapping))
		for publicID, upstreamID := range account.ModelMapping {
			baseRow.CurrentMappings = append(baseRow.CurrentMappings, report.Mapping{PublicID: publicID, UpstreamID: upstreamID, Disposition: "observed_current"})
		}
		if d.ManualOnlyOnly {
			refreshRow := refreshRows[accountID]
			baseRow.NativeRefreshProfile = refreshRow.SourceProfileID
			baseRow.NativeRefreshStatus = refreshRow.Status
		}
		baseRow.CatalogDiagnostics = catalogDiagnostics(account.ModelMapping, account.PublishedSnapshot, nil, false, doc.CreatedAt)
		if account.Status != "active" {
			baseRow.Status, baseRow.Reason = "skipped_inactive", "only active provider accounts are eligible for scheduled discovery"
			doc.Discovery = append(doc.Discovery, baseRow)
			continue
		}
		if account.ParentAccountID != nil {
			baseRow.Status, baseRow.Reason = "skipped_shadow", "credential shadow accounts are not eligible for discovery"
			doc.Discovery = append(doc.Discovery, baseRow)
			continue
		}
		if !account.HasModelMapping() || len(account.ModelMapping) == 0 {
			baseRow.Status = "skipped_unrestricted_mapping"
			baseRow.Reason = "account mapping is absent or explicitly empty; native unrestricted behavior is preserved and no mapping plan is generated"
			doc.Discovery = append(doc.Discovery, baseRow)
			continue
		}
		source, err := catalog.SourceForAccount(account.Platform, account.Type, account.Protocol, account.BaseURL, account.ID)
		if err != nil {
			baseRow.Reason = "account source identity is incomplete or unsafe"
			doc.Discovery = append(doc.Discovery, baseRow)
			continue
		}
		baseRow.SourceFingerprint = catalog.SourceFingerprint(source)
		profile, matched := rules.MatchSourceProfile(source, cfg.Target.RuntimeCompatibility.BuildID, cfg.Target.RuntimeCompatibility.APIContractID)
		if !matched {
			baseRow.SourceProfileStatus = "not_allowlisted_for_target"
			baseRow.Reason = "no exact approved source profile matches source, build, and API contract; no sync request sent"
			doc.Discovery = append(doc.Discovery, baseRow)
			continue
		}
		baseRow.SourceProfileStatus = "approved"
		baseRow.IdentityAddPolicy = profile.IdentityAddPolicy
		baseRow.IdentityCatalogPolicy = profile.IdentityCatalogPolicy
		baseRow.LifecycleScopes = append([]string{}, profile.LifecycleScopes...)
		lifecycleBlockedScopes := make([]string, 0)
		for _, lifecycleScope := range profile.LifecycleScopes {
			if officialcatalog.LifecycleScopeReady(d.LifecycleStartup, lifecycleScope, now().UTC()) {
				continue
			}
			lifecycleBlockedScopes = append(lifecycleBlockedScopes, lifecycleScope)
		}
		sort.Strings(baseRow.LifecycleScopes)
		sort.Strings(lifecycleBlockedScopes)
		baseRow.LifecycleBlockedScopes = lifecycleBlockedScopes
		ownerOnlyLifecycleScreen := d.FullScreen && len(lifecycleBlockedScopes) > 0 && exactOwnerAvailabilityRules(rules)
		if len(profile.LifecycleScopes) == 0 {
			baseRow.LifecycleScopeStatus = "not_configured"
		} else if len(lifecycleBlockedScopes) == 0 {
			baseRow.LifecycleScopeStatus = "ready"
		} else {
			baseRow.LifecycleScopeStatus = "blocked_official_source_unavailable"
		}
		catalogResult, err := client.SyncUpstream(ctx, accountID)
		if err != nil {
			baseRow.Status, baseRow.Reason = "sync_failed", "native upstream catalog sync failed; mapping was not changed"
			doc.Discovery = append(doc.Discovery, baseRow)
			continue
		}
		warningCodes := warningCodesOnly(catalogResult.Warnings)
		baseRow.LiveListAvailable = catalogResult.LiveListAvailable
		baseRow.Models = append([]string{}, catalogResult.Models...)
		baseRow.Warnings = warningCodes
		baseRow.CatalogDiagnostics = catalogDiagnostics(account.ModelMapping, account.PublishedSnapshot, catalogResult.Models, catalogResult.LiveListAvailable, doc.CreatedAt)
		if !catalogResult.LiveListAvailable || len(catalogResult.Models) == 0 {
			baseRow.Status, baseRow.Reason = "catalog_unknown", "response was fallback, unavailable, or empty; no mapping mutation is planned"
			doc.Discovery = append(doc.Discovery, baseRow)
			continue
		}
		directoryHash, err := catalog.DirectoryDigest(catalogResult.Models, catalogResult.LiveListAvailable, warningCodes)
		if err != nil {
			baseRow.Status, baseRow.Reason = "catalog_invalid", "catalog IDs or warning metadata are invalid; no mapping mutation is planned"
			doc.Discovery = append(doc.Discovery, baseRow)
			continue
		}
		observedAt := now().UTC()
		baseRow.CatalogHash = directoryHash
		baseRow.CatalogObservedAt = &observedAt
		baseRow.Status = "candidate_reported"
		completeProfile, hasCompleteProfile := rules.MatchCompleteCatalogProfile(source)
		completeness := catalog.CompletenessUnknown
		completeProfileID := ""
		if hasCompleteProfile {
			completeness = catalog.CompletenessComplete
			completeProfileID = completeProfile.ProfileID
		}
		baseRow.CatalogCompleteness = string(completeness)
		local := localState.Accounts[catalog.AccountKey(account.ID)]
		lifecycleExclusions := buildLifecycleExclusions(rules, profile.LifecycleScopes, d.LifecycleStartup, now().UTC())
		baseRow.LifecycleExclusions = append([]catalog.LifecycleExclusion{}, lifecycleExclusions...)
		identityAddPolicy := profile.IdentityAddPolicy
		if ownerOnlyLifecycleScreen {
			identityAddPolicy = "report_only"
		}
		normalizationRules := rules
		if ownerOnlyLifecycleScreen {
			normalizationRules = ownerOnlyNormalizationRules(rules)
		}
		plan, err := catalog.Normalize(normalizationRules, catalog.Input{
			AccountID: account.ID, Source: source, SourceIdentityAddPolicy: identityAddPolicy,
			IdentityCatalogPolicy: profile.IdentityCatalogPolicy, AllowIdentityCatalogSync: (d.ManualOnlyOnly || d.FullScreen) && profile.IdentityCatalogPolicy != "" && !ownerOnlyLifecycleScreen,
			CurrentMapping: account.ModelMapping, ManagedMappings: local.ManagedMappings,
			LiveModels: catalogResult.Models, LiveListAvailable: catalogResult.LiveListAvailable,
			Completeness: completeness, CompletenessProfileID: completeProfileID, DirectoryHash: directoryHash,
			LifecycleScopes: profile.LifecycleScopes, LifecycleExclusions: lifecycleExclusions,
		}, local)
		if err != nil {
			return result, err
		}
		plan.CatalogObservedAt = observedAt
		plan.CompletenessProfileID = completeProfileID
		plan.CatalogWarningCodes = append([]string{}, warningCodes...)
		if len(lifecycleBlockedScopes) > 0 {
			if ownerOnlyLifecycleScreen && ownerOnlyLifecycleDelta(rules, profile.LifecycleScopes, lifecycleBlockedScopes, plan) {
				plan.DiscoveryReason = "official lifecycle source is unavailable; only exact owner-confirmed removals are evaluated, aliases/version families/other retirement rules and identity additions are deferred, and newly observed IDs are not added in this plan"
				baseRow.Reason = plan.DiscoveryReason
			} else {
				plan.ApplyEligible = false
				plan.DiscoveryReason = "official product lifecycle sources are unavailable, stale, or invalid for a configured scope"
				for _, lifecycleScope := range lifecycleBlockedScopes {
					plan.Conflicts = append(plan.Conflicts, "product lifecycle scope is not ready; mapping changes are blocked: "+lifecycleScope)
				}
				sort.Strings(plan.Conflicts)
			}
		}
		if catalogWarningCodesBlockMappingApply(warningCodes) {
			plan.ApplyEligible = false
			plan.DiscoveryReason = "catalog response contains warnings that may affect the model-ID list"
		}
		baseRow.Changes = make([]report.MappingChange, 0, len(plan.Changes))
		for _, change := range plan.Changes {
			baseRow.Changes = append(baseRow.Changes, report.MappingChange{Action: change.Action, PublicID: change.PublicID, Before: change.Before, After: change.After, RuleKind: change.RuleKind, Evidence: change.Evidence, Reason: change.Reason})
		}
		baseRow.Conflicts = append([]string{}, plan.Conflicts...)
		baseRow.UnreviewedModels = append([]string{}, plan.UnreviewedModels...)
		baseRow.CatalogCompleteness = string(plan.Completeness)
		doc.Discovery = append(doc.Discovery, baseRow)
		local.DirectoryHash = directoryHash
		local.RulesHash = rulesHash
		local.AbsenceCounts = cloneCounterMap(plan.AbsenceCountsAfter)
		local.CatalogSnapshot = &state.CatalogSnapshot{Hash: directoryHash, ObservedAt: observedAt, Completeness: string(plan.Completeness), CompleteProfileID: completeProfileID, LiveListAvailable: catalogResult.LiveListAvailable, SourceFingerprint: plan.SourceFingerprint}
		successAt := observedAt
		local.LastSuccessAt = &successAt
		localState.Accounts[catalog.AccountKey(account.ID)] = local
		approval.Accounts = append(approval.Accounts, plan)
	}
	if !accountReadFailure {
		if err := state.Save(statePath, localState); err != nil {
			return result, err
		}
		stateHash, err := state.Hash(statePath)
		if err != nil {
			return result, err
		}
		approval.StateSHA256 = stateHash
		if len(approval.Accounts) > 0 {
			if err := approval.ValidateShape(now().UTC()); err != nil {
				return result, fmt.Errorf("generated plan failed its own validation: %w", err)
			}
			body, err := json.MarshalIndent(approval, "", "  ")
			if err != nil {
				return result, errors.New("approval plan could not be serialized")
			}
			path, digest, err := report.WritePlan(cfg.ReportDir, body)
			if err != nil {
				return result, err
			}
			result.Plan = &approval
			result.PlanPath = path
			result.PlanSHA256 = digest
		}
	}
	doc.Sort()
	result.Report = doc
	return result, nil
}

// ownerOnlyNormalizationRules prevents unrelated alias, family, retirement,
// and catalog rules from adding conflicts or changes to the narrow owner-only
// lifecycle plan while an official product source is unavailable.
func ownerOnlyNormalizationRules(rules catalog.Rules) catalog.Rules {
	return catalog.Rules{
		SchemaVersion:            rules.SchemaVersion,
		OwnerLifecycleExclusions: append([]catalog.OwnerLifecycleExclusion{}, rules.OwnerLifecycleExclusions...),
	}
}

func exactOwnerAvailabilityRules(rules catalog.Rules) bool {
	if len(rules.OwnerLifecycleExclusions) != len(ownerAvailabilityModelIDs) {
		return false
	}
	seen := make(map[string]struct{}, len(ownerAvailabilityModelIDs))
	for _, rule := range rules.OwnerLifecycleExclusions {
		if rule.Scope != ownerAvailabilityScope {
			return false
		}
		if _, ok := ownerAvailabilityModelIDs[rule.ModelID]; !ok {
			return false
		}
		if _, duplicate := seen[rule.ModelID]; duplicate {
			return false
		}
		seen[rule.ModelID] = struct{}{}
	}
	return len(seen) == len(ownerAvailabilityModelIDs)
}

// ownerOnlyLifecycleDelta is a narrow full-screen exception for the seven
// owner-confirmed IDs. It accepts no additions, renames, unrelated removals,
// official retirement actions, conflicts, or mapping drift.
func ownerOnlyLifecycleDelta(rules catalog.Rules, configuredScopes, blockedScopes []string, plan catalog.Plan) bool {
	if !exactOwnerAvailabilityRules(rules) || !plan.ApplyEligible || len(plan.Conflicts) != 0 || !plan.LiveListAvailable || plan.IdentityCatalogPolicy != "" || len(blockedScopes) == 0 {
		return false
	}
	configured := make(map[string]bool, len(configuredScopes))
	for _, scope := range configuredScopes {
		configured[scope] = true
	}
	if !configured[ownerAvailabilityScope] {
		return false
	}
	for _, scope := range blockedScopes {
		if scope != ownerAvailabilityScope || !configured[scope] {
			return false
		}
	}

	removed := 0
	for publicID, before := range plan.Before {
		after, exists := plan.After[publicID]
		if exists {
			if after != before {
				return false
			}
			continue
		}
		removed++
	}
	for publicID := range plan.After {
		if _, existed := plan.Before[publicID]; !existed {
			return false
		}
	}
	if removed != len(plan.Changes) {
		return false
	}
	if removed == 0 {
		return true
	}
	if len(plan.LifecycleExclusions) == 0 {
		return false
	}
	ownerExclusions := make(map[string]bool, len(plan.LifecycleExclusions))
	for _, exclusion := range plan.LifecycleExclusions {
		if exclusion.OwnerRule && exclusion.Scope == ownerAvailabilityScope {
			ownerExclusions[exclusion.ModelID] = true
		}
	}
	seenPublicIDs := make(map[string]bool, len(plan.Changes))
	for _, change := range plan.Changes {
		if change.Action != "remove" || change.After != "" || change.RuleKind != "product_lifecycle" || change.Evidence != "owner-confirmed unavailable in "+ownerAvailabilityScope {
			return false
		}
		if _, ok := ownerAvailabilityModelIDs[change.Before]; !ok || !ownerExclusions[change.Before] || change.PublicID != change.Before || seenPublicIDs[change.PublicID] {
			return false
		}
		if plan.Before[change.PublicID] != change.Before {
			return false
		}
		if _, exists := plan.After[change.PublicID]; exists {
			return false
		}
		seenPublicIDs[change.PublicID] = true
	}
	return len(seenPublicIDs) == removed
}

func cloneCounterMap(src map[string]int) map[string]int {
	if src == nil {
		return nil
	}
	dst := make(map[string]int, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func buildLifecycleExclusions(rules catalog.Rules, scopes []string, startup officialcatalog.StartupSyncResult, now time.Time) []catalog.LifecycleExclusion {
	enabled := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		enabled[scope] = true
	}
	byExact := make(map[string]catalog.LifecycleExclusion)
	for _, evidence := range officialcatalog.AutomaticExclusions(startup, scopes, now) {
		item := catalog.LifecycleExclusion{
			Scope: evidence.Scope, ModelID: evidence.ModelID, Status: evidence.Status,
			EffectiveAt: evidence.EffectiveAt, Replacement: evidence.Replacement, SourceID: evidence.SourceID,
			SourceURL: evidence.SourceURL, SourceTitle: evidence.SourceTitle, RetrievedAt: evidence.RetrievedAt,
			ContentSHA256: evidence.ContentSHA256, Excerpt: evidence.Excerpt,
		}
		byExact[item.Scope+"\x00"+item.ModelID+"\x00"+item.SourceID] = item
	}
	covered := make(map[string]bool)
	for _, item := range byExact {
		covered[item.Scope+"\x00"+item.ModelID] = true
	}
	for _, owner := range rules.OwnerLifecycleExclusions {
		if !enabled[owner.Scope] || covered[owner.Scope+"\x00"+owner.ModelID] {
			continue
		}
		item := catalog.LifecycleExclusion{
			Scope: owner.Scope, ModelID: owner.ModelID, Status: "owner_confirmed_unavailable",
			SourceTitle: "Owner-confirmed model availability", Excerpt: owner.Evidence, OwnerRule: true,
		}
		byExact[item.Scope+"\x00"+item.ModelID+"\x00owner"] = item
	}
	out := make([]catalog.LifecycleExclusion, 0, len(byExact))
	for _, item := range byExact {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		if out[i].ModelID != out[j].ModelID {
			return out[i].ModelID < out[j].ModelID
		}
		return out[i].SourceID < out[j].SourceID
	})
	return out
}

func (d Discoverer) waitForCurrentRefresh(ctx context.Context, client AdminAPI, current adminapi.RefreshStatus, now func() time.Time) (adminapi.RefreshStatus, error) {
	maxWait := d.RefreshWait
	if maxWait <= 0 {
		maxWait = 20 * time.Minute
	}
	poll := d.PollInterval
	if poll <= 0 {
		poll = 30 * time.Second
	}
	deadline := now().Add(maxWait)
	for !NativeRefreshCurrent(current, now()) {
		if !now().Before(deadline) {
			return adminapi.RefreshStatus{}, errors.New("run stopped: today's Asia/Shanghai native refresh did not complete before the bounded wait expired")
		}
		sleep := d.Sleep
		if sleep == nil {
			sleep = func(ctx context.Context, duration time.Duration) error {
				timer := time.NewTimer(duration)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timer.C:
					return nil
				}
			}
		}
		if err := sleep(ctx, poll); err != nil {
			return adminapi.RefreshStatus{}, errors.New("run stopped while waiting for native refresh")
		}
		var err error
		current, err = client.RefreshStatus(ctx)
		if err != nil {
			return adminapi.RefreshStatus{}, err
		}
	}
	return current, nil
}

func (d Discoverer) waitForManualOnlyRefresh(ctx context.Context, client AdminAPI, current adminapi.RefreshStatus, now func() time.Time) (adminapi.RefreshStatus, error) {
	maxWait := d.RefreshWait
	if maxWait <= 0 {
		maxWait = 20 * time.Minute
	}
	poll := d.PollInterval
	if poll <= 0 {
		poll = 30 * time.Second
	}
	deadline := now().Add(maxWait)
	for !ManualOnlyRefreshCurrent(current, now()) {
		if !now().Before(deadline) {
			return adminapi.RefreshStatus{}, errors.New("run stopped: today's completed manual-only refresh was not available before the bounded wait expired")
		}
		sleep := d.Sleep
		if sleep == nil {
			sleep = func(ctx context.Context, duration time.Duration) error {
				timer := time.NewTimer(duration)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timer.C:
					return nil
				}
			}
		}
		if err := sleep(ctx, poll); err != nil {
			return adminapi.RefreshStatus{}, errors.New("run stopped while waiting for today's completed manual-only refresh")
		}
		var err error
		current, err = client.RefreshStatus(ctx)
		if err != nil {
			return adminapi.RefreshStatus{}, err
		}
	}
	return current, nil
}

func ManualOnlyRefreshCurrent(status adminapi.RefreshStatus, now time.Time) bool {
	if !status.Enabled || status.Schedule != "04:00" || status.Timezone != "Asia/Shanghai" || status.StatusSource != "postgres" || status.RunStatus != "completed" || status.LastScheduledAt == nil || status.LastFinishedAt == nil {
		return false
	}
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return false
	}
	localNow := now.In(loc)
	scheduled := status.LastScheduledAt.In(loc)
	finished := status.LastFinishedAt.In(loc)
	return !scheduled.After(localNow) && !finished.Before(scheduled) && !finished.After(localNow) &&
		scheduled.Format("2006-01-02") == localNow.Format("2006-01-02") &&
		finished.Format("2006-01-02") == localNow.Format("2006-01-02") &&
		scheduled.Hour() == 4 && scheduled.Minute() == 0
}

func manualOnlySkippedRows(status adminapi.RefreshStatus) (map[int64]adminapi.AccountRunStatus, bool) {
	rows := make(map[int64]adminapi.AccountRunStatus, len(status.Accounts))
	for _, row := range status.Accounts {
		if row.AccountID <= 0 || !knownNativeAccountRefreshStatus(row.Status) || row.SourceProfileID == "" {
			return nil, false
		}
		if _, exists := rows[row.AccountID]; exists {
			return nil, false
		}
		rows[row.AccountID] = row
	}
	return rows, len(rows) > 0
}

func knownNativeAccountRefreshStatus(status string) bool {
	switch status {
	case "completed", "succeeded", "failed", "unsupported", "skipped":
		return true
	default:
		return false
	}
}

func ManualOnlySkippedAccountIDs(status adminapi.RefreshStatus) ([]int64, error) {
	rows, ok := manualOnlySkippedRows(status)
	if !ok {
		return nil, errors.New("native refresh account rows are incomplete or duplicated")
	}
	ids := make([]int64, 0)
	for id, row := range rows {
		if row.SourceProfileID == "manual_only" && row.Status == "skipped" {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func NativeRefreshCurrent(status adminapi.RefreshStatus, now time.Time) bool {
	if !status.Enabled || status.LastFinishedAt == nil || status.Timezone != "Asia/Shanghai" {
		return false
	}
	if status.RunStatus != "completed" && status.RunStatus != "partial_failure" {
		return false
	}
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return false
	}
	finished := status.LastFinishedAt.In(loc)
	return !finished.After(now.In(loc)) && finished.Format("2006-01-02") == now.In(loc).Format("2006-01-02")
}

func warningCodesOnly(warnings []adminapi.CatalogWarning) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, warning := range warnings {
		code := warning.Code
		if !safeWarningCodePattern.MatchString(code) {
			code = "unclassified_warning"
		}
		if !seen[code] {
			seen[code] = true
			out = append(out, code)
		}
	}
	sort.Strings(out)
	return out
}

func catalogWarningCodesBlockMappingApply(codes []string) bool {
	for _, code := range codes {
		switch code {
		case warningModelMetadataIncomplete, warningModelMetadataPartial:
			// These native warnings describe capability metadata only. They do not
			// block an exact reviewed mapping, but never prove catalog completeness.
		default:
			return true
		}
	}
	return false
}

func normalizedOrigin(raw string) string {
	u, err := config.ValidateBaseURL(raw)
	if err != nil {
		return ""
	}
	return u.String()
}
