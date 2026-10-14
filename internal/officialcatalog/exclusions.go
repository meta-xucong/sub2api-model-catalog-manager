package officialcatalog

import (
	"sort"
	"time"
)

const MaxLifecycleCacheAge = 7 * 24 * time.Hour
const NearRetirementWindow = 60 * 24 * time.Hour

// AutomaticExclusions returns only exact, terminal or near-terminal model IDs
// from fresh snapshots whose product scopes were explicitly enabled by the
// matched source profile. A failed/old/future-dated source contributes nothing.
func AutomaticExclusions(syncResult StartupSyncResult, enabledScopes []string, now time.Time) []LifecycleExclusion {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	enabled := map[string]bool{}
	for _, scope := range enabledScopes {
		if isProductScope(scope) {
			enabled[scope] = true
		}
	}
	if len(enabled) == 0 {
		return []LifecycleExclusion{}
	}
	for scope := range enabled {
		if !LifecycleScopeReady(syncResult, scope, now) {
			return []LifecycleExclusion{}
		}
	}
	bySource := make(map[string]ProviderSync, len(syncResult.Providers))
	for _, result := range syncResult.Providers {
		bySource[result.SourceID] = result
	}
	var candidates []LifecycleExclusion
	for _, spec := range sourceManifest {
		if spec.scope == "api" || !enabled[spec.scope] {
			continue
		}
		result, ok := bySource[spec.id]
		if !ok || result.Scope != spec.scope || result.Provider != spec.provider || result.Snapshot == nil || !eligibleSyncStatus(result.Status) {
			continue
		}
		snapshot := *result.Snapshot
		if validateSnapshot(spec, snapshot) != nil || !freshEnough(snapshot.FetchedAt, now) {
			continue
		}
		freshEvidence := true
		for _, page := range snapshot.Pages {
			if !freshEnough(page.FetchedAt, now) {
				freshEvidence = false
				break
			}
		}
		if !freshEvidence {
			continue
		}
		for _, evidence := range snapshot.Evidence {
			if evidence.SourceID != spec.id || evidence.Scope != spec.scope || evidence.Provider != spec.provider || !freshEnough(evidence.RetrievedAt, now) {
				continue
			}
			if !exclusionEligible(evidence, now) {
				continue
			}
			candidates = append(candidates, LifecycleExclusion{
				Provider: evidence.Provider, SourceID: evidence.SourceID, Scope: evidence.Scope, ModelID: evidence.ModelID,
				Status: evidence.Status, EffectiveAt: evidence.EffectiveAt, Replacement: evidence.Replacement,
				SourceURL: evidence.SourceURL, SourceTitle: evidence.SourceTitle, RetrievedAt: evidence.RetrievedAt,
				ContentSHA256: evidence.ContentSHA256, Excerpt: evidence.Excerpt,
			})
		}
	}
	conflicts := make(map[string]bool)
	statuses := make(map[string]map[string]bool)
	for _, item := range candidates {
		key := item.Provider + "\x00" + item.Scope + "\x00" + item.ModelID
		if statuses[key] == nil {
			statuses[key] = map[string]bool{}
		}
		statuses[key][item.Status] = true
	}
	for key, values := range statuses {
		conflicts[key] = len(values) > 1
	}
	out := make([]LifecycleExclusion, 0, len(candidates))
	for _, item := range candidates {
		key := item.Provider + "\x00" + item.Scope + "\x00" + item.ModelID
		if !conflicts[key] {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.ModelID != b.ModelID {
			return a.ModelID < b.ModelID
		}
		return a.SourceID < b.SourceID
	})
	return out
}

// LifecycleScopeReady is all-or-nothing across the fixed official sources for
// a product. This prevents a live proxy list from reintroducing retired IDs
// when one required official catalog page is unavailable or stale.
func LifecycleScopeReady(syncResult StartupSyncResult, scope string, now time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if !isProductScope(scope) {
		return false
	}
	bySource := make(map[string]ProviderSync, len(syncResult.Providers))
	for _, result := range syncResult.Providers {
		bySource[result.SourceID] = result
	}
	found := false
	for _, spec := range sourceManifest {
		if spec.scope != scope {
			continue
		}
		found = true
		result, ok := bySource[spec.id]
		if !ok || result.Scope != spec.scope || result.Provider != spec.provider || result.Snapshot == nil || !eligibleSyncStatus(result.Status) {
			return false
		}
		snapshot := *result.Snapshot
		if validateSnapshot(spec, snapshot) != nil || !freshEnough(snapshot.FetchedAt, now) {
			return false
		}
		for _, page := range snapshot.Pages {
			if !freshEnough(page.FetchedAt, now) {
				return false
			}
		}
		for _, evidence := range snapshot.Evidence {
			if !freshEnough(evidence.RetrievedAt, now) {
				return false
			}
		}
	}
	return found
}

func freshEnough(timestamp, now time.Time) bool {
	return !timestamp.IsZero() && !timestamp.After(now) && now.Sub(timestamp) <= MaxLifecycleCacheAge
}

func exclusionEligible(e LifecycleEvidence, now time.Time) bool {
	switch e.Status {
	case "retired", "retired_with_compatibility_route":
		return true
	case "announced_deprecated":
		retirement, err := parseAnyDate(e.EffectiveAt)
		if err != nil {
			return false
		}
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		retirement = time.Date(retirement.Year(), retirement.Month(), retirement.Day(), 0, 0, 0, 0, time.UTC)
		return !retirement.Before(today) && !retirement.After(today.Add(NearRetirementWindow))
	default:
		return false
	}
}

func eligibleSyncStatus(status string) bool {
	switch status {
	case "updated", "unchanged", "coalesced", "stale", "offline_cached":
		return true
	default:
		return false
	}
}

func isProductScope(scope string) bool {
	switch scope {
	case "openai_codex_chatgpt_login", "anthropic_claude_code_login", "kimi_code_login":
		return true
	default:
		return false
	}
}
