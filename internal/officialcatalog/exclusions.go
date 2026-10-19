package officialcatalog

import (
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const MaxLifecycleCacheAge = 7 * 24 * time.Hour
const MaxArkAccountCatalogAge = 24 * time.Hour
const MaxBailianModelStudioCatalogAge = 24 * time.Hour
const NearRetirementWindow = 60 * 24 * time.Hour

// AutomaticExclusions returns only exact lifecycle evidence from fresh sources
// explicitly audited to cover the accepted web/login union. Product-scoped
// retirement notices are report context and cannot delete vendor mappings.
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
			if !spec.lifecycleCoversAcceptedUnion {
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
	strongest := make(map[string]int)
	for _, item := range candidates {
		key := item.Provider + "\x00" + item.Scope + "\x00" + strings.ToLower(item.ModelID)
		if rank := lifecycleStatusRank(item.Status); rank > strongest[key] {
			strongest[key] = rank
		}
	}
	out := make([]LifecycleExclusion, 0, len(candidates))
	for _, item := range candidates {
		key := item.Provider + "\x00" + item.Scope + "\x00" + strings.ToLower(item.ModelID)
		if lifecycleStatusRank(item.Status) == strongest[key] {
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

func lifecycleStatusRank(status string) int {
	switch status {
	case "retired", "retired_with_compatibility_route":
		return 3
	case "deprecated":
		return 2
	case "announced_deprecated":
		return 1
	default:
		return 0
	}
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

// CurrentModelCatalog returns exact positive IDs from fresh official product
// pages. Catalog absence is negative evidence only when every declared source
// is explicitly audited to cover the full accepted web/login union.
func CurrentModelCatalog(syncResult StartupSyncResult, scope string, now time.Time) (AvailableModelCatalog, bool) {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	bySource := make(map[string]ProviderSync, len(syncResult.Providers))
	for _, result := range syncResult.Providers {
		bySource[result.SourceID] = result
	}
	var found *AvailableModelCatalog
	allDeclaredCatalogsComplete := true
	declaredCatalogs := 0
	for _, spec := range sourceManifest {
		if spec.scope != scope || !spec.catalog {
			continue
		}
		declaredCatalogs++
		allDeclaredCatalogsComplete = allDeclaredCatalogsComplete && spec.completeAcceptedUnion
		result, ok := bySource[spec.id]
		if !ok || result.Scope != spec.scope || result.Provider != spec.provider || result.Snapshot == nil || !eligibleSyncStatus(result.Status) || validateSnapshot(spec, *result.Snapshot) != nil {
			allDeclaredCatalogsComplete = false
			continue
		}
		page, pageOK := currentProductSourcePage(spec, *result.Snapshot, now)
		if !pageOK {
			allDeclaredCatalogsComplete = false
			continue
		}
		if found == nil {
			found = &AvailableModelCatalog{SourceID: spec.id, SourceIDs: []string{}, Provider: spec.provider, Scope: spec.scope, ModelIDs: []string{}, SourceURL: page.URL, SourceTitle: page.Title, RetrievedAt: page.FetchedAt, ContentSHA256: page.ContentSHA256}
		} else {
			if page.FetchedAt.After(found.RetrievedAt) {
				found.RetrievedAt = page.FetchedAt
			}
		}
		found.SourceIDs = append(found.SourceIDs, spec.id)
		retired := make(map[string]bool)
		for _, evidence := range productSurfaceRetirements(syncResult, spec.productSurface, now) {
			if productRetiredNow(evidence, now) {
				retired[strings.ToLower(strings.TrimSpace(evidence.ModelID))] = true
			}
		}
		for _, modelID := range page.AvailableModelIDs {
			if !retired[strings.ToLower(strings.TrimSpace(modelID))] {
				found.ModelIDs = append(found.ModelIDs, modelID)
			}
		}
	}
	if found == nil || declaredCatalogs == 0 {
		return AvailableModelCatalog{}, false
	}
	found.ModelIDs = uniqueStrings(found.ModelIDs)
	found.SourceIDs = uniqueStrings(found.SourceIDs)
	found.Complete = allDeclaredCatalogsComplete
	return *found, true
}

func currentProductSourcePage(spec sourceSpec, snapshot CatalogSnapshot, now time.Time) (CachedPage, bool) {
	if validateSnapshot(spec, snapshot) != nil || !freshEnough(snapshot.FetchedAt, now) {
		return CachedPage{}, false
	}
	for _, page := range snapshot.Pages {
		if page.URL == spec.rootURL && (len(page.AvailableModelIDs) > 0 || spec.catalogMayBeEmpty) && freshEnough(page.FetchedAt, now) {
			return page, true
		}
	}
	return CachedPage{}, false
}

// EvaluateProductAvailability returns exact positive support where a current
// official product list proves it. Absence is insufficient unless an audited
// complete accepted-union catalog or union-wide retirement proves otherwise.
func EvaluateProductAvailability(syncResult StartupSyncResult, modelIDs []string, now time.Time) []ProductModelAvailability {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	bySource := make(map[string]ProviderSync, len(syncResult.Providers))
	for _, result := range syncResult.Providers {
		bySource[result.SourceID] = result
	}
	ids := uniqueProductModelIDs(modelIDs)
	out := make([]ProductModelAvailability, 0, len(ids))
	for _, modelID := range ids {
		provider := productProviderForModelID(modelID)
		decision := ProductModelAvailability{ModelID: modelID, Provider: provider, Status: "insufficient_evidence", MatchKind: "none"}
		if provider == "" {
			out = append(out, decision)
			continue
		}
		var positive *ProductModelAvailability
		var completeAbsence *AvailableModelCatalog
		var versionFloor *AvailableModelCatalog
		var unionRetirement *LifecycleEvidence
		for _, evidence := range acceptedUnionRetirements(syncResult, provider, now) {
			if strings.EqualFold(strings.TrimSpace(evidence.ModelID), strings.TrimSpace(modelID)) && productRetiredNow(evidence, now) {
				copy := evidence
				unionRetirement = &copy
				break
			}
		}
		for _, spec := range sourceManifest {
			if !spec.catalog || spec.adapter != "" || spec.provider != provider {
				continue
			}
			result, ok := bySource[spec.id]
			if !ok || result.Scope != spec.scope || result.Provider != provider || result.Snapshot == nil || !eligibleSyncStatus(result.Status) {
				continue
			}
			page, pageOK := currentProductSourcePage(spec, *result.Snapshot, now)
			if !pageOK {
				continue
			}
			surfaceRetirements := productSurfaceRetirements(syncResult, spec.productSurface, now)
			retired := false
			for _, evidence := range surfaceRetirements {
				if productRetiredNow(evidence, now) && strings.EqualFold(strings.TrimSpace(evidence.ModelID), strings.TrimSpace(modelID)) {
					retired = true
					break
				}
			}
			matchKind := productCatalogMatchKind(spec.scope, modelID, page.AvailableModelIDs)
			floorIDs := make([]string, 0, len(page.AvailableModelIDs))
			for _, listedID := range page.AvailableModelIDs {
				listedRetired := false
				for _, evidence := range surfaceRetirements {
					if productRetiredNow(evidence, now) && strings.EqualFold(strings.TrimSpace(evidence.ModelID), strings.TrimSpace(listedID)) {
						listedRetired = true
						break
					}
				}
				if !listedRetired {
					floorIDs = append(floorIDs, listedID)
				}
			}
			if spec.versionFloorCatalog && olderThanProductVersionFloor(spec.scope, modelID, floorIDs) {
				versionFloor = &AvailableModelCatalog{
					SourceID: spec.id, SourceIDs: []string{spec.id}, Provider: spec.provider, Scope: spec.scope,
					ModelIDs: append([]string(nil), page.AvailableModelIDs...), SourceURL: page.URL, SourceTitle: page.Title,
					RetrievedAt: page.FetchedAt, ContentSHA256: page.ContentSHA256, Complete: false,
				}
			}
			if !retired && matchKind != "none" {
				positive = &ProductModelAvailability{
					ModelID: modelID, Provider: provider, Status: "available", MatchKind: matchKind,
					SourceIDs: []string{spec.id}, SourceURLs: []string{page.URL}, ContentSHA256: []string{page.ContentSHA256}, RetrievedAt: page.FetchedAt,
				}
				break
			}
			if scopeCatalog, scopeOK := CurrentModelCatalog(syncResult, spec.scope, now); scopeOK && scopeCatalog.Complete && !CurrentCatalogIncludes(spec.scope, modelID, scopeCatalog.ModelIDs) {
				copy := scopeCatalog
				completeAbsence = &copy
			}
		}
		if positive != nil && (unionRetirement != nil || completeAbsence != nil || versionFloor != nil) {
			// Fresh positive product evidence conflicts with a claimed union-wide
			// negative. Keep the mapping and block new import until the sources
			// agree; never turn the conflict into a deletion.
		} else if positive != nil {
			decision = *positive
		} else if unionRetirement != nil {
			decision.Status = "unavailable"
			decision.MatchKind = "accepted_union_retirement"
			decision.SourceIDs = []string{unionRetirement.SourceID}
			decision.SourceURLs = []string{unionRetirement.SourceURL}
			decision.ContentSHA256 = []string{unionRetirement.ContentSHA256}
			decision.RetrievedAt = unionRetirement.RetrievedAt
		} else if versionFloor != nil {
			decision.Status = "unavailable"
			decision.MatchKind = "accepted_union_version_floor"
			decision.SourceIDs = append([]string(nil), versionFloor.SourceIDs...)
			decision.SourceURLs = []string{versionFloor.SourceURL}
			decision.ContentSHA256 = []string{versionFloor.ContentSHA256}
			decision.RetrievedAt = versionFloor.RetrievedAt
		} else if completeAbsence != nil {
			decision.Status = "unavailable"
			decision.MatchKind = "accepted_union_absence"
			decision.SourceIDs = []string{completeAbsence.SourceID}
			decision.SourceURLs = []string{completeAbsence.SourceURL}
			decision.ContentSHA256 = []string{completeAbsence.ContentSHA256}
			decision.RetrievedAt = completeAbsence.RetrievedAt
		}
		out = append(out, decision)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModelID < out[j].ModelID })
	return out
}

type productVersion struct {
	major int
	minor int
}

// olderThanProductVersionFloor uses only explicitly designated signed-in
// product catalogs and canonical base IDs to identify the oldest currently
// listed version in a family. It never turns a newer or special model into a
// positive availability match.
func olderThanProductVersionFloor(scope, modelID string, catalogIDs []string) bool {
	candidate, ok := comparableProductVersion(scope, modelID, false)
	if !ok {
		return false
	}
	var floor *productVersion
	for _, id := range catalogIDs {
		version, ok := comparableProductVersion(scope, id, true)
		if !ok {
			continue
		}
		if floor == nil || version.major < floor.major || version.major == floor.major && version.minor < floor.minor {
			copy := version
			floor = &copy
		}
	}
	return floor != nil && (candidate.major < floor.major || candidate.major == floor.major && candidate.minor < floor.minor)
}

func comparableProductVersion(scope, modelID string, canonicalOnly bool) (productVersion, bool) {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	if scope == "openai_codex_chatgpt_login" {
		if strings.Contains(modelID, "codex-spark") {
			return productVersion{}, false
		}
		pattern := `^gpt-(\d+)\.(\d+)$`
		if !canonicalOnly {
			pattern = `^gpt-(\d+)\.(\d+)(?:-[a-z0-9][a-z0-9-]*)?$`
		}
		return parseProductVersion(pattern, modelID)
	}
	if scope == "xai_grok_web_login" {
		pattern := `^grok-(\d+)\.(\d+)$`
		if !canonicalOnly {
			pattern = `^grok-(\d+)\.(\d+)(?:-[a-z0-9][a-z0-9-]*)?$`
		}
		return parseProductVersion(pattern, modelID)
	}
	return productVersion{}, false
}

func parseProductVersion(pattern, modelID string) (productVersion, bool) {
	parts := regexp.MustCompile(pattern).FindStringSubmatch(modelID)
	if len(parts) != 3 {
		return productVersion{}, false
	}
	major, errMajor := strconv.Atoi(parts[1])
	minor, errMinor := strconv.Atoi(parts[2])
	if errMajor != nil || errMinor != nil {
		return productVersion{}, false
	}
	return productVersion{major: major, minor: minor}, true
}

// EvaluateArkAccountAvailability applies the current Ark account's complete
// Available-model response only to the exact Volcengine platform scope. A
// missing ID is negative evidence only after a successful, fresh, complete
// fetch; cached fallback and offline snapshots remain insufficient.
func EvaluateArkAccountAvailability(syncResult StartupSyncResult, platform string, modelIDs []string, now time.Time) []ProductModelAvailability {
	if platform != "volcengine" {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	spec, found := sourceForID("volcengine-ark-account-models")
	if !found {
		return insufficientPlatformAvailability(modelIDs)
	}
	var result *ProviderSync
	for i := range syncResult.Providers {
		if syncResult.Providers[i].SourceID == spec.id {
			result = &syncResult.Providers[i]
			break
		}
	}
	if result == nil || result.Provider != spec.provider || result.Scope != spec.scope || !accountCatalogFetchSucceeded(result.Status) || result.Snapshot == nil || validateSnapshot(spec, *result.Snapshot) != nil || !freshEnough(result.Snapshot.FetchedAt, now) || now.Sub(result.Snapshot.FetchedAt) > MaxArkAccountCatalogAge {
		return insufficientPlatformAvailability(modelIDs)
	}
	page, found := currentProductSourcePage(spec, *result.Snapshot, now)
	if !found {
		return insufficientPlatformAvailability(modelIDs)
	}
	available := make(map[string]bool, len(page.AvailableModelIDs))
	for _, id := range page.AvailableModelIDs {
		available[strings.ToLower(strings.TrimSpace(id))] = true
	}
	ids := uniqueProductModelIDs(modelIDs)
	out := make([]ProductModelAvailability, 0, len(ids))
	for _, modelID := range ids {
		status, match := "unavailable", "official_account_absence"
		if available[strings.ToLower(strings.TrimSpace(modelID))] {
			status, match = "available", "exact"
		}
		out = append(out, ProductModelAvailability{
			ModelID: modelID, Provider: "volcengine", Status: status, MatchKind: match,
			SourceIDs: []string{spec.id}, SourceURLs: []string{page.URL}, ContentSHA256: []string{page.ContentSHA256}, RetrievedAt: page.FetchedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModelID < out[j].ModelID })
	return out
}

func accountCatalogFetchSucceeded(status string) bool {
	switch status {
	case "updated", "unchanged", "coalesced":
		return true
	default:
		return false
	}
}

// EvaluateAlibabaModelStudioAvailability applies a fresh, complete regional
// Model Studio API catalog to Alibaba upstream model IDs. This does not assert
// web-product availability or account-level inference authorization.
func EvaluateAlibabaModelStudioAvailability(syncResult StartupSyncResult, platform, sourceBaseURL string, modelIDs []string, now time.Time) []ProductModelAvailability {
	if platform != "alibaba" {
		return nil
	}
	if !isBeijingModelStudioWorkspaceURL(sourceBaseURL) {
		return insufficientAlibabaAvailability(modelIDs)
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	spec, found := sourceForID("alibaba-model-studio-models")
	if !found {
		return insufficientAlibabaAvailability(modelIDs)
	}
	var result *ProviderSync
	for i := range syncResult.Providers {
		if syncResult.Providers[i].SourceID == spec.id {
			result = &syncResult.Providers[i]
			break
		}
	}
	if result == nil || result.Provider != spec.provider || result.Scope != spec.scope || !accountCatalogFetchSucceeded(result.Status) || result.Snapshot == nil || validateSnapshot(spec, *result.Snapshot) != nil || !freshEnough(result.Snapshot.FetchedAt, now) || now.Sub(result.Snapshot.FetchedAt) > MaxBailianModelStudioCatalogAge {
		return insufficientAlibabaAvailability(modelIDs)
	}
	available := make(map[string]bool)
	for _, page := range result.Snapshot.Pages {
		for _, id := range page.AvailableModelIDs {
			available[strings.ToLower(strings.TrimSpace(id))] = true
		}
	}
	ids := uniqueProductModelIDs(modelIDs)
	out := make([]ProductModelAvailability, 0, len(ids))
	for _, modelID := range ids {
		status, match := "unavailable", "official_api_catalog_absence"
		if available[strings.ToLower(strings.TrimSpace(modelID))] {
			status, match = "available", "exact"
		}
		out = append(out, ProductModelAvailability{
			ModelID: modelID, Provider: "alibaba", Status: status, MatchKind: match,
			SourceIDs: []string{spec.id}, SourceURLs: []string{spec.rootURL}, ContentSHA256: []string{result.Snapshot.ContentSHA256}, RetrievedAt: result.Snapshot.FetchedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModelID < out[j].ModelID })
	return out
}

func isBeijingModelStudioWorkspaceURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || !strings.EqualFold(parsed.Hostname(), "ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com") {
		return false
	}
	return parsed.Port() == "" || parsed.Port() == "443"
}

func insufficientAlibabaAvailability(modelIDs []string) []ProductModelAvailability {
	ids := uniqueProductModelIDs(modelIDs)
	out := make([]ProductModelAvailability, 0, len(ids))
	for _, modelID := range ids {
		out = append(out, ProductModelAvailability{ModelID: modelID, Provider: "alibaba", Status: "insufficient_evidence", MatchKind: "none"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModelID < out[j].ModelID })
	return out
}

func insufficientPlatformAvailability(modelIDs []string) []ProductModelAvailability {
	ids := uniqueProductModelIDs(modelIDs)
	out := make([]ProductModelAvailability, 0, len(ids))
	for _, modelID := range ids {
		out = append(out, ProductModelAvailability{ModelID: modelID, Provider: "volcengine", Status: "insufficient_evidence", MatchKind: "none"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModelID < out[j].ModelID })
	return out
}

func productProviderForModelID(modelID string) string {
	id := strings.ToLower(strings.TrimSpace(modelID))
	switch {
	case strings.HasPrefix(id, "gpt-"):
		return "openai"
	case strings.HasPrefix(id, "claude-"):
		return "anthropic"
	case strings.HasPrefix(id, "kimi-") || modelIDHasKimiNumericPrefix(id):
		return "kimi"
	case strings.HasPrefix(id, "deepseek-"):
		return "deepseek"
	case isQwenModelID(id), strings.HasPrefix(id, "qwq-"), strings.HasPrefix(id, "qvq-"), strings.HasPrefix(id, "wanx-"), strings.HasPrefix(id, "paraformer-"), strings.HasPrefix(id, "cosyvoice-"):
		return "alibaba"
	case strings.HasPrefix(id, "glm-"):
		return "zai"
	case strings.HasPrefix(id, "minimax-"):
		return "minimax"
	case strings.HasPrefix(id, "doubao-"), strings.HasPrefix(id, "seed-"):
		return "doubao"
	case strings.HasPrefix(id, "gemini-"):
		return "google"
	case len(id) > 2 && id[0:2] == "hy" && id[2] >= '0' && id[2] <= '9':
		return "tencent"
	case strings.HasPrefix(id, "mimo-"):
		return "xiaomi"
	case strings.HasPrefix(id, "muse-"):
		return "meta"
	case strings.HasPrefix(id, "longcat-"):
		return "longcat"
	case strings.HasPrefix(id, "grok-"):
		return "xai"
	default:
		return ""
	}
}

func isQwenModelID(id string) bool {
	if strings.HasPrefix(id, "qwen-") {
		return true
	}
	return len(id) > len("qwen") && strings.HasPrefix(id, "qwen") && id[len("qwen")] >= '0' && id[len("qwen")] <= '9'
}

func modelIDHasKimiNumericPrefix(id string) bool {
	if len(id) < 2 || id[0] != 'k' || id[1] < '0' || id[1] > '9' {
		return false
	}
	for _, r := range id[1:] {
		if (r < '0' || r > '9') && r != '-' && r != 'k' {
			return false
		}
	}
	return true
}

func productSurfaceRetirements(syncResult StartupSyncResult, surface string, now time.Time) []LifecycleEvidence {
	if surface == "" {
		return nil
	}
	providerForSurface := ""
	for _, spec := range sourceManifest {
		if spec.productSurface == surface {
			providerForSurface = spec.provider
			break
		}
	}
	bySource := make(map[string]ProviderSync, len(syncResult.Providers))
	for _, result := range syncResult.Providers {
		bySource[result.SourceID] = result
	}
	var out []LifecycleEvidence
	for _, spec := range sourceManifest {
		sameSurface := spec.productSurface == surface
		crossProductUnion := spec.lifecycleCoversAcceptedUnion && providerForSurface != "" && spec.provider == providerForSurface
		if (!sameSurface && !crossProductUnion) || spec.scope == "api" {
			continue
		}
		result, ok := bySource[spec.id]
		if !ok || result.Provider != spec.provider || result.Scope != spec.scope || result.Snapshot == nil || !eligibleSyncStatus(result.Status) || validateSnapshot(spec, *result.Snapshot) != nil || !freshEnough(result.Snapshot.FetchedAt, now) {
			continue
		}
		for _, evidence := range result.Snapshot.Evidence {
			if evidence.Scope == spec.scope && evidence.Provider == spec.provider && freshEnough(evidence.RetrievedAt, now) && exclusionEligible(evidence, now) {
				out = append(out, evidence)
			}
		}
	}
	return out
}

func acceptedUnionRetirements(syncResult StartupSyncResult, provider string, now time.Time) []LifecycleEvidence {
	var out []LifecycleEvidence
	seen := make(map[string]bool)
	for _, spec := range sourceManifest {
		if spec.provider != provider || !spec.lifecycleCoversAcceptedUnion || spec.productSurface == "" {
			continue
		}
		for _, evidence := range productSurfaceRetirements(syncResult, spec.productSurface, now) {
			if evidence.SourceID != spec.id {
				continue
			}
			key := spec.productSurface + "\x00" + strings.ToLower(evidence.ModelID) + "\x00" + evidence.Status
			if !seen[key] {
				seen[key] = true
				out = append(out, evidence)
			}
		}
	}
	return out
}

func productRetiredNow(evidence LifecycleEvidence, now time.Time) bool {
	switch evidence.Status {
	case "deprecated", "retired", "retired_with_compatibility_route":
		return true
	case "announced_deprecated":
		retirement, err := parseAnyDate(evidence.EffectiveAt)
		if err != nil {
			return false
		}
		today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
		retirement = time.Date(retirement.Year(), retirement.Month(), retirement.Day(), 0, 0, 0, 0, time.UTC)
		return !retirement.After(today)
	default:
		return false
	}
}

// CurrentCatalogIncludes compares an exact model ID or an explicitly reviewed
// product alias against an official product catalog. It intentionally does
// not infer availability from arbitrary suffixes or version prefixes.
func CurrentCatalogIncludes(scope, modelID string, catalogIDs []string) bool {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	for _, listed := range catalogIDs {
		if modelID == strings.ToLower(strings.TrimSpace(listed)) {
			return true
		}
	}
	for _, listed := range catalogIDs {
		if scope == "openai_codex_chatgpt_login" && explicitProductAlias(scope, strings.ToLower(strings.TrimSpace(listed)), modelID) {
			return true
		}
	}
	return false
}

// HasComparableModelFamily reports whether a model ID has a documented
// comparison path in a current catalog. The Codex catalog only establishes
// availability for GPT text/reasoning version families; it is not a complete
// ChatGPT web catalog for image, audio, realtime, or other product endpoints.
func HasComparableModelFamily(scope, modelID string, catalogIDs []string) bool {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	for _, listed := range catalogIDs {
		if modelID == strings.ToLower(strings.TrimSpace(listed)) {
			return true
		}
	}
	for _, listed := range catalogIDs {
		if scope == "openai_codex_chatgpt_login" && explicitProductAlias(scope, strings.ToLower(strings.TrimSpace(listed)), modelID) {
			return true
		}
	}
	return false
}

// This list is deliberately exact and product-scoped. A suffix can be added
// only after an official product source documents that exact alias.
var explicitProductAliases = map[string]map[string][]string{
	"openai_codex_chatgpt_login": {
		"gpt-5.6": {"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"},
		"gpt-6":   {"gpt-6-astra", "gpt-6-sol", "gpt-6-luna"},
		"gpt-6.1": {"gpt-6.1-sol"},
	},
}

func explicitProductAlias(scope, listed, modelID string) bool {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	for _, alias := range explicitProductAliases[scope][listed] {
		if modelID == alias {
			return true
		}
	}
	return false
}

func productCatalogMatchKind(scope, modelID string, catalogIDs []string) string {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	for _, listed := range catalogIDs {
		listed = strings.ToLower(strings.TrimSpace(listed))
		if modelID == listed {
			return "exact"
		}
		if explicitProductAlias(scope, listed, modelID) {
			return "explicit_alias"
		}
	}
	return "none"
}

func uniqueProductModelIDs(values []string) []string {
	byFolded := make(map[string]string, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := byFolded[key]; !exists {
			byFolded[key] = value
		}
	}
	out := make([]string, 0, len(byFolded))
	for _, value := range byFolded {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

func freshEnough(timestamp, now time.Time) bool {
	return !timestamp.IsZero() && !timestamp.After(now) && now.Sub(timestamp) <= MaxLifecycleCacheAge
}

func exclusionEligible(e LifecycleEvidence, now time.Time) bool {
	switch e.Status {
	case "deprecated", "retired", "retired_with_compatibility_route":
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
	// Only a source check completed in this run may authorize a catalog or
	// lifecycle decision. Last-good snapshots remain useful for diagnostics,
	// but a failed current fetch cannot prove current availability or absence.
	case "updated", "unchanged", "coalesced":
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
