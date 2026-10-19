package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"sub2api-model-catalog-manager/internal/modelversion"
	"sub2api-model-catalog-manager/internal/state"
)

type Completeness string

const (
	CompletenessUnknown  Completeness = "unknown"
	CompletenessComplete Completeness = "complete"
)

type Input struct {
	AccountID                    int64
	Source                       Source
	SourceIdentityAddPolicy      string
	IdentityCatalogPolicy        string
	AllowIdentityCatalogSync     bool
	CurrentMapping               map[string]string
	ManagedMappings              map[string]state.ManagedMapping
	LiveModels                   []string
	LiveListAvailable            bool
	Completeness                 Completeness
	CompletenessProfileID        string
	DirectoryHash                string
	LifecycleScopes              []string
	LifecycleExclusions          []LifecycleExclusion
	ProductAvailabilityEnforced  bool
	ProductAvailability          []ProductModelAvailability
	RequireOfficialSelectability bool
	OfficialSelectabilityScope   string
	PruneMissingMappings         bool
	Now                          time.Time
}

type LifecycleExclusion struct {
	Scope         string    `json:"scope"`
	ModelID       string    `json:"model_id"`
	Status        string    `json:"status"`
	EffectiveAt   string    `json:"effective_at,omitempty"`
	Replacement   string    `json:"replacement,omitempty"`
	SourceID      string    `json:"source_id,omitempty"`
	SourceURL     string    `json:"source_url,omitempty"`
	SourceTitle   string    `json:"source_title,omitempty"`
	RetrievedAt   time.Time `json:"retrieved_at,omitempty"`
	ContentSHA256 string    `json:"content_sha256,omitempty"`
	Excerpt       string    `json:"excerpt,omitempty"`
	OwnerRule     bool      `json:"owner_rule,omitempty"`
}

// ProductModelAvailability is bound into the approved plan so exact positive
// product evidence, and the absence of such evidence, cannot change between
// discovery and apply without changing the plan hash.
type ProductModelAvailability struct {
	ModelID             string    `json:"model_id"`
	Provider            string    `json:"provider,omitempty"`
	Status              string    `json:"status"`
	MatchKind           string    `json:"match_kind"`
	VersionFloorModelID string    `json:"version_floor_model_id,omitempty"`
	SourceIDs           []string  `json:"source_ids,omitempty"`
	SourceURLs          []string  `json:"source_urls,omitempty"`
	ContentSHA256       []string  `json:"content_sha256,omitempty"`
	RetrievedAt         time.Time `json:"retrieved_at,omitempty"`
}

var (
	xAIVersionFloorModelID = regexp.MustCompile(`^grok-\d+\.\d+(?:-[a-z0-9][a-z0-9-]*)?$`)
)

type Change struct {
	Action   string `json:"action"`
	PublicID string `json:"public_id"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
	RuleKind string `json:"rule_kind"`
	Evidence string `json:"evidence,omitempty"`
	Reason   string `json:"reason"`
}

type Plan struct {
	AccountID                       int64                      `json:"account_id"`
	Source                          Source                     `json:"source"`
	SourceFingerprint               string                     `json:"source_fingerprint"`
	BeforeHash                      string                     `json:"before_mapping_hash"`
	DirectoryHash                   string                     `json:"directory_hash,omitempty"`
	CatalogObservedAt               time.Time                  `json:"catalog_observed_at"`
	CompletenessProfileID           string                     `json:"completeness_profile_id,omitempty"`
	SourceIdentityAddPolicy         string                     `json:"source_identity_add_policy"`
	IdentityCatalogPolicy           string                     `json:"identity_catalog_policy,omitempty"`
	LifecycleScopes                 []string                   `json:"lifecycle_scopes,omitempty"`
	LifecycleExclusions             []LifecycleExclusion       `json:"lifecycle_exclusions,omitempty"`
	LifecycleEvidenceSHA256         string                     `json:"lifecycle_evidence_sha256"`
	ProductAvailabilityEnforced     bool                       `json:"product_availability_enforced,omitempty"`
	ProductAvailability             []ProductModelAvailability `json:"product_availability,omitempty"`
	ProductAvailabilitySHA256       string                     `json:"product_availability_sha256,omitempty"`
	OfficialSelectabilityScope      string                     `json:"official_selectability_scope,omitempty"`
	OfficialSelectabilitySHA256     string                     `json:"official_selectability_sha256,omitempty"`
	OfficialSelectabilityObservedAt time.Time                  `json:"official_selectability_observed_at,omitempty"`
	OfficialSelectabilityExpiresAt  time.Time                  `json:"official_selectability_expires_at,omitempty"`
	CatalogModels                   []string                   `json:"catalog_models"`
	CatalogWarningCodes             []string                   `json:"catalog_warning_codes"`
	ApplyEligible                   bool                       `json:"apply_eligible"`
	DiscoveryReason                 string                     `json:"discovery_reason,omitempty"`
	RulesHash                       string                     `json:"rules_hash"`
	Completeness                    Completeness               `json:"catalog_completeness"`
	LiveListAvailable               bool                       `json:"live_list_available"`
	Before                          map[string]string          `json:"before_mapping"`
	After                           map[string]string          `json:"after_mapping"`
	Changes                         []Change                   `json:"changes"`
	Conflicts                       []string                   `json:"conflicts"`
	UnreviewedModels                []string                   `json:"unreviewed_models"`
	CreatedAt                       time.Time                  `json:"created_at"`
	AbsenceCountsBefore             map[string]int             `json:"absence_counts_before"`
	AbsenceCountsAfter              map[string]int             `json:"absence_counts_after"`
}

func Normalize(rules Rules, input Input, prior state.Account) (Plan, error) {
	if err := rules.Validate(); err != nil {
		return Plan{}, err
	}
	if input.AccountID <= 0 || input.CurrentMapping == nil {
		return Plan{}, errors.New("invalid normalization input")
	}
	if input.Completeness != CompletenessUnknown && input.Completeness != CompletenessComplete {
		return Plan{}, errors.New("unknown catalog completeness value")
	}
	if input.SourceIdentityAddPolicy == "" {
		input.SourceIdentityAddPolicy = "report_only"
	}
	if input.SourceIdentityAddPolicy != "report_only" && input.SourceIdentityAddPolicy != "add_exact" {
		return Plan{}, errors.New("invalid source identity add policy")
	}
	// Completeness is accepted only for an implemented parser profile. No such
	// profile is currently registered; an unrecognized ID fails closed to unknown.
	if input.Completeness != CompletenessUnknown {
		if input.CompletenessProfileID == "" {
			input.Completeness = CompletenessUnknown
		} else if _, ok := implementedCompleteProfiles[input.CompletenessProfileID]; !ok {
			input.Completeness = CompletenessUnknown
		}
	}
	plan := Plan{
		AccountID:               input.AccountID,
		Source:                  input.Source,
		SourceFingerprint:       SourceFingerprint(input.Source),
		DirectoryHash:           input.DirectoryHash,
		CatalogObservedAt:       time.Now().UTC(),
		CompletenessProfileID:   input.CompletenessProfileID,
		SourceIdentityAddPolicy: input.SourceIdentityAddPolicy,
		IdentityCatalogPolicy: func() string {
			if input.AllowIdentityCatalogSync {
				return input.IdentityCatalogPolicy
			}
			return ""
		}(),
		LifecycleScopes:             append([]string{}, input.LifecycleScopes...),
		LifecycleExclusions:         append([]LifecycleExclusion{}, input.LifecycleExclusions...),
		ProductAvailabilityEnforced: input.ProductAvailabilityEnforced,
		ProductAvailability:         cloneProductAvailability(input.ProductAvailability),
		CatalogModels:               append([]string{}, input.LiveModels...),
		CatalogWarningCodes:         []string{},
		ApplyEligible:               true,
		Completeness:                input.Completeness,
		LiveListAvailable:           input.LiveListAvailable,
		Before:                      cloneMapping(input.CurrentMapping),
		After:                       cloneMapping(input.CurrentMapping),
		AbsenceCountsBefore:         cloneAbsenceCounts(prior.AbsenceCounts),
		AbsenceCountsAfter:          cloneAbsenceCounts(prior.AbsenceCounts),
		Changes:                     []Change{}, Conflicts: []string{}, UnreviewedModels: []string{},
		CreatedAt: time.Now().UTC(),
	}
	sort.Strings(plan.LifecycleScopes)
	for i := 1; i < len(plan.LifecycleScopes); i++ {
		if plan.LifecycleScopes[i-1] == plan.LifecycleScopes[i] {
			return Plan{}, errors.New("lifecycle scopes contain duplicates")
		}
	}
	lifecycleDigest, err := LifecycleEvidenceDigest(plan.LifecycleScopes, plan.LifecycleExclusions)
	if err != nil {
		return Plan{}, err
	}
	plan.LifecycleEvidenceSHA256 = lifecycleDigest
	if input.ProductAvailabilityEnforced {
		availabilityDigest, availabilityErr := ProductAvailabilityDigest(plan.ProductAvailability)
		if availabilityErr != nil {
			return Plan{}, availabilityErr
		}
		plan.ProductAvailabilitySHA256 = availabilityDigest
	} else if len(plan.ProductAvailability) != 0 {
		return Plan{}, errors.New("product availability evidence requires enforcement")
	}
	plan.BeforeHash, err = MappingHash(input.CurrentMapping)
	if err != nil {
		return Plan{}, err
	}
	plan.RulesHash, err = canonicalHash(rules)
	if err != nil {
		return Plan{}, err
	}
	if input.Source.AccountID != 0 && input.Source.AccountID != input.AccountID {
		return Plan{}, errors.New("source account ID does not match plan account")
	}
	selectable := map[string]bool(nil)
	if input.RequireOfficialSelectability {
		snapshot, found := rules.OfficialSelectabilityForScope(input.OfficialSelectabilityScope)
		if !found {
			plan.ApplyEligible = false
			plan.DiscoveryReason = "official account selectability snapshot is missing for the matched source profile"
			plan.Conflicts = append(plan.Conflicts, "official account selectability is the only model eligibility authority; no exact approved snapshot is available")
			plan.OfficialSelectabilityScope = input.OfficialSelectabilityScope
			plan.OfficialSelectabilitySHA256 = hashMissingSelectability(input.Source, input.OfficialSelectabilityScope)
			return plan, nil
		}
		plan.OfficialSelectabilityScope = snapshot.Scope
		now := input.Now.UTC()
		if now.IsZero() {
			now = time.Now().UTC()
		}
		if !snapshot.Complete || snapshot.ObservedAt.After(now) || !snapshot.ExpiresAt.After(now) || now.Sub(snapshot.ObservedAt) > OfficialSelectabilityMaxAge {
			plan.ApplyEligible = false
			plan.DiscoveryReason = "official account selectability snapshot is incomplete, future-dated, or expired"
			plan.Conflicts = append(plan.Conflicts, "official account selectability snapshot is not current; no mapping changes are permitted")
			plan.OfficialSelectabilitySHA256 = hashSelectability(snapshot)
			plan.OfficialSelectabilityObservedAt = snapshot.ObservedAt.UTC()
			plan.OfficialSelectabilityExpiresAt = snapshot.ExpiresAt.UTC()
			return plan, nil
		}
		plan.OfficialSelectabilitySHA256 = hashSelectability(snapshot)
		plan.OfficialSelectabilityObservedAt = snapshot.ObservedAt.UTC()
		plan.OfficialSelectabilityExpiresAt = snapshot.ExpiresAt.UTC()
		ids := append([]string{}, snapshot.ModelIDs...)
		sort.Strings(ids)
		selectable = make(map[string]bool, len(ids))
		for _, id := range ids {
			selectable[id] = true
		}
	}
	liveUsable := input.LiveListAvailable && len(input.LiveModels) > 0
	live := make(map[string]bool, len(input.LiveModels))
	for _, id := range input.LiveModels {
		if !validID(id) {
			plan.Conflicts = append(plan.Conflicts, "live catalog contains an invalid model ID")
			return plan, nil
		}
		if selectable == nil || selectable[id] {
			live[id] = true
		}
	}
	// Version families are account-scoped because a preferred upstream ID and
	// its hide actions are evidence about one exact credential/source binding.
	// SourceMatches permits account_id=0 as a wildcard for other rule types;
	// do not let that broader matching semantics apply to version families.
	for _, family := range rules.VersionFamilies {
		if !sameSourceEndpoint(family.Source, input.Source) {
			continue
		}
		if input.AccountID <= 0 || family.Source.AccountID <= 0 {
			plan.ApplyEligible = false
			plan.DiscoveryReason = "version family does not name the exact positive account ID"
			plan.Conflicts = append(plan.Conflicts, "version family requires an exact positive account ID matching the normalization account: "+family.PublicID)
		}
	}
	if len(plan.Conflicts) > 0 {
		sort.Strings(plan.Conflicts)
		return plan, nil
	}
	productStatus := make(map[string]string, len(plan.ProductAvailability))
	probeStatus := make(map[string]string, len(plan.ProductAvailability))
	for _, evidence := range plan.ProductAvailability {
		if err := validateProductModelAvailability(evidence); err != nil {
			return Plan{}, err
		}
		accountCatalogSource := ""
		regionalCatalogSource := ""
		for _, sourceID := range evidence.SourceIDs {
			if sourceID == "volcengine-ark-account-models" {
				accountCatalogSource = sourceID
			}
			if sourceID == "alibaba-model-studio-models" {
				regionalCatalogSource = sourceID
			}
		}
		if evidence.MatchKind == "official_account_absence" && accountCatalogSource == "" || evidence.MatchKind == "official_api_catalog_absence" && regionalCatalogSource == "" {
			return Plan{}, errors.New("official catalog absence evidence is not bound to a recognized exact catalog")
		}
		if accountCatalogSource != "" || regionalCatalogSource != "" {
			sourceID := accountCatalogSource
			if sourceID == "" {
				sourceID = regionalCatalogSource
			}
			expectedPlatform, expectedProvider, expectedURL := "", "", ""
			switch sourceID {
			case "volcengine-ark-account-models":
				expectedPlatform, expectedProvider = "volcengine", "volcengine"
				expectedURL = "https://ark.cn-beijing.volcengineapi.com/?Action=ListModelActivations&Version=2024-01-01"
			case "alibaba-model-studio-models":
				expectedPlatform, expectedProvider = "alibaba", "alibaba"
				expectedURL = "https://ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com/api/v1/models?page_no=1&page_size=200"
			}
			if sourceID == "alibaba-model-studio-models" && !matchesBeijingModelStudioWorkspace(input.Source.BaseURL) {
				return Plan{}, errors.New("official model availability evidence is outside the configured Alibaba workspace")
			}
			if input.Source.Platform != expectedPlatform || evidence.Provider != expectedProvider || len(evidence.SourceIDs) != 1 || evidence.SourceIDs[0] != sourceID || len(evidence.SourceURLs) != 1 || evidence.SourceURLs[0] != expectedURL {
				return Plan{}, errors.New("official model availability evidence is not bound to its exact provider and source")
			}
		}
		key := strings.ToLower(evidence.ModelID)
		if _, duplicate := productStatus[key]; duplicate {
			return Plan{}, errors.New("product availability contains duplicate model IDs")
		}
		if evidence.MatchKind == "account_probe_success" || evidence.MatchKind == "all_account_probes_failed" || evidence.MatchKind == "account_probe_ignored" {
			// Probe conclusions apply only to the exact requested upstream ID.
			// Keep the folded product status conservative so this evidence cannot
			// authorize lifecycle, retired-catalog, or alias removal for a case
			// variant of the candidate.
			probeStatus[evidence.ModelID] = evidence.Status
			productStatus[key] = "insufficient_evidence"
		} else {
			productStatus[key] = evidence.Status
		}
	}
	productAvailable := func(modelID string) bool {
		if status, found := probeStatus[modelID]; found {
			return status == "available"
		}
		status, found := productStatus[strings.ToLower(modelID)]
		return !input.ProductAvailabilityEnforced || !found || status == "available"
	}
	productEvidenceKnown := func(modelID string) bool {
		_, found := productStatus[strings.ToLower(modelID)]
		return input.ProductAvailabilityEnforced && found
	}
	managed := input.ManagedMappings
	if managed == nil {
		managed = prior.ManagedMappings
	}
	if managed == nil {
		managed = map[string]state.ManagedMapping{}
	}
	allowChanges := func(key string) bool {
		owner, ok := managed[key]
		if !ok || owner.SourceFingerprint != plan.SourceFingerprint {
			return false
		}
		current, exists := input.CurrentMapping[key]
		return exists && current == owner.LastAppliedValue
	}
	if input.ProductAvailabilityEnforced {
		unavailable := make(map[string]ProductModelAvailability)
		probeUnavailable := make(map[string]ProductModelAvailability)
		for _, evidence := range plan.ProductAvailability {
			if evidence.Status == "unavailable" {
				if evidence.MatchKind == "all_account_probes_failed" {
					probeUnavailable[evidence.ModelID] = evidence
				} else {
					unavailable[strings.ToLower(evidence.ModelID)] = evidence
				}
			}
		}
		for modelID := range live {
			if _, isUnavailable := probeUnavailable[modelID]; isUnavailable {
				delete(live, modelID)
			} else if _, isUnavailable := unavailable[strings.ToLower(modelID)]; isUnavailable {
				delete(live, modelID)
			}
		}
		removeKeys := make([]string, 0)
		for publicID, upstreamID := range plan.After {
			if IsWildcard(publicID) || IsWildcard(upstreamID) {
				continue
			}
			availability, isUnavailable := probeUnavailable[upstreamID]
			if !isUnavailable {
				availability, isUnavailable = unavailable[strings.ToLower(upstreamID)]
			}
			if !isUnavailable {
				continue
			}
			productUnionEvidence := authorizesUnmanagedProductRemoval(availability)
			if !allowChanges(publicID) && !productUnionEvidence {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "official product-availability evidence cannot remove an unmanaged or drifted mapping: "+publicID)
				continue
			}
			removeKeys = append(removeKeys, publicID)
		}
		if len(plan.Conflicts) > 0 {
			sort.Strings(plan.Conflicts)
			plan.DiscoveryReason = "official product-availability evidence conflicts with an unmanaged or drifted mapping"
			return plan, nil
		}
		sort.Strings(removeKeys)
		for _, publicID := range removeKeys {
			upstreamID := plan.After[publicID]
			availability, isProbeUnavailable := probeUnavailable[upstreamID]
			if !isProbeUnavailable {
				availability = unavailable[strings.ToLower(upstreamID)]
			}
			delete(plan.After, publicID)
			reason := "official evidence establishes that the model is unavailable across the accepted product union"
			if availability.MatchKind == "all_account_probes_failed" {
				reason = "exact-model inference failed on every relevant 404token account in the completed screening scope"
			}
			if availability.MatchKind == "accepted_union_version_floor" {
				reason = "the model version is older than the lowest currently listed canonical version in the official product catalog"
			}
			if availability.MatchKind == "official_account_absence" || availability.MatchKind == "official_api_catalog_absence" {
				switch availability.SourceIDs[0] {
				case "volcengine-ark-account-models":
					reason = "the official Ark inventory does not list this model as available for the configured Volcengine account"
				case "alibaba-model-studio-models":
					reason = "the official Beijing Model Studio API catalog does not list this model"
				}
			}
			plan.Changes = append(plan.Changes, Change{
				Action: "remove", PublicID: publicID, Before: upstreamID, RuleKind: "official_product_availability",
				Evidence: strings.Join(availability.SourceIDs, ","),
				Reason:   reason,
			})
		}
	}
	if input.PruneMissingMappings && liveUsable && selectable == nil {
		keys := make([]string, 0, len(plan.After))
		for publicID := range plan.After {
			keys = append(keys, publicID)
		}
		sort.Strings(keys)
		for _, publicID := range keys {
			upstreamID := plan.After[publicID]
			if IsWildcard(publicID) || IsWildcard(upstreamID) || live[upstreamID] {
				continue
			}
			if !allowChanges(publicID) {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "404token upstream catalog cannot remove an unmanaged or drifted mapping: "+publicID)
				continue
			}
			delete(plan.After, publicID)
			plan.Changes = append(plan.Changes, Change{
				Action: "remove", PublicID: publicID, Before: upstreamID,
				RuleKind: "live_catalog_absence", Evidence: "successful 404token native upstream catalog sync",
				Reason: "exact upstream model ID is absent from the refreshed 404token model list",
			})
		}
		if len(plan.Conflicts) > 0 {
			sort.Strings(plan.Conflicts)
			plan.DiscoveryReason = "404token upstream catalog conflicts with an unmanaged or drifted mapping"
			return plan, nil
		}
	}
	// The current official account selector is the sole retention authority.
	// Upstream catalog visibility and static retirement/family rules cannot
	// retain a model that the account cannot select. Existing mappings may be
	// removed only when this manager still owns their exact current value.
	if selectable != nil {
		keys := make([]string, 0, len(plan.After))
		for publicID := range plan.After {
			keys = append(keys, publicID)
		}
		sort.Strings(keys)
		for _, publicID := range keys {
			upstreamID := plan.After[publicID]
			// Wildcard routes are routing policy, not concrete selectable model
			// IDs. An account selector snapshot cannot certify or retire them.
			if IsWildcard(upstreamID) {
				continue
			}
			if selectable[upstreamID] {
				continue
			}
			if !allowChanges(publicID) {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "official account cannot select a model in an unmanaged or drifted mapping: "+publicID)
				continue
			}
			delete(plan.After, publicID)
			plan.Changes = append(plan.Changes, Change{Action: "remove", PublicID: publicID, Before: upstreamID, RuleKind: "official_selectability", Evidence: "complete current official account selectable-model snapshot", Reason: "model is absent from the official account's current selectable model list"})
		}
		if len(plan.Conflicts) > 0 {
			sort.Strings(plan.Conflicts)
			plan.DiscoveryReason = "official selectability conflicts with an unmanaged or drifted mapping"
			return plan, nil
		}
	}
	if !liveUsable {
		// A verified official snapshot can safely retire manager-owned models,
		// but an unavailable/incomplete gateway catalog cannot justify adding or
		// changing routes. Keep the removal-only plan eligible if it is conflict-free.
		if selectable == nil {
			plan.ApplyEligible = false
			plan.DiscoveryReason = "live catalog unavailable, fallback, or empty"
			plan.Conflicts = append(plan.Conflicts, "live catalog is unavailable, fallback, or empty; mapping changes are blocked")
			plan.UnreviewedModels = append([]string{}, input.LiveModels...)
			return plan, nil
		}
		if len(plan.Changes) == 0 {
			plan.ApplyEligible = false
			plan.DiscoveryReason = "live catalog unavailable; no mapping changes are permitted"
			plan.Conflicts = append(plan.Conflicts, "live catalog is unavailable, fallback, or empty; additions and updates are blocked")
			return plan, nil
		}
		sort.Slice(plan.Changes, func(i, j int) bool { return plan.Changes[i].PublicID < plan.Changes[j].PublicID })
		return plan, nil
	}
	excludedIDs := make(map[string]LifecycleExclusion, len(plan.LifecycleExclusions))
	for _, exclusion := range plan.LifecycleExclusions {
		if !validProductLifecycleScope(exclusion.Scope) || !containsString(plan.LifecycleScopes, exclusion.Scope) || !validID(exclusion.ModelID) || !validLifecycleExclusion(exclusion) {
			return Plan{}, errors.New("lifecycle exclusion is invalid or outside the approved product scope")
		}
		if productEvidenceKnown(exclusion.ModelID) && productStatus[strings.ToLower(exclusion.ModelID)] != "unavailable" {
			// Lifecycle evidence from one user-facing surface is report context
			// unless the product-union evaluator establishes a negative result.
			continue
		}
		key := strings.ToLower(exclusion.ModelID)
		if previous, exists := excludedIDs[key]; exists && previous.Scope != exclusion.Scope {
			return Plan{}, errors.New("lifecycle evidence assigns one model ID to multiple product scopes")
		}
		if selectable == nil {
			excludedIDs[key] = exclusion
		}
	}
	if len(excludedIDs) > 0 {
		for id := range live {
			if _, excluded := excludedIDs[strings.ToLower(id)]; excluded {
				delete(live, id)
			}
		}
		keys := make([]string, 0, len(input.CurrentMapping))
		for publicID := range input.CurrentMapping {
			keys = append(keys, publicID)
		}
		sort.Strings(keys)
		for _, publicID := range keys {
			upstreamID := input.CurrentMapping[publicID]
			if _, remains := plan.After[publicID]; !remains {
				continue
			}
			exclusion, excluded := excludedIDs[strings.ToLower(upstreamID)]
			if !excluded {
				continue
			}
			if !allowChanges(publicID) && publicID != upstreamID {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "product lifecycle exclusion cannot remove an unmanaged or drifted mapping: "+publicID)
				continue
			}
			delete(plan.After, publicID)
			reason := "exact upstream ID is excluded by approved official product-scope evidence"
			if publicID == upstreamID && !allowChanges(publicID) {
				reason = "exact identity mapping is excluded by fresh official product-scope evidence"
			}
			if exclusion.OwnerRule {
				reason = "exact upstream ID is excluded by an owner-confirmed product-scope availability decision"
			}
			plan.Changes = append(plan.Changes, Change{Action: "remove", PublicID: publicID, Before: upstreamID, RuleKind: "product_lifecycle", Evidence: lifecycleEvidenceLabel(exclusion), Reason: reason})
		}
	}
	if len(plan.Conflicts) > 0 {
		sort.Strings(plan.Conflicts)
		return plan, nil
	}
	if input.AllowIdentityCatalogSync {
		if input.IdentityCatalogPolicy != "replace_identity_from_live_list" && input.IdentityCatalogPolicy != "add_identity_from_live_list" {
			plan.ApplyEligible = false
			plan.DiscoveryReason = "source profile does not approve live identity mapping synchronization"
			plan.Conflicts = append(plan.Conflicts, "identity catalog sync is not approved for this exact source profile")
			return plan, nil
		}
		// This mode only imports exact upstream model IDs as identity mappings.
		// A wildcard from a provider catalog is not an exact ID and must not be
		// written as a broad routing rule. Preserve the current mapping and stop
		// the entire account plan before any removals or additions are computed.
		for modelID := range live {
			if IsWildcard(modelID) {
				plan.ApplyEligible = false
				plan.DiscoveryReason = "live identity catalog contains a wildcard model ID"
				plan.Conflicts = append(plan.Conflicts, "live identity sync requires exact model IDs; wildcard model ID is not safe to import")
				return plan, nil
			}
		}
		for _, rule := range rules.Aliases {
			if SourceMatches(rule.Source, input.Source) {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "live identity sync cannot overlap source-specific alias rules")
			}
		}
		// Reviewed exact version families are the only approved exception to
		// identity-only reconciliation. Preflight every family before changing
		// the plan so a conflict cannot leave a partial mapping diff.
		type familyOverlay struct {
			upstreamID string
			evidence   string
		}
		familyTargets := map[string]familyOverlay{}
		hiddenMembers := map[string]string{}
		keptMembers := map[string]string{}
		familyCovered := map[string]bool{}
		familyIDOwners := map[string]string{}
		for _, family := range rules.VersionFamilies {
			if !SourceMatches(family.Source, input.Source) {
				continue
			}
			if family.Source.AccountID <= 0 || family.Source.AccountID != input.AccountID {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "live identity sync requires a version family pinned to this exact account: "+family.PublicID)
				continue
			}
			// A concrete upstream ID may belong to only one canonical family
			// for this account/source. Even two "keep" rules that reuse an ID
			// can publish conflicting canonical names, so stop before creating
			// any partial plan.
			familyIDs := map[string]bool{family.PublicID: true}
			for _, member := range family.Members {
				familyIDs[member.UpstreamID] = true
			}
			familyOverlap := false
			for id := range familyIDs {
				if owner, exists := familyIDOwners[id]; exists && owner != family.PublicID {
					plan.ApplyEligible = false
					plan.Conflicts = append(plan.Conflicts, "version families overlap on exact model ID: "+id)
					familyOverlap = true
				}
			}
			if familyOverlap {
				continue
			}
			for id := range familyIDs {
				familyIDOwners[id] = family.PublicID
			}
			if !live[family.PreferredUpstreamID] {
				if input.ProductAvailabilityEnforced && productStatus[strings.ToLower(family.PreferredUpstreamID)] == "unavailable" {
					continue // Product-union removal was handled before family reconciliation.
				}
				if selectable == nil && !input.PruneMissingMappings {
					plan.ApplyEligible = false
					plan.DiscoveryReason = "live identity sync conflicts with an unavailable family target"
					plan.Conflicts = append(plan.Conflicts, "version family preferred upstream ID is absent: "+family.PublicID)
				}
				// A family target absent from the successful 404token catalog is
				// unavailable for this source. Do not recreate it or block removal
				// of an existing owned route; the live catalog is the authority here.
				continue
			}
			if !productAvailable(family.PreferredUpstreamID) {
				// A relay candidate without exact positive product evidence cannot
				// add or update a canonical family mapping.
				continue
			}
			if previous, exists := familyTargets[family.PublicID]; exists && previous.upstreamID != family.PreferredUpstreamID {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "multiple version families assign different upstream IDs to public key "+family.PublicID)
				continue
			}
			familyTargets[family.PublicID] = familyOverlay{upstreamID: family.PreferredUpstreamID, evidence: family.Evidence}
			familyCovered[family.PreferredUpstreamID] = true
			familyCovered[family.PublicID] = true
			for _, member := range family.Members {
				if !productAvailable(member.UpstreamID) {
					// Keep/hide actions affect concrete mappings, so require exact
					// positive availability for that member as well.
					continue
				}
				familyCovered[member.UpstreamID] = true
				if member.ExactIDAction == "hide" {
					if selectable != nil {
						continue
					}
					if keptFamily, kept := keptMembers[member.UpstreamID]; kept {
						plan.ApplyEligible = false
						plan.Conflicts = append(plan.Conflicts, "version families assign conflicting keep and hide actions to member: "+member.UpstreamID+" (family "+keptFamily+")")
						continue
					}
					if oldFamily, exists := hiddenMembers[member.UpstreamID]; exists && oldFamily != family.PublicID {
						plan.ApplyEligible = false
						plan.Conflicts = append(plan.Conflicts, "version families assign conflicting hide actions to member: "+member.UpstreamID)
						continue
					}
					hiddenMembers[member.UpstreamID] = family.PublicID
				} else {
					if hiddenFamily, hidden := hiddenMembers[member.UpstreamID]; hidden {
						plan.ApplyEligible = false
						plan.Conflicts = append(plan.Conflicts, "version families assign conflicting keep and hide actions to member: "+member.UpstreamID+" (family "+hiddenFamily+")")
						continue
					}
					keptMembers[member.UpstreamID] = family.PublicID
				}
			}
		}
		for publicID, target := range familyTargets {
			if hiddenFamily, hidden := hiddenMembers[publicID]; hidden {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "version family canonical key is also hidden: "+publicID+" (family "+hiddenFamily+")")
			}
			if current, exists := input.CurrentMapping[publicID]; exists && current != target.upstreamID && input.ProductAvailabilityEnforced && !productAvailable(current) {
				// Insufficient evidence for the existing target means preserve the
				// current mapping; a new preferred target cannot overwrite it.
				delete(familyTargets, publicID)
				continue
			}
			if current, exists := input.CurrentMapping[publicID]; exists && current != target.upstreamID && !allowChanges(publicID) {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "version family canonical key would overwrite an unmanaged or drifted mapping: "+publicID)
			}
		}
		for hiddenID := range hiddenMembers {
			if current, exists := input.CurrentMapping[hiddenID]; !exists {
				continue // A newly observed hidden member is skipped before import.
			} else if !isExactIdentityMapping(hiddenID, current) {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "version-family hide only supports an exact identity mapping: "+hiddenID)
			} else if !allowChanges(hiddenID) {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "version-family hide cannot change an unmanaged or drifted identity mapping: "+hiddenID)
			}
		}
		retired := make(map[string]RetiredRule)
		for _, rule := range rules.RetiredModels {
			if !SourceMatches(rule.Source, input.Source) {
				continue
			}
			if selectable != nil {
				continue
			}
			if productEvidenceKnown(rule.UpstreamID) && productStatus[strings.ToLower(rule.UpstreamID)] != "unavailable" {
				// Static retirement rules cannot turn incomplete product evidence
				// into a mapping deletion.
				continue
			}
			// This branch only reconciles exact identity mappings. A retirement
			// rule that renames an ID is ambiguous here and must remain manual.
			if !isExactIdentityMapping(rule.PublicID, rule.UpstreamID) {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "live identity sync cannot apply a non-identity retirement rule")
				continue
			}
			if _, duplicate := retired[rule.UpstreamID]; duplicate {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "live identity sync has duplicate source retirement rules")
				continue
			}
			retired[rule.UpstreamID] = rule
		}
		for retiredID := range retired {
			if _, hidden := hiddenMembers[retiredID]; hidden {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "retirement and version-family rules overlap on model ID: "+retiredID)
			}
			if _, kept := keptMembers[retiredID]; kept {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "retirement and version-family rules overlap on model ID: "+retiredID)
			}
		}
		for publicID := range familyTargets {
			if _, retiredPublicID := retired[publicID]; retiredPublicID {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "retirement and version-family rules overlap on public key: "+publicID)
			}
		}
		for publicID, rule := range retired {
			if current, exists := input.CurrentMapping[publicID]; exists && current == rule.UpstreamID && !allowChanges(publicID) {
				plan.ApplyEligible = false
				plan.Conflicts = append(plan.Conflicts, "explicit retirement cannot remove an unmanaged or drifted mapping: "+publicID)
			}
		}
		if len(plan.Conflicts) > 0 {
			plan.DiscoveryReason = "live identity sync conflicts with explicit source rules"
			sort.Strings(plan.Conflicts)
			return plan, nil
		}
		for publicID, upstreamID := range input.CurrentMapping {
			if !isExactIdentityMapping(publicID, upstreamID) {
				continue
			}
			if _, remains := plan.After[publicID]; !remains {
				continue // An earlier live-catalog or explicit-rule removal already handled this key.
			}
			if _, explicitlyHidden := hiddenMembers[publicID]; explicitlyHidden {
				continue // Explicit hides are handled only through the ownership gate below.
			}
			if _, familyPublicID := familyTargets[publicID]; familyPublicID {
				continue // Keep the canonical key for the reviewed overlay below.
			}
			if selectable != nil && selectable[upstreamID] {
				continue
			}
			if productEvidenceKnown(upstreamID) && productStatus[strings.ToLower(upstreamID)] != "unavailable" {
				// Insufficient/positive product evidence preserves this mapping;
				// relay-list omission alone does not authorize a deletion.
				continue
			}
			if rule, explicitlyRetired := retired[publicID]; explicitlyRetired {
				if _, stillPresent := plan.After[publicID]; stillPresent {
					delete(plan.After, publicID)
					plan.Changes = append(plan.Changes, Change{Action: "remove", PublicID: publicID, Before: upstreamID, RuleKind: "retired_model", Evidence: rule.Evidence, Reason: "exact model ID is covered by an approved source-specific retirement rule"})
				}
				continue
			}
			if (selectable != nil && selectable[upstreamID]) || live[publicID] || input.IdentityCatalogPolicy == "add_identity_from_live_list" {
				continue
			}
			delete(plan.After, publicID)
			plan.Changes = append(plan.Changes, Change{Action: "remove", PublicID: publicID, Before: upstreamID, RuleKind: "live_identity_sync", Evidence: "approved exact-source live catalog policy", Reason: "identity mapping is absent from the successful live upstream model list"})
		}
		for modelID := range live {
			if productEvidenceKnown(modelID) && productStatus[strings.ToLower(modelID)] != "available" {
				continue
			}
			if _, explicitlyHidden := hiddenMembers[modelID]; explicitlyHidden {
				continue // Never identity-import an exact member reviewed as hidden.
			}
			if _, familyPublicID := familyTargets[modelID]; familyPublicID {
				continue // The explicit family target owns this public key.
			}
			if _, explicitlyRetired := retired[modelID]; explicitlyRetired {
				if current, exists := input.CurrentMapping[modelID]; exists && current != modelID {
					plan.ApplyEligible = false
					plan.Conflicts = append(plan.Conflicts, "retired live model ID collides with a preserved non-identity mapping: "+modelID)
				}
				continue
			}
			if current, exists := input.CurrentMapping[modelID]; exists {
				if current != modelID {
					plan.ApplyEligible = false
					plan.Conflicts = append(plan.Conflicts, "live model ID collides with a preserved non-identity mapping: "+modelID)
				}
				continue
			}
			plan.After[modelID] = modelID
			plan.Changes = append(plan.Changes, Change{Action: "add", PublicID: modelID, After: modelID, RuleKind: "live_identity_sync", Evidence: "approved exact-source live catalog policy", Reason: "new exact upstream ID added without renaming or semantic inference"})
		}
		for hiddenID, familyPublicID := range hiddenMembers {
			if current, exists := plan.After[hiddenID]; exists {
				delete(plan.After, hiddenID)
				plan.Changes = append(plan.Changes, Change{Action: "remove", PublicID: hiddenID, Before: current, RuleKind: "version_family", Evidence: familyTargets[familyPublicID].evidence, Reason: "reviewed exact family member marked hide and ownership is unchanged"})
			}
		}
		for publicID, target := range familyTargets {
			if current, exists := plan.After[publicID]; exists {
				if current == target.upstreamID {
					continue
				}
				// The preflight above proves this mapping is manager-owned and
				// unchanged. Do not overwrite any other current value.
				plan.After[publicID] = target.upstreamID
				plan.Changes = append(plan.Changes, Change{Action: "update", PublicID: publicID, Before: current, After: target.upstreamID, RuleKind: "version_family", Evidence: target.evidence, Reason: "exact source-scoped reviewed family overlay"})
			} else {
				plan.After[publicID] = target.upstreamID
				plan.Changes = append(plan.Changes, Change{Action: "add", PublicID: publicID, After: target.upstreamID, RuleKind: "version_family", Evidence: target.evidence, Reason: "exact source-scoped reviewed family overlay"})
			}
		}
		if len(plan.After) == 0 {
			plan.ApplyEligible = false
			plan.DiscoveryReason = "live identity sync would produce an empty model mapping"
			plan.Conflicts = append(plan.Conflicts, "live identity sync would clear all model mappings; empty mappings may restore unrestricted or default routing")
		}
		for id := range live {
			if _, explicitlyRetired := retired[id]; explicitlyRetired {
				continue
			}
			if familyCovered[id] {
				continue
			}
			plan.UnreviewedModels = append(plan.UnreviewedModels, id)
		}
		sort.Strings(plan.UnreviewedModels)
		sort.Slice(plan.Changes, func(i, j int) bool {
			if plan.Changes[i].PublicID == plan.Changes[j].PublicID {
				return plan.Changes[i].Action < plan.Changes[j].Action
			}
			return plan.Changes[i].PublicID < plan.Changes[j].PublicID
		})
		sort.Strings(plan.Conflicts)
		return plan, nil
	}
	desired := map[string]struct{ value, kind, evidence string }{}
	addDesired := func(public, upstream, kind, evidence string) {
		if old, ok := desired[public]; ok && old.value != upstream {
			plan.Conflicts = append(plan.Conflicts, "multiple approved rules assign different upstream IDs to public key "+public)
			return
		}
		desired[public] = struct{ value, kind, evidence string }{upstream, kind, evidence}
	}
	for _, rule := range rules.Aliases {
		if !SourceMatches(rule.Source, input.Source) {
			continue
		}
		if live[rule.UpstreamID] && productAvailable(rule.UpstreamID) {
			addDesired(rule.PublicID, rule.UpstreamID, "alias", rule.Evidence)
		}
	}
	for _, family := range rules.VersionFamilies {
		if !SourceMatches(family.Source, input.Source) {
			continue
		}
		if !live[family.PreferredUpstreamID] {
			if input.ProductAvailabilityEnforced && productStatus[strings.ToLower(family.PreferredUpstreamID)] == "unavailable" {
				continue // Authoritative product evidence already removed the unavailable exact target.
			}
			if selectable == nil && !input.PruneMissingMappings {
				plan.Conflicts = append(plan.Conflicts, "version family preferred upstream ID is absent: "+family.PublicID)
			}
			continue
		}
		if !productAvailable(family.PreferredUpstreamID) {
			// Product evidence is insufficient; preserve existing mappings and
			// leave this canonical overlay untouched.
			continue
		}
		addDesired(family.PublicID, family.PreferredUpstreamID, "version_family", family.Evidence)
		for _, member := range family.Members {
			if member.ExactIDAction == "keep" && live[member.UpstreamID] && productAvailable(member.UpstreamID) {
				addDesiredIfIdentityAbsent(plan.After, member.UpstreamID, member.UpstreamID, "version_family_keep", family.Evidence, &plan)
			}
			if member.ExactIDAction == "hide" {
				if !productAvailable(member.UpstreamID) {
					continue
				}
				if selectable != nil {
					continue
				}
				if current, exists := plan.After[member.UpstreamID]; exists {
					if current != member.UpstreamID {
						plan.Conflicts = append(plan.Conflicts, "hide rule only supports exact identity mapping: "+member.UpstreamID)
						continue
					}
					if !allowChanges(member.UpstreamID) {
						plan.Conflicts = append(plan.Conflicts, "hide rule cannot change unmanaged or drifted identity mapping: "+member.UpstreamID)
						continue
					}
					delete(plan.After, member.UpstreamID)
					plan.Changes = append(plan.Changes, Change{Action: "remove", PublicID: member.UpstreamID, Before: current, RuleKind: "version_family", Evidence: family.Evidence, Reason: "reviewed exact member action is hide"})
				}
			}
		}
	}
	for public, item := range desired {
		if !productAvailable(item.value) {
			continue
		}
		if current, exists := plan.After[public]; exists {
			if current == item.value {
				continue
			}
			if input.ProductAvailabilityEnforced && !productAvailable(current) {
				// Keep an existing mapping whose current target has insufficient
				// official product evidence rather than replacing it speculatively.
				continue
			}
			if !allowChanges(public) {
				plan.Conflicts = append(plan.Conflicts, "approved mapping is blocked by unmanaged or drifted key: "+public)
				continue
			}
			plan.After[public] = item.value
			plan.Changes = append(plan.Changes, Change{Action: "update", PublicID: public, Before: current, After: item.value, RuleKind: item.kind, Evidence: item.evidence, Reason: "exact source-scoped reviewed rule"})
		} else {
			plan.After[public] = item.value
			plan.Changes = append(plan.Changes, Change{Action: "add", PublicID: public, After: item.value, RuleKind: item.kind, Evidence: item.evidence, Reason: "exact source-scoped reviewed rule"})
		}
	}
	for _, rule := range rules.RetiredModels {
		if !SourceMatches(rule.Source, input.Source) {
			continue
		}
		if selectable != nil {
			continue
		}
		current, exists := plan.After[rule.PublicID]
		if !exists {
			// Retiring an already absent exact key is idempotent and must not
			// block unrelated reviewed changes for this source.
			continue
		}
		if current != rule.UpstreamID {
			plan.Conflicts = append(plan.Conflicts, "retirement rule has no exact public-to-upstream mapping: "+rule.PublicID)
			continue
		}
		if productEvidenceKnown(current) && productStatus[strings.ToLower(current)] != "unavailable" {
			continue
		}
		if !allowChanges(rule.PublicID) {
			plan.Conflicts = append(plan.Conflicts, "retirement rule cannot remove unmanaged or drifted mapping: "+rule.PublicID)
			continue
		}
		delete(plan.After, rule.PublicID)
		plan.Changes = append(plan.Changes, Change{Action: "remove", PublicID: rule.PublicID, Before: current, RuleKind: "retired_model", Evidence: rule.Evidence, Reason: "exact source-scoped retirement rule"})
	}
	if input.Completeness == CompletenessComplete && selectable == nil {
		plan.AbsenceCountsAfter, plan.Changes = updateCompleteCatalogAbsence(
			plan.SourceFingerprint, live, managed, plan.AbsenceCountsAfter, plan.After, plan.Changes, allowChanges,
		)
	}
	known := map[string]bool{}
	for _, v := range input.CurrentMapping {
		known[v] = true
	}
	for _, rule := range rules.Aliases {
		if SourceMatches(rule.Source, input.Source) {
			known[rule.UpstreamID] = true
		}
	}
	for _, fam := range rules.VersionFamilies {
		if SourceMatches(fam.Source, input.Source) {
			for _, m := range fam.Members {
				known[m.UpstreamID] = true
			}
		}
	}
	for _, retired := range rules.RetiredModels {
		if SourceMatches(retired.Source, input.Source) {
			known[retired.UpstreamID] = true
		}
	}
	if input.Completeness == CompletenessComplete && input.SourceIdentityAddPolicy == "add_exact" {
		for id := range live {
			if productEvidenceKnown(id) && productStatus[strings.ToLower(id)] != "available" {
				continue
			}
			if known[id] {
				continue
			}
			if current, exists := plan.After[id]; exists {
				if current != id {
					plan.Conflicts = append(plan.Conflicts, "identity add is blocked by an existing mapping key: "+id)
				}
				continue
			}
			plan.After[id] = id
			plan.Changes = append(plan.Changes, Change{Action: "add", PublicID: id, After: id, RuleKind: "identity_add", Reason: "approved add_exact source profile and complete catalog; raw ID kept unreviewed"})
			plan.UnreviewedModels = append(plan.UnreviewedModels, id)
		}
	}
	for id := range live {
		if !known[id] {
			plan.UnreviewedModels = append(plan.UnreviewedModels, id)
		}
	}
	sort.Strings(plan.UnreviewedModels)
	sort.Slice(plan.Changes, func(i, j int) bool {
		if plan.Changes[i].PublicID == plan.Changes[j].PublicID {
			return plan.Changes[i].Action < plan.Changes[j].Action
		}
		return plan.Changes[i].PublicID < plan.Changes[j].PublicID
	})
	sort.Strings(plan.Conflicts)
	return plan, nil
}

func hashMissingSelectability(source Source, scope string) string {
	body, _ := json.Marshal(struct {
		Source  string `json:"source_fingerprint"`
		Scope   string `json:"scope"`
		Missing bool   `json:"missing"`
	}{SourceFingerprint(source), scope, true})
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

func hashSelectability(snapshot OfficialSelectability) string {
	ids := append([]string{}, snapshot.ModelIDs...)
	sort.Strings(ids)
	body, err := json.Marshal(struct {
		Scope      string    `json:"scope"`
		Complete   bool      `json:"complete"`
		ObservedAt time.Time `json:"observed_at"`
		ExpiresAt  time.Time `json:"expires_at"`
		ModelIDs   []string  `json:"model_ids"`
		Evidence   string    `json:"evidence"`
	}{snapshot.Scope, snapshot.Complete, snapshot.ObservedAt.UTC(), snapshot.ExpiresAt.UTC(), ids, snapshot.Evidence})
	if err != nil {
		return ""
	}
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// isExactIdentityMapping excludes Sub2API wildcard patterns even when their
// public and upstream strings are identical. A live catalog contains concrete
// IDs, so absence from that catalog cannot establish that a wildcard mapping
// is stale.
func isExactIdentityMapping(publicID, upstreamID string) bool {
	return publicID != "" && publicID == upstreamID && !IsWildcard(publicID)
}

// sameSourceEndpoint compares every source dimension except the account ID.
// It is used only to detect a family rule that would otherwise be dangerously
// broadened by SourceMatches' account_id=0 wildcard behavior.
func sameSourceEndpoint(rule, actual Source) bool {
	rule.AccountID = 0
	actual.AccountID = 0
	return SourceMatches(rule, actual)
}

func addDesiredIfIdentityAbsent(after map[string]string, key, value, kind, evidence string, plan *Plan) {
	if current, exists := after[key]; exists {
		if current != value {
			plan.Conflicts = append(plan.Conflicts, "version family keep conflicts with existing mapping: "+key)
		}
		return
	}
	after[key] = value
	plan.Changes = append(plan.Changes, Change{Action: "add", PublicID: key, After: value, RuleKind: kind, Evidence: evidence, Reason: "reviewed family member explicitly marked keep"})
}

func matchesBeijingModelStudioWorkspace(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || !strings.EqualFold(parsed.Hostname(), "ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com") {
		return false
	}
	return parsed.Port() == "" || parsed.Port() == "443"
}

func SourceFingerprint(s Source) string {
	normalized, _ := NormalizeBaseURL(s.BaseURL)
	s.BaseURL = normalized
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func canonicalHash(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", errors.New("canonical hash could not be computed")
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func LifecycleEvidenceDigest(scopes []string, exclusions []LifecycleExclusion) (string, error) {
	orderedScopes := append([]string(nil), scopes...)
	orderedExclusions := append([]LifecycleExclusion(nil), exclusions...)
	sort.Strings(orderedScopes)
	for i := range orderedExclusions {
		// Retrieval time is freshness metadata. A 304 refresh may update it while
		// preserving the same official statement; freshness is validated against
		// the current startup snapshot during apply. Keep this digest semantic.
		orderedExclusions[i].RetrievedAt = time.Time{}
	}
	sort.Slice(orderedExclusions, func(i, j int) bool {
		a, b := orderedExclusions[i], orderedExclusions[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.ModelID != b.ModelID {
			return a.ModelID < b.ModelID
		}
		return a.SourceID < b.SourceID
	})
	return canonicalHash(struct {
		Scopes     []string             `json:"scopes"`
		Exclusions []LifecycleExclusion `json:"exclusions"`
	}{Scopes: orderedScopes, Exclusions: orderedExclusions})
}

func ProductAvailabilityDigest(items []ProductModelAvailability) (string, error) {
	ordered := cloneProductAvailability(items)
	sort.Slice(ordered, func(i, j int) bool { return strings.ToLower(ordered[i].ModelID) < strings.ToLower(ordered[j].ModelID) })
	for i := range ordered {
		sort.Strings(ordered[i].SourceIDs)
		sort.Strings(ordered[i].SourceURLs)
		sort.Strings(ordered[i].ContentSHA256)
		if i > 0 && strings.EqualFold(ordered[i-1].ModelID, ordered[i].ModelID) {
			return "", errors.New("product availability contains duplicate model IDs")
		}
		if err := validateProductModelAvailability(ordered[i]); err != nil {
			return "", err
		}
	}
	return canonicalHash(ordered)
}

func cloneProductAvailability(items []ProductModelAvailability) []ProductModelAvailability {
	out := append([]ProductModelAvailability{}, items...)
	for i := range out {
		out[i].SourceIDs = append([]string(nil), items[i].SourceIDs...)
		out[i].SourceURLs = append([]string(nil), items[i].SourceURLs...)
		out[i].ContentSHA256 = append([]string(nil), items[i].ContentSHA256...)
	}
	return out
}

func validateProductModelAvailability(item ProductModelAvailability) error {
	if !validID(item.ModelID) {
		return errors.New("product availability contains an invalid model ID")
	}
	if item.Status != "available" && item.Status != "unavailable" && item.Status != "insufficient_evidence" {
		return errors.New("product availability contains an invalid status")
	}
	if item.MatchKind != "exact" && item.MatchKind != "explicit_alias" && item.MatchKind != "accepted_union_absence" && item.MatchKind != "accepted_union_retirement" && item.MatchKind != "accepted_union_version_floor" && item.MatchKind != "official_account_absence" && item.MatchKind != "official_api_catalog_absence" && item.MatchKind != "account_probe_success" && item.MatchKind != "all_account_probes_failed" && item.MatchKind != "account_probe_ignored" && item.MatchKind != "lower_than_unavailable_version" && item.MatchKind != "none" {
		return errors.New("product availability contains an invalid match kind")
	}
	if item.Status == "available" {
		if item.MatchKind != "exact" && item.MatchKind != "explicit_alias" && item.MatchKind != "account_probe_success" || len(item.SourceIDs) == 0 || len(item.SourceURLs) == 0 || len(item.ContentSHA256) == 0 || item.RetrievedAt.IsZero() {
			return errors.New("positive product availability is missing exact source evidence")
		}
	} else if item.Status == "unavailable" {
		if item.MatchKind != "accepted_union_absence" && item.MatchKind != "accepted_union_retirement" && item.MatchKind != "accepted_union_version_floor" && item.MatchKind != "official_account_absence" && item.MatchKind != "official_api_catalog_absence" && item.MatchKind != "all_account_probes_failed" && item.MatchKind != "lower_than_unavailable_version" || len(item.SourceIDs) == 0 || len(item.SourceURLs) == 0 || len(item.ContentSHA256) == 0 || item.RetrievedAt.IsZero() {
			return errors.New("negative product availability is missing complete-scope evidence")
		}
	} else if item.MatchKind != "none" && item.MatchKind != "account_probe_ignored" {
		return errors.New("insufficient product availability cannot claim a model match")
	}
	if item.MatchKind == "account_probe_success" || item.MatchKind == "all_account_probes_failed" || item.MatchKind == "account_probe_ignored" {
		if len(item.SourceIDs) != 1 || item.SourceIDs[0] != "404token-account-probe-v1" || len(item.SourceURLs) != 1 || item.SourceURLs[0] != "https://404token.xyz/api/v1/admin/accounts/{account_id}/test" || len(item.ContentSHA256) != 1 {
			return errors.New("account probe evidence is not bound to the approved probe contract")
		}
	}
	if len(item.SourceIDs) != len(item.SourceURLs) || len(item.SourceIDs) != len(item.ContentSHA256) {
		return errors.New("product availability source metadata lengths differ")
	}
	if item.MatchKind == "accepted_union_version_floor" {
		if len(item.SourceIDs) != 1 || len(item.SourceURLs) != 1 || len(item.ContentSHA256) != 1 {
			return errors.New("version-floor evidence must identify exactly one approved official catalog")
		}
		switch {
		case item.Provider == "xai" && item.SourceIDs[0] == "xai-grok-web-models" && item.SourceURLs[0] == "https://x.ai/news/grok-4-5-everywhere" && xAIVersionFloorModelID.MatchString(strings.ToLower(item.ModelID)):
		default:
			return errors.New("version-floor evidence is not bound to an approved provider catalog")
		}
	}
	if item.MatchKind == "accepted_union_retirement" {
		if len(item.SourceIDs) != 1 || len(item.SourceURLs) != 1 || len(item.ContentSHA256) != 1 ||
			item.Provider != "openai" || item.SourceIDs[0] != "openai-cross-product-lifecycle-v2" ||
			item.SourceURLs[0] != "https://learn.chatgpt.com/docs/changelog" || !strings.HasPrefix(strings.ToLower(item.ModelID), "gpt-") {
			return errors.New("product retirement evidence is not bound to the approved OpenAI cross-product lifecycle source")
		}
	}
	if item.MatchKind == "lower_than_unavailable_version" {
		if item.VersionFloorModelID == "" || item.ModelID == item.VersionFloorModelID || !modelversion.AtOrBelowVersion(item.ModelID, item.VersionFloorModelID) || !validVersionFloorSource(item) {
			return errors.New("cascaded version-floor evidence does not identify an equal-or-lower model relative to its unavailable trigger")
		}
	} else if item.VersionFloorModelID != "" {
		return errors.New("version-floor trigger is only valid for cascaded unavailability")
	}
	for i, sourceID := range item.SourceIDs {
		if strings.TrimSpace(sourceID) == "" || !strings.HasPrefix(item.SourceURLs[i], "https://") || !validSHA256(item.ContentSHA256[i]) || (i > 0 && item.SourceIDs[i-1] >= sourceID) {
			return errors.New("product availability source metadata is invalid or not canonical")
		}
	}
	for i := 1; i < len(item.SourceURLs); i++ {
		if item.SourceURLs[i-1] >= item.SourceURLs[i] {
			return errors.New("product availability source URLs are not canonical")
		}
	}
	for i := 1; i < len(item.ContentSHA256); i++ {
		if item.ContentSHA256[i-1] >= item.ContentSHA256[i] {
			return errors.New("product availability hashes are not canonical")
		}
	}
	return nil
}

func authorizesUnmanagedProductRemoval(item ProductModelAvailability) bool {
	switch item.MatchKind {
	case "accepted_union_version_floor", "accepted_union_retirement", "all_account_probes_failed", "lower_than_unavailable_version":
		return validateProductModelAvailability(item) == nil
	default:
		return false
	}
}

func validLifecycleExclusion(exclusion LifecycleExclusion) bool {
	if !validProductLifecycleScope(exclusion.Scope) || !validID(exclusion.ModelID) || len(exclusion.Excerpt) > 360 {
		return false
	}
	if exclusion.OwnerRule {
		return exclusion.Status == "owner_confirmed_unavailable" && exclusion.SourceID == "" && exclusion.SourceURL == "" && exclusion.ContentSHA256 == "" && exclusion.RetrievedAt.IsZero()
	}
	if exclusion.Status != "not_listed" && exclusion.Status != "deprecated" && exclusion.Status != "retired" && exclusion.Status != "retired_with_compatibility_route" && exclusion.Status != "announced_deprecated" {
		return false
	}
	if !officialLifecycleModelIDMatchesScope(exclusion.Scope, exclusion.ModelID) {
		return false
	}
	if exclusion.Status == "not_listed" && exclusion.Scope == "openai_codex_chatgpt_login" && !strings.HasPrefix(strings.ToLower(exclusion.ModelID), "gpt-") {
		return false
	}
	if exclusion.SourceID == "" || !strings.HasPrefix(exclusion.SourceURL, "https://") || !validSHA256(exclusion.ContentSHA256) || exclusion.RetrievedAt.IsZero() {
		return false
	}
	if exclusion.EffectiveAt != "" && !validReviewDate(exclusion.EffectiveAt) {
		return false
	}
	return exclusion.Status != "announced_deprecated" || exclusion.EffectiveAt != ""
}

func officialLifecycleModelIDMatchesScope(scope, modelID string) bool {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	switch scope {
	case "openai_codex_chatgpt_login":
		return strings.HasPrefix(modelID, "gpt-")
	case "anthropic_claude_code_login":
		return strings.HasPrefix(modelID, "claude-")
	case "kimi_code_login":
		if strings.HasPrefix(modelID, "kimi-") {
			return true
		}
		return regexp.MustCompile(`^k[0-9]+(?:-[0-9]+k)?$`).MatchString(modelID)
	default:
		return false
	}
}

func lifecycleEvidenceLabel(exclusion LifecycleExclusion) string {
	if exclusion.OwnerRule {
		return "owner-confirmed unavailable in " + exclusion.Scope
	}
	label := exclusion.Scope + "; " + exclusion.SourceID + "; " + exclusion.SourceURL
	if exclusion.Status == "not_listed" {
		label += "; absent from current official product model list"
	}
	if exclusion.EffectiveAt != "" {
		label += "; effective=" + exclusion.EffectiveAt
	}
	return label
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func cloneMapping(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func cloneAbsenceCounts(src map[string]int) map[string]int {
	dst := make(map[string]int, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// updateCompleteCatalogAbsence returns the next per-account counters and any
// exact managed removals justified by the second consecutive complete snapshot.
// The caller is responsible for proving completeness before calling it.
func updateCompleteCatalogAbsence(sourceFingerprint string, live map[string]bool, managed map[string]state.ManagedMapping, counts map[string]int, after map[string]string, changes []Change, allowChanges func(string) bool) (map[string]int, []Change) {
	next := cloneAbsenceCounts(counts)
	if next == nil {
		next = map[string]int{}
	}
	for key, owner := range managed {
		if owner.SourceFingerprint != sourceFingerprint {
			continue
		}
		next[key] = ObserveAbsence(next[key], CompletenessComplete, true, live[owner.LastAppliedValue])
		if next[key] < 2 {
			continue
		}
		current, exists := after[key]
		if !exists || current != owner.LastAppliedValue || !allowChanges(key) {
			continue
		}
		delete(after, key)
		changes = append(changes, Change{Action: "remove", PublicID: key, Before: current, RuleKind: "complete_catalog_absence", Reason: "missing from two consecutive complete snapshots"})
	}
	return next, changes
}

func ObserveAbsence(count int, completeness Completeness, live bool, modelPresent bool) int {
	if completeness != CompletenessComplete || !live {
		return count
	}
	if modelPresent {
		return 0
	}
	return count + 1
}

func (p Plan) ValidateBeforeApply(expectedSource Source, mapping map[string]string, rules Rules) error {
	if len(p.Conflicts) > 0 {
		return errors.New("plan contains conflicts")
	}
	if p.AccountID <= 0 || p.SourceFingerprint != SourceFingerprint(expectedSource) {
		return errors.New("plan source fingerprint changed")
	}
	hash, err := MappingHash(mapping)
	if err != nil || hash != p.BeforeHash {
		return errors.New("plan mapping snapshot changed")
	}
	rulesHash, err := canonicalHash(rules)
	if err != nil || rulesHash != p.RulesHash {
		return errors.New("plan rules changed")
	}
	return nil
}

func CanonicalMappingJSON(mapping map[string]string) ([]byte, error) {
	if mapping == nil {
		return nil, errors.New("mapping is nil")
	}
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	b := []byte("{")
	for i, key := range keys {
		k, _ := json.Marshal(key)
		v, _ := json.Marshal(mapping[key])
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, k...)
		b = append(b, ':')
		b = append(b, v...)
	}
	b = append(b, '}')
	return b, nil
}

func MappingFingerprint(mapping map[string]string) (string, error) {
	b, err := CanonicalMappingJSON(mapping)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func AccountKey(id int64) string { return strconv.FormatInt(id, 10) }

func (p Plan) String() string {
	return fmt.Sprintf("account=%d changes=%d conflicts=%d", p.AccountID, len(p.Changes), len(p.Conflicts))
}

func IsWildcard(s string) bool { return strings.ContainsAny(s, "*?") }
