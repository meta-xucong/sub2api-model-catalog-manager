package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

const ApprovalPlanSchemaVersion = 6
const ApprovalPlanTTL = 15 * time.Minute

type TargetBinding struct {
	Origin        string `json:"origin"`
	BuildID       string `json:"build_id"`
	APIContractID string `json:"api_contract_id"`
}

// ApprovalPlan is the immutable, human-confirmed envelope applied later. The
// file's raw bytes are hashed separately by the CLI and are never reserialized
// before confirmation.
type ApprovalPlan struct {
	SchemaVersion          int                  `json:"schema_version"`
	CreatedAt              time.Time            `json:"created_at"`
	ExpiresAt              time.Time            `json:"expires_at"`
	Target                 TargetBinding        `json:"target"`
	AccountScope           string               `json:"account_scope"`
	AccountInventoryCount  int                  `json:"account_inventory_count,omitempty"`
	AccountInventorySHA256 string               `json:"account_inventory_sha256,omitempty"`
	RulesSHA256            string               `json:"rules_sha256"`
	StateSHA256            string               `json:"state_sha256"`
	ModelProbeDecisions    []ModelProbeDecision `json:"model_probe_decisions,omitempty"`
	ModelProbeSHA256       string               `json:"model_probe_sha256,omitempty"`
	Accounts               []Plan               `json:"accounts"`
}

type ModelProbeOutcome struct {
	AccountID int64  `json:"account_id"`
	Outcome   string `json:"outcome"`
}

type ModelProbeDecision struct {
	Provider      string                   `json:"provider,omitempty"`
	ModelID       string                   `json:"model_id"`
	Status        string                   `json:"status"` // available, unavailable, or ignored
	ScopeAccounts []ModelProbeScopeAccount `json:"scope_accounts"`
	Accounts      []ModelProbeOutcome      `json:"accounts"`
}

// ModelProbeScopeAccount binds every active exact-model mapping in the provider
// namespace, including accounts excluded from probing by official evidence.
type ModelProbeScopeAccount struct {
	AccountID int64  `json:"account_id"`
	Reason    string `json:"reason"` // probe, official_available, official_unavailable
}

func (p ApprovalPlan) ValidateShape(now time.Time) error {
	if p.SchemaVersion != ApprovalPlanSchemaVersion || p.CreatedAt.IsZero() || p.ExpiresAt.IsZero() || len(p.Accounts) == 0 {
		return errors.New("approval plan is missing required fields")
	}
	if p.CreatedAt.After(now) || !p.ExpiresAt.After(now) || p.ExpiresAt.Sub(p.CreatedAt) > ApprovalPlanTTL || p.ExpiresAt.Before(p.CreatedAt) {
		return errors.New("approval plan is outside its 15-minute validity window")
	}
	if strings.TrimSpace(p.Target.Origin) == "" || strings.TrimSpace(p.Target.BuildID) == "" || (p.Target.APIContractID != "admin-catalog-v1" && p.Target.APIContractID != "admin-catalog-all-v1") || !validSHA256(p.RulesSHA256) || !validSHA256(p.StateSHA256) {
		return errors.New("approval plan target or hash binding is invalid")
	}
	if p.AccountScope != "allowlist" && p.AccountScope != "all" {
		return errors.New("approval plan account scope is invalid")
	}
	if p.AccountScope == "all" {
		if p.AccountInventoryCount <= 0 || !validSHA256(p.AccountInventorySHA256) {
			return errors.New("all-account plan is missing its inventory snapshot")
		}
	} else if p.AccountInventoryCount != 0 || p.AccountInventorySHA256 != "" {
		return errors.New("allowlist plan unexpectedly contains an all-account inventory")
	}
	if len(p.ModelProbeDecisions) == 0 {
		if p.ModelProbeSHA256 != "" {
			return errors.New("approval plan contains an empty model-probe digest")
		}
	} else {
		digest, err := ModelProbeDigest(p.ModelProbeDecisions)
		if err != nil || digest != p.ModelProbeSHA256 {
			return errors.New("approval plan model-probe evidence is invalid or its hash does not match")
		}
	}
	seen := map[int64]bool{}
	probeParticipants := map[string]map[int64]string{}
	cascadedAvailability := map[string][]ProductModelAvailability{}
	for _, account := range p.Accounts {
		if account.AccountID <= 0 || seen[account.AccountID] || account.Before == nil || account.After == nil || account.AbsenceCountsBefore == nil || account.AbsenceCountsAfter == nil || !validAbsenceCounts(account.AbsenceCountsBefore) || !validAbsenceCounts(account.AbsenceCountsAfter) || account.Conflicts == nil || account.CatalogObservedAt.IsZero() || !validSHA256(account.DirectoryHash) || !validSHA256(account.SourceFingerprint) || !validSHA256(account.LifecycleEvidenceSHA256) || (account.OfficialSelectabilitySHA256 == "" && (!account.OfficialSelectabilityObservedAt.IsZero() || !account.OfficialSelectabilityExpiresAt.IsZero() || account.OfficialSelectabilityScope != "")) || (account.OfficialSelectabilitySHA256 != "" && (!validOfficialSelectabilityScope(account.OfficialSelectabilityScope) || !validSHA256(account.OfficialSelectabilitySHA256) || account.OfficialSelectabilityObservedAt.IsZero() || account.OfficialSelectabilityExpiresAt.IsZero())) || (account.OfficialSelectabilityObservedAt.IsZero() != account.OfficialSelectabilityExpiresAt.IsZero()) || (!account.OfficialSelectabilityObservedAt.IsZero() && (!account.OfficialSelectabilityExpiresAt.After(account.OfficialSelectabilityObservedAt) || account.OfficialSelectabilityExpiresAt.Sub(account.OfficialSelectabilityObservedAt) > OfficialSelectabilityMaxAge)) || (account.IdentityCatalogPolicy != "" && account.IdentityCatalogPolicy != "replace_identity_from_live_list" && account.IdentityCatalogPolicy != "add_identity_from_live_list") {
			return errors.New("approval plan contains an invalid account snapshot")
		}
		for i, scope := range account.LifecycleScopes {
			if !validProductLifecycleScope(scope) || (i > 0 && account.LifecycleScopes[i-1] >= scope) {
				return errors.New("approval plan account lifecycle scopes are invalid or not canonical")
			}
		}
		for _, exclusion := range account.LifecycleExclusions {
			if !containsString(account.LifecycleScopes, exclusion.Scope) || !validLifecycleExclusion(exclusion) {
				return errors.New("approval plan contains invalid lifecycle evidence")
			}
		}
		lifecycleDigest, err := LifecycleEvidenceDigest(account.LifecycleScopes, account.LifecycleExclusions)
		if err != nil || lifecycleDigest != account.LifecycleEvidenceSHA256 {
			return errors.New("approval plan lifecycle evidence hash does not match its contents")
		}
		if account.ProductAvailabilityEnforced {
			availabilityDigest, availabilityErr := ProductAvailabilityDigest(account.ProductAvailability)
			if availabilityErr != nil || availabilityDigest != account.ProductAvailabilitySHA256 {
				return errors.New("approval plan product availability evidence is invalid or its hash does not match")
			}
		} else if account.ProductAvailabilitySHA256 != "" || len(account.ProductAvailability) != 0 {
			return errors.New("approval plan contains product availability evidence without enforcement")
		}
		for _, evidence := range account.ProductAvailability {
			if evidence.MatchKind == "lower_than_unavailable_version" {
				key := ModelProbeKey(evidence.Provider, evidence.ModelID)
				cascadedAvailability[key] = append(cascadedAvailability[key], evidence)
			}
			if evidence.MatchKind != "account_probe_success" && evidence.MatchKind != "all_account_probes_failed" && evidence.MatchKind != "account_probe_ignored" {
				continue
			}
			mapped := false
			for _, upstreamID := range account.Before {
				if upstreamID == evidence.ModelID {
					mapped = true
					break
				}
			}
			if !mapped {
				return errors.New("model-probe evidence is attached to an account without that exact current mapping")
			}
			key := ModelProbeKey(evidence.Provider, evidence.ModelID)
			if probeParticipants[key] == nil {
				probeParticipants[key] = map[int64]string{}
			}
			if _, duplicate := probeParticipants[key][account.AccountID]; duplicate {
				return errors.New("model-probe account evidence is duplicated")
			}
			participantStatus := evidence.Status
			if evidence.MatchKind == "account_probe_ignored" {
				participantStatus = "ignored"
			}
			probeParticipants[key][account.AccountID] = participantStatus
		}
		seen[account.AccountID] = true
		if account.Source.AccountID != 0 && account.Source.AccountID != account.AccountID || SourceFingerprint(account.Source) != account.SourceFingerprint {
			return errors.New("approval plan source identity does not match its fingerprint")
		}
		directoryHash, err := DirectoryDigest(account.CatalogModels, account.LiveListAvailable, account.CatalogWarningCodes)
		if err != nil || directoryHash != account.DirectoryHash {
			return errors.New("approval plan catalog snapshot hash does not match its contents")
		}
		if _, err := MappingFingerprint(account.Before); err != nil {
			return errors.New("approval plan before mapping is invalid")
		}
		if _, err := MappingFingerprint(account.After); err != nil {
			return errors.New("approval plan after mapping is invalid")
		}
	}
	if len(probeParticipants) != nonCascadedProbeDecisionCount(p.ModelProbeDecisions, cascadedAvailability) {
		return errors.New("approval plan model-probe decisions do not match account evidence")
	}
	for _, decision := range p.ModelProbeDecisions {
		key := ModelProbeKey(decision.Provider, decision.ModelID)
		participants := probeParticipants[key]
		if len(cascadedAvailability[key]) > 0 {
			if !hasValidatedVersionFloorProof(p, cascadedAvailability[key]) {
				return errors.New("cascaded model-probe evidence has no matching unavailable version-floor proof")
			}
		} else if len(participants) != len(decision.Accounts) {
			return errors.New("approval plan model-probe account scope is incomplete")
		}
		for _, outcome := range decision.Accounts {
			if len(cascadedAvailability[key]) > 0 {
				continue // A newer unavailable version overrides this model's independent probe outcome.
			}
			status, found := participants[outcome.AccountID]
			if !found {
				return errors.New("approval plan model-probe account scope does not match the participating account plans")
			}
			if status != decision.Status {
				return errors.New("approval plan model-probe aggregate disagrees with account availability evidence")
			}
		}
		seenScope := map[int64]bool{}
		for _, scope := range decision.ScopeAccounts {
			if scope.AccountID <= 0 || seenScope[scope.AccountID] {
				return errors.New("approval plan model-probe scope manifest is invalid")
			}
			seenScope[scope.AccountID] = true
			if scope.Reason == "probe" {
				if len(cascadedAvailability[key]) == 0 {
					if _, ok := participants[scope.AccountID]; !ok {
						return errors.New("model-probe scope does not match participating accounts")
					}
				}
			} else if scope.Reason != "official_available" && scope.Reason != "official_unavailable" && scope.Reason != "other_provider" {
				return errors.New("approval plan model-probe scope reason is invalid")
			}
		}
		expectedScope := make(map[int64]string)
		for _, account := range p.Accounts {
			mapped := false
			for _, upstreamID := range account.Before {
				if upstreamID == decision.ModelID {
					mapped = true
					break
				}
			}
			if !mapped || !account.ProductAvailabilityEnforced {
				continue
			}
			var match *ProductModelAvailability
			for i := range account.ProductAvailability {
				if account.ProductAvailability[i].ModelID == decision.ModelID {
					match = &account.ProductAvailability[i]
					break
				}
			}
			if match == nil {
				continue
			}
			if match.MatchKind == "lower_than_unavailable_version" {
				expectedScope[account.AccountID] = "cascade"
				continue
			}
			if match.Provider != decision.Provider {
				expectedScope[account.AccountID] = "other_provider"
				continue
			}
			reason := "probe"
			if match.MatchKind != "account_probe_success" && match.MatchKind != "all_account_probes_failed" && match.MatchKind != "account_probe_ignored" {
				switch match.Status {
				case "available":
					reason = "official_available"
				case "unavailable":
					reason = "official_unavailable"
				default:
					continue
				}
			}
			expectedScope[account.AccountID] = reason
		}
		if len(expectedScope) != len(decision.ScopeAccounts) {
			return errors.New("model-probe scope manifest does not match exact-model account plans")
		}
		for _, scope := range decision.ScopeAccounts {
			if expectedScope[scope.AccountID] != "cascade" && expectedScope[scope.AccountID] != scope.Reason {
				return errors.New("model-probe scope manifest disagrees with account evidence")
			}
		}
	}
	for _, account := range p.Accounts {
		for _, evidence := range account.ProductAvailability {
			if evidence.MatchKind == "lower_than_unavailable_version" && !hasValidatedVersionFloorProof(p, []ProductModelAvailability{evidence}) {
				return errors.New("cascaded product availability has no matching unavailable version-floor proof")
			}
		}
	}
	return nil
}

func nonCascadedProbeDecisionCount(decisions []ModelProbeDecision, cascaded map[string][]ProductModelAvailability) int {
	count := 0
	for _, decision := range decisions {
		if len(cascaded[ModelProbeKey(decision.Provider, decision.ModelID)]) == 0 {
			count++
		}
	}
	return count
}

func hasValidatedVersionFloorProof(plan ApprovalPlan, cascaded []ProductModelAvailability) bool {
	for _, item := range cascaded {
		found := false
		for _, account := range plan.Accounts {
			for _, trigger := range account.ProductAvailability {
				validTrigger := canEstablishVersionFloor(trigger)
				if trigger.MatchKind == "all_account_probes_failed" {
					validTrigger = modelProbeEvidenceMatchesDecision(plan, trigger)
				}
				if trigger.ModelID == item.VersionFloorModelID && trigger.Provider == item.Provider && trigger.Status == "unavailable" &&
					trigger.MatchKind != "lower_than_unavailable_version" && validTrigger &&
					stringSliceEqual(trigger.SourceIDs, item.SourceIDs) && stringSliceEqual(trigger.SourceURLs, item.SourceURLs) && stringSliceEqual(trigger.ContentSHA256, item.ContentSHA256) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			for _, decision := range plan.ModelProbeDecisions {
				if decision.Provider != item.Provider || decision.ModelID != item.VersionFloorModelID || decision.Status != "unavailable" {
					continue
				}
				if modelProbeEvidenceMatchesDecision(plan, ProductModelAvailability{
					ModelID: item.VersionFloorModelID, Provider: item.Provider, Status: "unavailable", MatchKind: "all_account_probes_failed",
					SourceIDs: item.SourceIDs, SourceURLs: item.SourceURLs, ContentSHA256: item.ContentSHA256,
				}) {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	return len(cascaded) > 0
}

func modelProbeEvidenceMatchesDecision(plan ApprovalPlan, evidence ProductModelAvailability) bool {
	if evidence.MatchKind != "all_account_probes_failed" || evidence.Status != "unavailable" || len(evidence.SourceIDs) != 1 || evidence.SourceIDs[0] != "404token-account-probe-v1" || len(evidence.SourceURLs) != 1 || evidence.SourceURLs[0] != "https://404token.xyz/api/v1/admin/accounts/{account_id}/test" || len(evidence.ContentSHA256) != 1 {
		return false
	}
	for _, decision := range plan.ModelProbeDecisions {
		if decision.Provider != evidence.Provider || decision.ModelID != evidence.ModelID || decision.Status != "unavailable" {
			continue
		}
		body, err := json.Marshal(decision)
		if err != nil {
			continue
		}
		h := sha256.Sum256(body)
		if evidence.ContentSHA256[0] == hex.EncodeToString(h[:]) {
			return true
		}
	}
	return false
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ModelProbeDigest(decisions []ModelProbeDecision) (string, error) {
	ordered := append([]ModelProbeDecision(nil), decisions...)
	sort.Slice(ordered, func(i, j int) bool {
		return ModelProbeKey(ordered[i].Provider, ordered[i].ModelID) < ModelProbeKey(ordered[j].Provider, ordered[j].ModelID)
	})
	for i, decision := range ordered {
		key := ModelProbeKey(decision.Provider, decision.ModelID)
		if !validID(decision.ModelID) || i > 0 && ModelProbeKey(ordered[i-1].Provider, ordered[i-1].ModelID) >= key || decision.Status != "available" && decision.Status != "unavailable" && decision.Status != "ignored" || len(decision.Accounts) == 0 || len(decision.ScopeAccounts) == 0 {
			return "", errors.New("model-probe decision is invalid or not canonical")
		}
		lastScopeID := int64(0)
		for _, scope := range decision.ScopeAccounts {
			if scope.AccountID <= lastScopeID || (scope.Reason != "probe" && scope.Reason != "official_available" && scope.Reason != "official_unavailable" && scope.Reason != "other_provider") {
				return "", errors.New("model-probe scope accounts are invalid or unordered")
			}
			lastScopeID = scope.AccountID
		}
		succeeded := false
		failed := 0
		incomplete := 0
		officialAvailableInScope := false
		for _, scope := range decision.ScopeAccounts {
			if scope.Reason == "official_available" {
				officialAvailableInScope = true
				break
			}
		}
		previousID := int64(0)
		seenSuccess := false
		for _, account := range decision.Accounts {
			if account.AccountID <= previousID {
				return "", errors.New("model-probe account outcomes are invalid or unordered")
			}
			previousID = account.AccountID
			switch account.Outcome {
			case "failed":
				if seenSuccess {
					return "", errors.New("model-probe attempt follows a successful account")
				}
				failed++
			case "incomplete":
				if seenSuccess {
					return "", errors.New("model-probe attempt follows a successful account")
				}
				incomplete++
			case "succeeded":
				if seenSuccess {
					return "", errors.New("model-probe decision contains multiple successful accounts")
				}
				seenSuccess = true
				succeeded = true
			case "not_attempted_after_success":
				if !seenSuccess {
					return "", errors.New("model-probe skipped account has no preceding success")
				}
			default:
				return "", errors.New("model-probe account outcome is invalid")
			}
		}
		if decision.Status == "available" && !succeeded || decision.Status == "unavailable" && (succeeded || incomplete != 0 || failed != len(decision.Accounts) || officialAvailableInScope) || decision.Status == "ignored" && (succeeded || incomplete == 0 && !officialAvailableInScope) {
			return "", errors.New("model-probe aggregate does not match account outcomes")
		}
	}
	body, err := json.Marshal(ordered)
	if err != nil {
		return "", errors.New("model-probe evidence digest could not be computed")
	}
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:]), nil
}

func ModelProbeKey(provider, modelID string) string { return provider + "\x00" + modelID }

func AccountIDsDigest(ids []int64) (string, error) {
	ordered := append([]int64(nil), ids...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	for i, id := range ordered {
		if id <= 0 || (i > 0 && ordered[i-1] == id) {
			return "", errors.New("account inventory contains an invalid or duplicate ID")
		}
	}
	body, err := json.Marshal(ordered)
	if err != nil {
		return "", errors.New("account inventory digest could not be computed")
	}
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:]), nil
}

func validAbsenceCounts(counts map[string]int) bool {
	for key, count := range counts {
		if strings.TrimSpace(key) == "" || count < 0 {
			return false
		}
	}
	return true
}

func DirectoryDigest(models []string, live bool, warningCodes []string) (string, error) {
	modelCopy := append([]string(nil), models...)
	warningCopy := append([]string(nil), warningCodes...)
	sort.Strings(modelCopy)
	sort.Strings(warningCopy)
	for i, model := range modelCopy {
		if !validID(model) || (i > 0 && modelCopy[i-1] == model) {
			return "", errors.New("catalog contains invalid or duplicate model IDs")
		}
	}
	for i, warning := range warningCopy {
		if strings.TrimSpace(warning) == "" || (i > 0 && warningCopy[i-1] == warning) {
			return "", errors.New("catalog warning codes are invalid or duplicated")
		}
	}
	body, err := json.Marshal(struct {
		Models   []string `json:"models"`
		Live     bool     `json:"live_list_available"`
		Warnings []string `json:"warning_codes"`
	}{Models: modelCopy, Live: live, Warnings: warningCopy})
	if err != nil {
		return "", errors.New("catalog snapshot hash could not be computed")
	}
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:]), nil
}

func validSHA256(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
