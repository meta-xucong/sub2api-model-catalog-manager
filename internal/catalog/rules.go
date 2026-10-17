package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var validDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

type Rules struct {
	SchemaVersion            int                       `json:"schema_version"`
	Aliases                  []AliasRule               `json:"aliases"`
	VersionFamilies          []VersionFamily           `json:"version_families"`
	RetiredModels            []RetiredRule             `json:"retired_models"`
	OwnerLifecycleExclusions []OwnerLifecycleExclusion `json:"owner_lifecycle_exclusions,omitempty"`
	OfficialSelectability    []OfficialSelectability   `json:"official_selectability"`
	SourceProfiles           []SourceProfile           `json:"source_profiles"`
	CompleteCatalogProfiles  []CompleteCatalogProfile  `json:"complete_catalog_profiles"`
}

// OfficialSelectability is an operator-reviewed, complete snapshot of model
// IDs that the corresponding official account can currently select. It is
// the sole authority for model eligibility; other catalogs and lifecycle
// rules may not override it.
type OfficialSelectability struct {
	Scope      string    `json:"scope"`
	Complete   bool      `json:"complete"`
	ModelIDs   []string  `json:"model_ids"`
	ObservedAt time.Time `json:"observed_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Evidence   string    `json:"evidence"`
}

const OfficialSelectabilityMaxAge = 24 * time.Hour

type OwnerLifecycleExclusion struct {
	Scope      string `json:"scope"`
	ModelID    string `json:"model_id"`
	Decision   string `json:"decision"`
	Evidence   string `json:"evidence"`
	ReviewedAt string `json:"reviewed_at"`
}

type Source struct {
	Platform    string `json:"platform"`
	AccountType string `json:"account_type"`
	APIProtocol string `json:"api_protocol"`
	BaseURL     string `json:"base_url"`
	AccountID   int64  `json:"account_id,omitempty"`
}

type AliasRule struct {
	Source     Source `json:"source"`
	UpstreamID string `json:"upstream_id"`
	PublicID   string `json:"public_id"`
	Decision   string `json:"decision"`
	Evidence   string `json:"evidence"`
	ReviewedAt string `json:"reviewed_at"`
}

type VersionFamily struct {
	Source              Source         `json:"source"`
	PublicID            string         `json:"public_id"`
	PreferredUpstreamID string         `json:"preferred_upstream_id"`
	Members             []FamilyMember `json:"members"`
	Decision            string         `json:"decision"`
	Evidence            string         `json:"evidence"`
	ReviewedAt          string         `json:"reviewed_at"`
}

type FamilyMember struct {
	UpstreamID    string `json:"upstream_id"`
	ExactIDAction string `json:"exact_id_action"`
}

type RetiredRule struct {
	Source     Source `json:"source"`
	UpstreamID string `json:"upstream_id"`
	PublicID   string `json:"public_id"`
	Decision   string `json:"decision"`
	Evidence   string `json:"evidence"`
	ReviewedAt string `json:"reviewed_at"`
}

type SourceProfile struct {
	Source                        Source   `json:"source"`
	BuildID                       string   `json:"build_id"`
	APIContractID                 string   `json:"api_contract_id"`
	Decision                      string   `json:"decision"`
	OfficialSelectabilityScope    string   `json:"official_selectability_scope"`
	OfficialSelectabilityProduct  string   `json:"official_selectability_product,omitempty"`
	OfficialSelectabilityProvider string   `json:"official_selectability_provider,omitempty"`
	LifecycleScopes               []string `json:"lifecycle_scopes,omitempty"`
	IdentityAddPolicy             string   `json:"identity_add_policy,omitempty"`
	IdentityCatalogPolicy         string   `json:"identity_catalog_policy,omitempty"`
	Evidence                      string   `json:"evidence"`
	ReviewedAt                    string   `json:"reviewed_at"`
}

type CompleteCatalogProfile struct {
	Source     Source `json:"source"`
	ProfileID  string `json:"profile_id"`
	Evidence   string `json:"evidence"`
	ReviewedAt string `json:"reviewed_at"`
}

func LoadRules(path string) (Rules, error) {
	rules, _, err := LoadRulesWithHash(path)
	return rules, err
}

func LoadRulesWithHash(path string) (Rules, string, error) {
	var rules Rules
	f, err := os.Open(path)
	if err != nil {
		return rules, "", errors.New("rules file is unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return rules, "", errors.New("rules file has an invalid shape")
	}
	b, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		return rules, "", errors.New("rules file exceeds size limit")
	}
	h := sha256.Sum256(b)
	rawHash := hex.EncodeToString(h[:])
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rules); err != nil {
		return rules, "", errors.New("rules file is invalid")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return rules, "", errors.New("rules file contains trailing data")
	}
	if err := rules.Validate(); err != nil {
		return rules, "", err
	}
	return rules, rawHash, nil
}

func (r Rules) Validate() error {
	if r.SchemaVersion != 1 {
		return errors.New("unsupported rules schema version")
	}
	for i, rule := range r.Aliases {
		if err := validateSource(rule.Source); err != nil {
			return fmt.Errorf("alias[%d]: %w", i, err)
		}
		if !validID(rule.UpstreamID) || !validID(rule.PublicID) || rule.UpstreamID == rule.PublicID || !approved(rule.Decision, rule.Evidence, rule.ReviewedAt) {
			return fmt.Errorf("alias[%d] is incomplete or unapproved", i)
		}
	}
	for i, family := range r.VersionFamilies {
		if err := validateSource(family.Source); err != nil {
			return fmt.Errorf("version_family[%d]: %w", i, err)
		}
		if !validID(family.PublicID) || !validID(family.PreferredUpstreamID) || !approved(family.Decision, family.Evidence, family.ReviewedAt) || len(family.Members) == 0 {
			return fmt.Errorf("version_family[%d] is incomplete or unapproved", i)
		}
		memberSeen, preferredSeen := map[string]bool{}, false
		for _, member := range family.Members {
			if !validID(member.UpstreamID) || (member.ExactIDAction != "keep" && member.ExactIDAction != "hide") || memberSeen[member.UpstreamID] {
				return fmt.Errorf("version_family[%d] has invalid or duplicate members", i)
			}
			memberSeen[member.UpstreamID] = true
			if member.UpstreamID == family.PreferredUpstreamID {
				preferredSeen = true
			}
		}
		if !preferredSeen {
			return fmt.Errorf("version_family[%d] preferred ID is not a member", i)
		}
	}
	for i, rule := range r.RetiredModels {
		if err := validateSource(rule.Source); err != nil {
			return fmt.Errorf("retired_model[%d]: %w", i, err)
		}
		if !validID(rule.UpstreamID) || !validID(rule.PublicID) || !approved(rule.Decision, rule.Evidence, rule.ReviewedAt) {
			return fmt.Errorf("retired_model[%d] is incomplete or unapproved", i)
		}
	}
	ownerLifecycleSeen := map[string]bool{}
	for i, exclusion := range r.OwnerLifecycleExclusions {
		if !validProductLifecycleScope(exclusion.Scope) || !validID(exclusion.ModelID) || !approved(exclusion.Decision, exclusion.Evidence, exclusion.ReviewedAt) {
			return fmt.Errorf("owner_lifecycle_exclusion[%d] is incomplete or invalid", i)
		}
		key := exclusion.Scope + "\x00" + exclusion.ModelID
		if ownerLifecycleSeen[key] {
			return fmt.Errorf("owner_lifecycle_exclusion[%d] duplicates an exact scope/model", i)
		}
		ownerLifecycleSeen[key] = true
	}
	sourceProfileKeys := map[string]bool{}
	for i, profile := range r.SourceProfiles {
		if err := validateSource(profile.Source); err != nil {
			return fmt.Errorf("source_profile[%d]: %w", i, err)
		}
		policy := profile.IdentityAddPolicy
		if policy == "" {
			policy = "report_only"
		}
		identityCatalogPolicy := profile.IdentityCatalogPolicy
		if strings.TrimSpace(profile.BuildID) == "" || (profile.APIContractID != "admin-catalog-v1" && profile.APIContractID != "admin-catalog-all-v1") || !approved(profile.Decision, profile.Evidence, profile.ReviewedAt) || (policy != "report_only" && policy != "add_exact") || (identityCatalogPolicy != "" && identityCatalogPolicy != "replace_identity_from_live_list" && identityCatalogPolicy != "add_identity_from_live_list") || (profile.OfficialSelectabilityScope != "" && !validOfficialSelectabilityScope(profile.OfficialSelectabilityScope)) || (profile.OfficialSelectabilityProduct != "" && profile.OfficialSelectabilityProduct != "api" && profile.OfficialSelectabilityProduct != "ui") || !validOfficialSelectabilityProductBinding(profile) {
			return fmt.Errorf("source_profile[%d] is incomplete or invalid", i)
		}
		seenScopes := map[string]bool{}
		for _, scope := range profile.LifecycleScopes {
			if !validProductLifecycleScope(scope) || seenScopes[scope] {
				return fmt.Errorf("source_profile[%d] contains an invalid or duplicate lifecycle scope", i)
			}
			seenScopes[scope] = true
		}
		key := sourceProfileKey(profile)
		if sourceProfileKeys[key] {
			return fmt.Errorf("source_profile[%d] duplicates a source/build/API profile", i)
		}
		sourceProfileKeys[key] = true
	}
	selectabilityByScope := make(map[string]OfficialSelectability, len(r.OfficialSelectability))
	for i, snapshot := range r.OfficialSelectability {
		if !validOfficialSelectabilityScope(snapshot.Scope) || !snapshot.Complete || len(snapshot.ModelIDs) == 0 || snapshot.ObservedAt.IsZero() || snapshot.ExpiresAt.IsZero() || !snapshot.ExpiresAt.After(snapshot.ObservedAt) || snapshot.ExpiresAt.Sub(snapshot.ObservedAt) > OfficialSelectabilityMaxAge || strings.TrimSpace(snapshot.Evidence) == "" {
			return fmt.Errorf("official_selectability[%d] is incomplete or invalid", i)
		}
		ids := make(map[string]bool, len(snapshot.ModelIDs))
		for _, id := range snapshot.ModelIDs {
			if !validID(id) || IsWildcard(id) || ids[id] {
				return fmt.Errorf("official_selectability[%d] has an invalid or duplicate model ID", i)
			}
			ids[id] = true
		}
		if _, exists := selectabilityByScope[snapshot.Scope]; exists {
			return fmt.Errorf("official_selectability[%d] duplicates a scope", i)
		}
		selectabilityByScope[snapshot.Scope] = snapshot
	}
	for i, profile := range r.CompleteCatalogProfiles {
		if err := validateSource(profile.Source); err != nil {
			return fmt.Errorf("complete_catalog_profile[%d]: %w", i, err)
		}
		if !validID(profile.ProfileID) || profile.Evidence == "" || !validReviewDate(profile.ReviewedAt) {
			return fmt.Errorf("complete_catalog_profile[%d] is incomplete", i)
		}
		if _, implemented := implementedCompleteProfiles[profile.ProfileID]; !implemented {
			return fmt.Errorf("complete_catalog_profile[%d] selects an unimplemented completeness profile", i)
		}
	}
	return nil
}

func validOfficialSelectabilityProductBinding(profile SourceProfile) bool {
	switch profile.OfficialSelectabilityProduct {
	case "":
		return profile.OfficialSelectabilityScope == "" && profile.OfficialSelectabilityProvider == ""
	case "api":
		switch profile.OfficialSelectabilityProvider {
		case "openai-api", "anthropic-api", "xai-api", "deepseek-api":
			return profile.OfficialSelectabilityScope != ""
		default:
			return false
		}
	case "ui":
		return profile.OfficialSelectabilityScope != "" && profile.OfficialSelectabilityProvider == ""
	default:
		return false
	}
}

func validProductLifecycleScope(scope string) bool {
	switch scope {
	case "openai_codex_chatgpt_login", "anthropic_claude_code_login", "kimi_code_login":
		return true
	default:
		return false
	}
}

// Official selectability belongs to a concrete upstream account identity, not
// to a provider or protocol category. Use a stable, non-secret operator alias
// so one account's visible model list cannot silently govern every account of
// the same protocol. Multiple profiles may share the alias only when they
// intentionally use the same official account.
func validOfficialSelectabilityScope(scope string) bool {
	const prefix = "official-account:"
	if !strings.HasPrefix(scope, prefix) || len(scope) <= len(prefix) || len(scope) > 128 {
		return false
	}
	alias := scope[len(prefix):]
	for _, r := range alias {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return alias[0] != '.' && alias[0] != '-' && alias[0] != '_'
}

func sourceProfileKey(profile SourceProfile) string {
	return SourceFingerprint(profile.Source) + "\x00" + profile.BuildID + "\x00" + profile.APIContractID
}

func (r Rules) MatchSourceProfile(source Source, buildID, apiContractID string) (SourceProfile, bool) {
	var match SourceProfile
	found := false
	for _, profile := range r.SourceProfiles {
		if profile.BuildID != buildID || profile.APIContractID != apiContractID || profile.Decision != "approved" || !SourceMatches(profile.Source, source) {
			continue
		}
		if found {
			return SourceProfile{}, false
		}
		match = profile
		found = true
	}
	if match.IdentityAddPolicy == "" {
		match.IdentityAddPolicy = "report_only"
	}
	return match, found
}

func (r Rules) MatchCompleteCatalogProfile(source Source) (CompleteCatalogProfile, bool) {
	var match CompleteCatalogProfile
	found := false
	for _, profile := range r.CompleteCatalogProfiles {
		if !SourceMatches(profile.Source, source) {
			continue
		}
		if _, implemented := implementedCompleteProfiles[profile.ProfileID]; !implemented || found {
			return CompleteCatalogProfile{}, false
		}
		match = profile
		found = true
	}
	return match, found
}

func (r Rules) OfficialSelectabilityForScope(scope string) (OfficialSelectability, bool) {
	if !validOfficialSelectabilityScope(scope) {
		return OfficialSelectability{}, false
	}
	for _, snapshot := range r.OfficialSelectability {
		if snapshot.Scope == scope {
			return snapshot, true
		}
	}
	return OfficialSelectability{}, false
}

func approved(decision, evidence, reviewedAt string) bool {
	return decision == "approved" && strings.TrimSpace(evidence) != "" && validReviewDate(reviewedAt)
}

func validReviewDate(v string) bool {
	if !validDate.MatchString(v) {
		return false
	}
	_, err := timeParseDate(v)
	return err == nil
}

// Kept as a small indirection so rule date validation has no locale dependency.
func timeParseDate(v string) (string, error) {
	parsed, err := time.Parse("2006-01-02", v)
	if err != nil || parsed.Format("2006-01-02") != v {
		return "", errors.New("invalid date")
	}
	return parsed.Format("2006-01-02"), nil
}

func validID(v string) bool {
	return strings.TrimSpace(v) != "" && v == strings.TrimSpace(v) && !strings.ContainsAny(v, "\x00\r\n")
}

func validateSource(s Source) error {
	if s.Platform == "" || s.AccountType == "" || s.BaseURL == "" || s.AccountID < 0 {
		return errors.New("source identity is incomplete")
	}
	if _, err := NormalizeBaseURL(s.BaseURL); err != nil {
		return errors.New("source base_url is invalid")
	}
	return nil
}

func NormalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid source URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", errors.New("unsupported source URL scheme")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func SourceForAccount(platform, accountType, protocol, baseURL string, id int64) (Source, error) {
	normalized, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return Source{}, err
	}
	return Source{Platform: platform, AccountType: accountType, APIProtocol: protocol, BaseURL: normalized, AccountID: id}, nil
}

func SourceMatches(rule, actual Source) bool {
	ruleURL, e1 := NormalizeBaseURL(rule.BaseURL)
	actualURL, e2 := NormalizeBaseURL(actual.BaseURL)
	return e1 == nil && e2 == nil && rule.Platform == actual.Platform && rule.AccountType == actual.AccountType && rule.APIProtocol == actual.APIProtocol && ruleURL == actualURL && (rule.AccountID == 0 || rule.AccountID == actual.AccountID)
}

// No complete-catalog provider profiles are accepted in this release.
// A reviewed profile needs its own parser, evidence and tests before registration.
var implementedCompleteProfiles = map[string]struct{}{}

func MappingHash(mapping map[string]string) (string, error) {
	return canonicalHash(mapping)
}
