package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const MaxConfigBytes = 1 << 20
const APIContractCatalogV1 = "admin-catalog-v1"
const APIContractAllAccountsV1 = "admin-catalog-all-v1"

var hashPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

type Config struct {
	Target                                    TargetConfig                  `json:"target"`
	AccountScope                              string                        `json:"account_scope,omitempty"`
	AcceptAllCredentialResponseMemoryExposure bool                          `json:"accept_all_credential_response_memory_exposure,omitempty"`
	RequireManualOnlyMode                     bool                          `json:"require_manual_only_mode,omitempty"`
	AllowFullScreenMode                       bool                          `json:"allow_full_screen_mode,omitempty"`
	Accounts                                  []AccountConfig               `json:"accounts"`
	AllowNativeSyncMetadataWrite              bool                          `json:"allow_native_sync_metadata_write"`
	ApplyMode                                 string                        `json:"apply_mode"`
	ApprovedRulesSHA256                       string                        `json:"approved_rules_sha256"`
	Credential                                CredentialConfig              `json:"credential"`
	StateDir                                  string                        `json:"state_dir,omitempty"`
	ReportDir                                 string                        `json:"report_dir,omitempty"`
	BackupDir                                 string                        `json:"backup_dir,omitempty"`
	RulesFile                                 string                        `json:"rules_file,omitempty"`
	OfficialSelectabilitySources              []OfficialSelectabilitySource `json:"official_selectability_sources,omitempty"`
}

// OfficialSelectabilitySource binds one stable official-account scope to a
// fixed provider API adapter and an OS-protected API credential reference.
// Endpoints are intentionally not configurable.
type OfficialSelectabilitySource struct {
	Scope      string           `json:"scope"`
	Provider   string           `json:"provider"`
	Product    string           `json:"product"`
	Credential CredentialConfig `json:"credential"`
}

type TargetConfig struct {
	BaseURL              string               `json:"base_url"`
	RuntimeCompatibility RuntimeCompatibility `json:"runtime_compatibility"`
}

type RuntimeCompatibility struct {
	BuildID       string `json:"build_id"`
	APIContractID string `json:"api_contract_id"`
	Evidence      string `json:"evidence"`
	ReviewedAt    string `json:"reviewed_at"`
}

type AccountConfig struct {
	ID                                     int64 `json:"id"`
	AcceptCredentialResponseMemoryExposure *bool `json:"accept_credential_response_memory_exposure"`
}

type CredentialConfig struct {
	WindowsCredentialTarget string `json:"windows_credential_target"`
	SystemdCredentialName   string `json:"systemd_credential_name"`
}

func Load(path string) (Config, error) {
	var cfg Config
	file, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return cfg, errors.New("stat config failed")
	}
	if !info.Mode().IsRegular() || info.Size() > MaxConfigBytes {
		return cfg, errors.New("config must be a regular file within the size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxConfigBytes+1))
	if err != nil || len(data) > MaxConfigBytes {
		return cfg, errors.New("read config failed or size limit exceeded")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid config: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return cfg, err
	}
	if cfg.Credential.WindowsCredentialTarget == "" && cfg.Credential.SystemdCredentialName == "" {
		cfg.Credential = DefaultCredentialConfig()
	}
	baseDir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return cfg, errors.New("config directory could not be resolved")
	}
	if cfg.StateDir == "" {
		cfg.StateDir = filepath.Join(baseDir, "state")
	}
	if cfg.ReportDir == "" {
		cfg.ReportDir = filepath.Join(baseDir, "reports")
	}
	if cfg.BackupDir == "" {
		cfg.BackupDir = filepath.Join(baseDir, "backups")
	}
	if cfg.RulesFile == "" {
		cfg.RulesFile = filepath.Join(baseDir, "model-rules.json")
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func DefaultCredentialConfig() CredentialConfig {
	if runtime.GOOS == "windows" {
		return CredentialConfig{WindowsCredentialTarget: "Sub2API 404token Admin API Key"}
	}
	if runtime.GOOS == "linux" {
		return CredentialConfig{SystemdCredentialName: "admin-api-key"}
	}
	return CredentialConfig{}
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("config must contain exactly one JSON value")
	}
	return nil
}

func (c Config) Validate() error {
	if _, err := ValidateBaseURL(c.Target.BaseURL); err != nil {
		return fmt.Errorf("target.base_url: %w", err)
	}
	scope := c.AccountScopeValue()
	if scope != "allowlist" && scope != "all" {
		return errors.New("account_scope must be allowlist or all")
	}
	if scope == "all" {
		if len(c.Accounts) != 0 {
			return errors.New("accounts must be empty when account_scope is all")
		}
	} else if len(c.Accounts) == 0 {
		return errors.New("accounts must explicitly list at least one account ID in allowlist mode")
	}
	seen := map[int64]bool{}
	for _, account := range c.Accounts {
		if account.ID <= 0 || seen[account.ID] {
			return errors.New("accounts must contain unique positive IDs")
		}
		seen[account.ID] = true
		if account.AcceptCredentialResponseMemoryExposure == nil {
			return fmt.Errorf("account %d must explicitly set accept_credential_response_memory_exposure", account.ID)
		}
	}
	if c.RequireManualOnlyMode && scope != "all" {
		return errors.New("require_manual_only_mode requires account_scope=all")
	}
	if c.AllowFullScreenMode {
		if scope != "all" {
			return errors.New("allow_full_screen_mode requires account_scope=all")
		}
		if c.RequireManualOnlyMode {
			return errors.New("allow_full_screen_mode cannot be combined with require_manual_only_mode")
		}
		if !c.AllowNativeSyncMetadataWrite {
			return errors.New("allow_full_screen_mode requires allow_native_sync_metadata_write=true")
		}
	}
	if strings.TrimSpace(c.Credential.WindowsCredentialTarget) == "" && strings.TrimSpace(c.Credential.SystemdCredentialName) == "" {
		return errors.New("a Windows Credential Manager target or systemd credential name is required")
	}
	if c.Credential.WindowsCredentialTarget != "" && c.Credential.SystemdCredentialName != "" {
		return errors.New("configure exactly one OS credential source")
	}
	if c.Credential.SystemdCredentialName != "" && !safeCredentialName(c.Credential.SystemdCredentialName) {
		return errors.New("systemd_credential_name must be a simple file name")
	}
	if c.ApplyMode != "" && c.ApplyMode != "preview" && c.ApplyMode != "approved_rules" {
		return errors.New("apply_mode must be preview or approved_rules")
	}
	if c.ApprovedRulesSHA256 != "" {
		if !hashPattern.MatchString(c.ApprovedRulesSHA256) {
			return errors.New("approved_rules_sha256 must be a SHA256 hex digest")
		}
		if _, err := hex.DecodeString(c.ApprovedRulesSHA256); err != nil {
			return errors.New("approved_rules_sha256 is invalid")
		}
	}
	if !validCompatibilityDateOrEmpty(c.Target.RuntimeCompatibility.ReviewedAt) {
		return errors.New("runtime compatibility reviewed_at must be YYYY-MM-DD when set")
	}
	for _, dir := range []string{c.StateDir, c.ReportDir, c.BackupDir} {
		if strings.ContainsRune(dir, '\x00') {
			return errors.New("local data directories contain an invalid path")
		}
	}
	if strings.ContainsRune(c.RulesFile, '\x00') {
		return errors.New("rules_file contains an invalid path")
	}
	if len(c.OfficialSelectabilitySources) > 100 {
		return errors.New("official_selectability_sources exceeds the configured limit")
	}
	officialScopes := map[string]bool{}
	for i, source := range c.OfficialSelectabilitySources {
		if !validOfficialScope(source.Scope) || officialScopes[source.Scope] {
			return fmt.Errorf("official_selectability_sources[%d] has an invalid or duplicate scope", i)
		}
		officialScopes[source.Scope] = true
		if source.Product != "api" {
			return fmt.Errorf("official_selectability_sources[%d] must bind an API product; UI selectors require a product-specific adapter", i)
		}
		switch source.Provider {
		case "openai-api", "anthropic-api", "xai-api", "deepseek-api":
		default:
			return fmt.Errorf("official_selectability_sources[%d] uses an unsupported provider adapter", i)
		}
		credential := source.Credential
		if (strings.TrimSpace(credential.WindowsCredentialTarget) == "") == (strings.TrimSpace(credential.SystemdCredentialName) == "") {
			return fmt.Errorf("official_selectability_sources[%d] must configure exactly one OS credential reference", i)
		}
		if credential.WindowsCredentialTarget != "" && len(credential.WindowsCredentialTarget) > 256 {
			return fmt.Errorf("official_selectability_sources[%d] has an invalid Windows credential reference", i)
		}
		if credential.SystemdCredentialName != "" && !safeCredentialName(credential.SystemdCredentialName) {
			return fmt.Errorf("official_selectability_sources[%d] has an invalid systemd credential reference", i)
		}
	}
	return nil
}

func validOfficialScope(scope string) bool {
	const prefix = "official-account:"
	if !strings.HasPrefix(scope, prefix) || len(scope) > 128 || strings.TrimSpace(scope) != scope {
		return false
	}
	alias := strings.TrimPrefix(scope, prefix)
	if alias == "" || strings.ContainsAny(alias[:1], "._-") {
		return false
	}
	for _, r := range alias {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.", r)) {
			return false
		}
	}
	return true
}

func (c Config) RuntimeCompatible() bool {
	r := c.Target.RuntimeCompatibility
	expectedContract := APIContractCatalogV1
	if c.AllAccounts() {
		expectedContract = APIContractAllAccountsV1
	}
	return strings.TrimSpace(r.BuildID) != "" && r.APIContractID == expectedContract && strings.TrimSpace(r.Evidence) != "" && validCompatibilityDateOrEmpty(r.ReviewedAt) && r.ReviewedAt != ""
}

func (c Config) ApplyModeValue() string {
	if c.ApplyMode == "" {
		return "preview"
	}
	return c.ApplyMode
}

func (c Config) OfficialSelectabilityFile() string {
	return filepath.Join(c.StateDir, "official-selectability.json")
}

func (c Config) IDs() []int64 {
	ids := make([]int64, 0, len(c.Accounts))
	for _, account := range c.Accounts {
		ids = append(ids, account.ID)
	}
	return ids
}

func (c Config) AccountScopeValue() string {
	if strings.TrimSpace(c.AccountScope) == "" {
		return "allowlist"
	}
	return c.AccountScope
}

func (c Config) AllAccounts() bool { return c.AccountScopeValue() == "all" }

func (c Config) IsAllowlisted(id int64) bool {
	for _, account := range c.Accounts {
		if account.ID == id {
			return true
		}
	}
	return false
}

func (c Config) AcceptsCredentialMemoryExposure(id int64) bool {
	for _, account := range c.Accounts {
		if account.ID == id {
			return account.AcceptCredentialResponseMemoryExposure != nil && *account.AcceptCredentialResponseMemoryExposure
		}
	}
	return false
}

func (c Config) EligibleAccountIDs() []int64 {
	ids := []int64{}
	for _, account := range c.Accounts {
		if account.AcceptCredentialResponseMemoryExposure != nil && *account.AcceptCredentialResponseMemoryExposure {
			ids = append(ids, account.ID)
		}
	}
	return ids
}

func ValidateBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("URL must be a bare origin without credentials, path, query, or fragment")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme != "https" || host != "404token.xyz" || u.Port() != "" {
		return nil, errors.New("target must be the fixed HTTPS origin https://404token.xyz")
	}
	u.Scheme = scheme
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u, nil
}

func safeCredentialName(name string) bool {
	return name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsAny(name, `/\:`)
}

func validCompatibilityDateOrEmpty(v string) bool {
	if v == "" {
		return true
	}
	parsed, err := time.Parse("2006-01-02", v)
	return err == nil && parsed.Format("2006-01-02") == v
}

func (c Config) ExposureGateFor(accountIDs []int64) error {
	if c.AllAccounts() {
		if !c.AcceptAllCredentialResponseMemoryExposure {
			return errors.New("all-account mode is blocked: credential-response memory exposure was not explicitly accepted for all accounts")
		}
		if len(accountIDs) == 0 {
			return errors.New("all-account mode resolved no accounts")
		}
		for _, id := range accountIDs {
			if id <= 0 {
				return errors.New("all-account mode resolved an invalid account ID")
			}
		}
		return nil
	}
	for _, id := range accountIDs {
		if !c.IsAllowlisted(id) {
			return fmt.Errorf("account %d is blocked: it is not in the explicit account allowlist", id)
		}
		if !c.AcceptsCredentialMemoryExposure(id) {
			return fmt.Errorf("account %d is blocked: credential-response memory exposure was not explicitly accepted", id)
		}
	}
	if len(accountIDs) == 0 {
		return errors.New("no account passed the credential-response memory exposure gate")
	}
	return nil
}
