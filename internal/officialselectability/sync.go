package officialselectability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sub2api-model-catalog-manager/internal/catalog"
	"sub2api-model-catalog-manager/internal/config"
	"sub2api-model-catalog-manager/internal/securecred"
)

const (
	SchemaVersion   = 1
	AdapterVersion  = "official-api-models-v1"
	MaxAge          = 24 * time.Hour
	RequestTimeout  = 15 * time.Second
	MaxResponseSize = 2 << 20
	MaxModels       = 20000
	MaxPages        = 100
	MaxSources      = 100
)

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}
type SecretReader func(config.CredentialConfig) (securecred.Value, error)

type snapshotRecord struct {
	Scope          string    `json:"scope"`
	Provider       string    `json:"provider"`
	Product        string    `json:"product"`
	AdapterVersion string    `json:"adapter_version"`
	BindingSHA256  string    `json:"binding_sha256"`
	Complete       bool      `json:"complete"`
	ModelIDs       []string  `json:"model_ids"`
	ObservedAt     time.Time `json:"observed_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Evidence       string    `json:"evidence"`
}

type bundle struct {
	SchemaVersion int              `json:"schema_version"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Snapshots     []snapshotRecord `json:"snapshots"`
}

// ValidateRuleBindings prevents API-product scopes from silently falling back
// to manually pasted snapshots and prevents a credential for one provider
// from governing a different product scope. UI scopes remain manual until
// that product's official selector has a supported adapter.
func ValidateRuleBindings(rules catalog.Rules, sources []config.OfficialSelectabilitySource) error {
	configured := make(map[string]config.OfficialSelectabilitySource, len(sources))
	for _, source := range sources {
		if err := validateSource(source); err != nil {
			return errors.New("official selectability source binding is invalid")
		}
		if _, exists := configured[source.Scope]; exists {
			return errors.New("official selectability source scope is duplicated")
		}
		configured[source.Scope] = source
	}
	apiScopes := map[string]string{}
	profilesByScope := map[string]bool{}
	for _, profile := range rules.SourceProfiles {
		if profile.OfficialSelectabilityScope == "" {
			continue
		}
		scope := profile.OfficialSelectabilityScope
		if profile.OfficialSelectabilityProduct != "api" && profile.OfficialSelectabilityProduct != "ui" {
			return errors.New("official selectability scope must be explicitly classified as an API or UI product")
		}
		profilesByScope[scope] = true
		if profile.OfficialSelectabilityProduct != "api" {
			if _, hasSource := configured[scope]; hasSource {
				return errors.New("official selectability API source is bound to a non-API product scope")
			}
			continue
		}
		source, exists := configured[scope]
		if !exists {
			return errors.New("API product scope has no automatic official selectability source")
		}
		if profile.OfficialSelectabilityProvider != source.Provider {
			return errors.New("API product scope provider does not match its official source adapter")
		}
		if previous, exists := apiScopes[scope]; exists && previous != profile.OfficialSelectabilityProvider {
			return errors.New("API product scope is assigned to conflicting providers")
		}
		apiScopes[scope] = profile.OfficialSelectabilityProvider
	}
	for scope := range configured {
		if !profilesByScope[scope] || apiScopes[scope] == "" {
			return errors.New("official selectability source is not bound to an approved API product scope")
		}
	}
	return nil
}

// Refresh fetches every configured official API account source and publishes
// one all-or-nothing snapshot bundle. No gateway URL or provider response body
// is configurable or persisted.
func Refresh(ctx context.Context, path string, sources []config.OfficialSelectabilitySource, readSecret SecretReader, doer Doer, now func() time.Time) error {
	if len(sources) == 0 || len(sources) > MaxSources || readSecret == nil || doer == nil {
		return errors.New("official selectability sources are not configured safely")
	}
	if now == nil {
		now = time.Now
	}
	ordered := append([]config.OfficialSelectabilitySource(nil), sources...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Scope < ordered[j].Scope })
	seen := map[string]bool{}
	result := bundle{SchemaVersion: SchemaVersion, GeneratedAt: now().UTC(), Snapshots: make([]snapshotRecord, 0, len(ordered))}
	for _, source := range ordered {
		if seen[source.Scope] {
			return errors.New("official selectability source scopes are duplicated")
		}
		seen[source.Scope] = true
		if err := validateSource(source); err != nil {
			return err
		}
		secret, err := readSecret(source.Credential)
		if err != nil || len(secret.APIKey) == 0 {
			secret.Clear()
			return fmt.Errorf("official selectability credential unavailable for scope %s", source.Scope)
		}
		observed := now().UTC()
		ids, err := fetchIDs(ctx, source.Provider, secret.APIKey, doer)
		secret.Clear()
		if err != nil {
			return fmt.Errorf("official selectability refresh failed for scope %s: %w", source.Scope, err)
		}
		if len(ids) == 0 || len(ids) > MaxModels {
			return fmt.Errorf("official selectability response is empty or exceeds limits for scope %s", source.Scope)
		}
		record := snapshotRecord{
			Scope: source.Scope, Provider: source.Provider, Product: source.Product,
			AdapterVersion: AdapterVersion, BindingSHA256: bindingDigest(source), Complete: true,
			ModelIDs: ids, ObservedAt: observed, ExpiresAt: observed.Add(MaxAge),
			Evidence: "complete authenticated official API model-access response; adapter=" + AdapterVersion,
		}
		result.Snapshots = append(result.Snapshots, record)
	}
	if err := validateBundle(result, sources, now().UTC()); err != nil {
		return errors.New("official selectability bundle failed validation")
	}
	return writeAtomic(path, result)
}

// Load validates the persisted bundle against current source bindings and
// returns only fresh snapshots. Configured sources never fall back to older
// rules-file snapshots if their artifact is missing or invalid.
func Load(path string, sources []config.OfficialSelectabilitySource, now time.Time) ([]catalog.OfficialSelectability, error) {
	snapshots, _, err := LoadWithDigest(path, sources, now)
	return snapshots, err
}

func LoadWithDigest(path string, sources []config.OfficialSelectabilitySource, now time.Time) ([]catalog.OfficialSelectability, string, error) {
	if len(sources) == 0 {
		return nil, "", nil
	}
	if len(sources) > MaxSources {
		return nil, "", errors.New("official selectability source count exceeds limit")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 8<<20 {
		return nil, "", errors.New("official selectability snapshot is unavailable or oversized")
	}
	defer zero(data)
	fileHash := sha256.Sum256(data)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var stored bundle
	if err := dec.Decode(&stored); err != nil {
		return nil, "", errors.New("official selectability snapshot is invalid")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, "", errors.New("official selectability snapshot contains trailing data")
	}
	if err := validateBundle(stored, sources, now.UTC()); err != nil {
		return nil, "", err
	}
	out := make([]catalog.OfficialSelectability, 0, len(stored.Snapshots))
	for _, item := range stored.Snapshots {
		out = append(out, catalog.OfficialSelectability{
			Scope: item.Scope, Complete: item.Complete, ModelIDs: append([]string(nil), item.ModelIDs...),
			ObservedAt: item.ObservedAt, ExpiresAt: item.ExpiresAt, Evidence: item.Evidence,
		})
	}
	return out, hex.EncodeToString(fileHash[:]), nil
}

func validateBundle(value bundle, sources []config.OfficialSelectabilitySource, now time.Time) error {
	if value.SchemaVersion != SchemaVersion || value.GeneratedAt.IsZero() || value.GeneratedAt.After(now) || len(value.Snapshots) != len(sources) {
		return errors.New("bundle shape is invalid")
	}
	sourceByScope := make(map[string]config.OfficialSelectabilitySource, len(sources))
	for _, source := range sources {
		if err := validateSource(source); err != nil {
			return err
		}
		if _, exists := sourceByScope[source.Scope]; exists {
			return errors.New("duplicate configured scope")
		}
		sourceByScope[source.Scope] = source
	}
	seen := map[string]bool{}
	for _, item := range value.Snapshots {
		source, exists := sourceByScope[item.Scope]
		if !exists || seen[item.Scope] || !item.Complete || item.Provider != source.Provider || item.Product != source.Product || item.AdapterVersion != AdapterVersion || item.BindingSHA256 != bindingDigest(source) || item.ObservedAt.IsZero() || item.ObservedAt.After(now) || item.ExpiresAt.Sub(item.ObservedAt) != MaxAge || !item.ExpiresAt.After(now) || len(item.ModelIDs) == 0 || len(item.ModelIDs) > MaxModels || strings.TrimSpace(item.Evidence) == "" {
			return errors.New("snapshot is incomplete, stale, or bound to a different source")
		}
		ids := map[string]bool{}
		for _, id := range item.ModelIDs {
			if !validModelID(id) || ids[id] {
				return errors.New("snapshot contains invalid or duplicate model IDs")
			}
			ids[id] = true
		}
		seen[item.Scope] = true
	}
	if len(seen) != len(sourceByScope) {
		return errors.New("bundle does not cover every configured scope")
	}
	return nil
}

func validateSource(source config.OfficialSelectabilitySource) error {
	if source.Product != "api" || source.Scope == "" || source.Credential.WindowsCredentialTarget == "" && source.Credential.SystemdCredentialName == "" {
		return errors.New("official selectability source binding is incomplete")
	}
	switch source.Provider {
	case "openai-api", "anthropic-api", "xai-api", "deepseek-api":
		return nil
	default:
		return errors.New("official provider adapter is unsupported")
	}
}

func bindingDigest(source config.OfficialSelectabilitySource) string {
	body, _ := json.Marshal(struct {
		Scope            string `json:"scope"`
		Provider         string `json:"provider"`
		Product          string `json:"product"`
		CredentialTarget string `json:"credential_target"`
		CredentialName   string `json:"credential_name"`
	}{source.Scope, source.Provider, source.Product, source.Credential.WindowsCredentialTarget, source.Credential.SystemdCredentialName})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func fetchIDs(ctx context.Context, provider string, secret []byte, doer Doer) ([]string, error) {
	if len(secret) == 0 || len(secret) > 16*1024 {
		return nil, errors.New("credential has an invalid size")
	}
	base, path, authHeader, authPrefix := adapter(provider)
	if base == "" {
		return nil, errors.New("provider adapter is unsupported")
	}
	ids := make([]string, 0, 256)
	seen := map[string]bool{}
	afterID := ""
	for page := 0; page < MaxPages; page++ {
		endpoint, _ := url.Parse(base + path)
		if provider == "anthropic-api" {
			query := endpoint.Query()
			query.Set("limit", "1000")
			if afterID != "" {
				query.Set("after_id", afterID)
			}
			endpoint.RawQuery = query.Encode()
		}
		requestCtx, cancel := context.WithTimeout(ctx, RequestTimeout)
		request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			cancel()
			return nil, errors.New("official request could not be constructed")
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set(authHeader, authPrefix+string(secret))
		if provider == "anthropic-api" {
			request.Header.Set("anthropic-version", "2023-06-01")
		}
		response, err := doer.Do(request)
		if err != nil {
			cancel()
			return nil, errors.New("official endpoint request failed")
		}
		if response == nil || response.Body == nil {
			cancel()
			return nil, errors.New("official endpoint returned no response body")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, MaxResponseSize+1))
		closeErr := response.Body.Close()
		cancel()
		if readErr != nil || closeErr != nil || len(body) == 0 || len(body) > MaxResponseSize {
			zero(body)
			return nil, errors.New("official endpoint response is unreadable or oversized")
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			zero(body)
			return nil, fmt.Errorf("official endpoint returned HTTP %d", response.StatusCode)
		}
		pageIDs, hasMore, lastID, err := decodeModelPage(body)
		zero(body)
		if err != nil || len(pageIDs) == 0 {
			return nil, errors.New("official endpoint model list is empty or malformed")
		}
		for _, id := range pageIDs {
			if !validModelID(id) || seen[id] {
				return nil, errors.New("official endpoint returned invalid or duplicate model IDs")
			}
			seen[id] = true
			ids = append(ids, id)
			if len(ids) > MaxModels {
				return nil, errors.New("official endpoint model list exceeds limit")
			}
		}
		if provider != "anthropic-api" {
			if hasMore {
				return nil, errors.New("official endpoint pagination contract is unsupported")
			}
			return ids, nil
		}
		if !hasMore {
			return ids, nil
		}
		if lastID == "" || lastID != pageIDs[len(pageIDs)-1] || lastID == afterID {
			return nil, errors.New("official endpoint pagination did not advance")
		}
		afterID = lastID
	}
	return nil, errors.New("official endpoint exceeded the page limit")
}

func adapter(provider string) (base, path, header, prefix string) {
	switch provider {
	case "openai-api":
		return "https://api.openai.com", "/v1/models", "Authorization", "Bearer "
	case "anthropic-api":
		return "https://api.anthropic.com", "/v1/models", "x-api-key", ""
	case "xai-api":
		return "https://api.x.ai", "/v1/models", "Authorization", "Bearer "
	case "deepseek-api":
		return "https://api.deepseek.com", "/models", "Authorization", "Bearer "
	default:
		return "", "", "", ""
	}
}

// NewHTTPDoer pins requests to the adapter's official origin without ambient
// proxies, redirects, or relaxed TLS.
func NewHTTPDoer() Doer {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:             nil,
			DialContext:       (&net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
		Timeout:       RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func decodeModelPage(data []byte) ([]string, bool, string, error) {
	var payload struct {
		Object string `json:"object"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
		HasMore *bool  `json:"has_more"`
		LastID  string `json:"last_id"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&payload); err != nil {
		return nil, false, "", err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || payload.Data == nil || (payload.Object != "" && payload.Object != "list") {
		return nil, false, "", errors.New("invalid model list shape")
	}
	ids := make([]string, 0, len(payload.Data))
	for _, item := range payload.Data {
		ids = append(ids, item.ID)
	}
	return ids, payload.HasMore != nil && *payload.HasMore, payload.LastID, nil
}

func validModelID(id string) bool {
	if id == "" || len(id) > 512 || strings.TrimSpace(id) != id {
		return false
	}
	for _, r := range id {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

func writeAtomic(path string, value bundle) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(data) > 8<<20 {
		return errors.New("official selectability snapshot serialization failed")
	}
	defer zero(data)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("official selectability state directory could not be created")
	}
	tmp, err := os.CreateTemp(dir, ".official-selectability-*.tmp")
	if err != nil {
		return errors.New("official selectability temporary file could not be created")
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return errors.New("official selectability permissions could not be restricted")
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return errors.New("official selectability snapshot write failed")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return errors.New("official selectability snapshot flush failed")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("official selectability snapshot close failed")
	}
	if err := atomicReplace(tmpName, path); err != nil {
		return errors.New("official selectability snapshot atomic replace failed")
	}
	return syncDirectory(dir)
}

func zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
