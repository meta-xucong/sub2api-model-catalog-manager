package officialcatalog

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

const (
	SchemaVersion       = 2
	MaxInputReportBytes = 8 << 20
	MaxModelIDBytes     = 512
	MaxAccounts         = 5000
	MaxModelsPerAccount = 20000
	MaxTotalModels      = 50000
	MaxResponseBytes    = 2 << 20
)

type InputModel struct {
	AccountID         int64  `json:"account_id"`
	SourceFingerprint string `json:"source_fingerprint,omitempty"`
	Platform          string `json:"platform,omitempty"`
	AccountType       string `json:"account_type,omitempty"`
	APIProtocol       string `json:"api_protocol,omitempty"`
	ModelID           string `json:"model_id"`
	ObservedAs        string `json:"observed_as"`
}

type InputMetadata struct {
	CreatedAt              string
	AccountScope           string
	AccountScanStatus      string
	AccountInventoryCount  int
	AccountInventorySHA256 string
	TargetBuildFingerprint string
}

type InputAccount struct {
	ID                int64
	SourceFingerprint string
	Platform          string
	AccountType       string
	APIProtocol       string
}

type MappingEdge struct {
	AccountID         int64
	SourceFingerprint string
	Platform          string
	AccountType       string
	APIProtocol       string
	PublicID          string
	UpstreamID        string
}

type DiscoveryRecord struct {
	AccountID         int64
	SourceFingerprint string
	Status            string
	LiveListAvailable bool
	Models            []string
}

type Inventory struct {
	Mode             string            `json:"mode"`
	Digest           string            `json:"digest"`
	Observations     []InputModel      `json:"observations"`
	Metadata         InputMetadata     `json:"-"`
	AccountRowIDs    []int64           `json:"-"`
	DiscoveryRowIDs  []int64           `json:"-"`
	Accounts         []InputAccount    `json:"-"`
	Mappings         []MappingEdge     `json:"-"`
	DiscoveryRecords []DiscoveryRecord `json:"-"`
}

type inputAccount struct {
	ID                int64          `json:"account_id"`
	SourceFingerprint string         `json:"source_fingerprint,omitempty"`
	Platform          string         `json:"platform,omitempty"`
	AccountType       string         `json:"account_type,omitempty"`
	APIProtocol       string         `json:"api_protocol,omitempty"`
	Mappings          []inputMapping `json:"mappings,omitempty"`
	DiscoveredModels  []string       `json:"discovered_models,omitempty"`
}

type inputMapping struct {
	PublicID   string `json:"public_id"`
	UpstreamID string `json:"upstream_id"`
}

type LifecycleEvidence struct {
	Provider      string    `json:"provider"`
	SourceID      string    `json:"source_id"`
	Scope         string    `json:"scope"`
	ModelID       string    `json:"model_id"`
	Status        string    `json:"status"`
	AnnouncedAt   string    `json:"announced_at,omitempty"`
	EffectiveAt   string    `json:"effective_at,omitempty"`
	Replacement   string    `json:"replacement,omitempty"`
	SourceURL     string    `json:"source_url"`
	SourceTitle   string    `json:"source_title"`
	RetrievedAt   time.Time `json:"retrieved_at"`
	ContentSHA256 string    `json:"content_sha256"`
	Excerpt       string    `json:"excerpt"`
}

type CachedPage struct {
	URL               string              `json:"url"`
	Title             string              `json:"title"`
	ContentSHA256     string              `json:"content_sha256"`
	FetchedAt         time.Time           `json:"fetched_at"`
	CatalogTotal      int                 `json:"catalog_total,omitempty"`
	CatalogPageNo     int                 `json:"catalog_page_no,omitempty"`
	CatalogPageSize   int                 `json:"catalog_page_size,omitempty"`
	ETag              string              `json:"etag,omitempty"`
	LastModified      string              `json:"last_modified,omitempty"`
	Links             []string            `json:"links,omitempty"`
	Evidence          []LifecycleEvidence `json:"evidence,omitempty"`
	AvailableModelIDs []string            `json:"available_model_ids,omitempty"`
}

type CatalogSnapshot struct {
	SourceID      string              `json:"source_id"`
	Provider      string              `json:"provider"`
	Scope         string              `json:"scope"`
	Pages         []CachedPage        `json:"pages"`
	Evidence      []LifecycleEvidence `json:"evidence"`
	FetchedAt     time.Time           `json:"fetched_at"`
	CheckedAt     time.Time           `json:"checked_at"`
	ContentSHA256 string              `json:"content_sha256"`
	Complete      bool                `json:"complete"`
}

type ProviderSync struct {
	SourceID       string           `json:"source_id"`
	Provider       string           `json:"provider"`
	Scope          string           `json:"scope"`
	Status         string           `json:"status"`
	ErrorCode      string           `json:"error_code,omitempty"`
	FetchedAt      *time.Time       `json:"fetched_at,omitempty"`
	CheckedAt      *time.Time       `json:"checked_at,omitempty"`
	EvidenceCount  int              `json:"evidence_count"`
	CachePersisted bool             `json:"cache_persisted"`
	Coalesced      bool             `json:"coalesced,omitempty"`
	Snapshot       *CatalogSnapshot `json:"-"`
	SourceURL      string           `json:"source_url"`
	PageTitle      string           `json:"page_title,omitempty"`
	ContentSHA256  string           `json:"content_sha256,omitempty"`
	Limitation     string           `json:"limitation"`
}

type StartupSyncResult struct {
	Providers []ProviderSync `json:"providers"`
}

type StartupSyncOptions struct {
	Offline           bool
	CacheDir          string
	ArkCredentialFile string
	LookupEnv         func(string) (string, bool)
	userCacheDir      func() (string, error)
	proxyResolver     func(*http.Request) (*url.URL, error)
	NewDoer           func() HTTPDoer
	Now               func() time.Time
	cachePrepared     bool
	cachePrepareError string
	startupTimeout    time.Duration
	requestTimeout    time.Duration
	acquireInitLock   func(context.Context, string) (osFileLock, error)
	acquireScopeLock  func(context.Context, string) (osFileLock, error)
}

type ProviderResult struct {
	SourceID       string     `json:"source_id"`
	Provider       string     `json:"provider"`
	Scope          string     `json:"scope"`
	Status         string     `json:"status"`
	SyncStatus     string     `json:"startup_sync_status,omitempty"`
	CachePersisted bool       `json:"cache_persisted,omitempty"`
	LastFetchedAt  *time.Time `json:"last_fetched_at,omitempty"`
	LastCheckedAt  *time.Time `json:"last_checked_at,omitempty"`
	EvidenceCount  int        `json:"evidence_count"`
	ErrorCode      string     `json:"error_code,omitempty"`
	Limitation     string     `json:"limitation"`
	SourceURL      string     `json:"source_url"`
	PageTitle      string     `json:"page_title,omitempty"`
	ContentSHA256  string     `json:"content_sha256,omitempty"`
}

type Reference struct {
	SourceID      string    `json:"source_id"`
	Provider      string    `json:"provider"`
	Scope         string    `json:"scope"`
	ModelID       string    `json:"model_id"`
	MatchKind     string    `json:"match_kind"`
	Status        string    `json:"status"`
	AnnouncedAt   string    `json:"announced_at,omitempty"`
	EffectiveAt   string    `json:"effective_at,omitempty"`
	Replacement   string    `json:"replacement,omitempty"`
	SourceURL     string    `json:"source_url"`
	SourceTitle   string    `json:"source_title"`
	RetrievedAt   time.Time `json:"retrieved_at"`
	ContentSHA256 string    `json:"content_sha256"`
	Excerpt       string    `json:"excerpt"`
	Conflict      bool      `json:"conflict,omitempty"`
}

type Observation struct {
	AccountID         int64       `json:"account_id"`
	SourceFingerprint string      `json:"source_fingerprint,omitempty"`
	Platform          string      `json:"platform,omitempty"`
	AccountType       string      `json:"account_type,omitempty"`
	APIProtocol       string      `json:"api_protocol,omitempty"`
	ModelID           string      `json:"model_id"`
	ObservedAs        string      `json:"observed_as"`
	Status            string      `json:"status"`
	MultipleRefs      bool        `json:"multiple_official_references,omitempty"`
	Matches           []Reference `json:"official_references,omitempty"`
	Warning           string      `json:"warning"`
}

// LifecycleExclusion is an exact, evidence-backed upstream ID that is
// ineligible for import/remains removed within one explicitly authorized
// product scope. It carries no credentials or intermediary routing data.
type LifecycleExclusion struct {
	Provider      string    `json:"provider"`
	SourceID      string    `json:"source_id"`
	Scope         string    `json:"scope"`
	ModelID       string    `json:"model_id"`
	Status        string    `json:"status"`
	EffectiveAt   string    `json:"effective_at,omitempty"`
	Replacement   string    `json:"replacement,omitempty"`
	SourceURL     string    `json:"source_url"`
	SourceTitle   string    `json:"source_title"`
	RetrievedAt   time.Time `json:"retrieved_at"`
	ContentSHA256 string    `json:"content_sha256"`
	Excerpt       string    `json:"excerpt"`
	OwnerRule     bool      `json:"owner_rule,omitempty"`
}

type AvailableModelCatalog struct {
	SourceID      string    `json:"source_id"`
	SourceIDs     []string  `json:"source_ids,omitempty"`
	Provider      string    `json:"provider"`
	Scope         string    `json:"scope"`
	ModelIDs      []string  `json:"model_ids"`
	Complete      bool      `json:"complete_accepted_union"`
	SourceURL     string    `json:"source_url"`
	SourceTitle   string    `json:"source_title"`
	RetrievedAt   time.Time `json:"retrieved_at"`
	ContentSHA256 string    `json:"content_sha256"`
}

// ProductModelAvailability records whether exact official product evidence
// permits a model ID to enter an automatic identity mapping. A missing ID on
// an incomplete page is insufficient evidence, never a negative decision.
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

type NameShapeCandidate struct {
	AccountID      int64  `json:"account_id"`
	FullModelID    string `json:"full_model_id"`
	ObservedPrefix string `json:"observed_prefix"`
	Label          string `json:"label"`
	Action         string `json:"action"`
	Equivalence    string `json:"equivalence"`
}

type Report struct {
	SchemaVersion   int                  `json:"schema_version"`
	ReportID        string               `json:"report_id"`
	CreatedAt       time.Time            `json:"created_at"`
	InputReportMode string               `json:"input_report_mode"`
	InputDigest     string               `json:"input_whitelist_sha256"`
	ProviderResults []ProviderResult     `json:"providers"`
	Observations    []Observation        `json:"observations"`
	NameShape       []NameShapeCandidate `json:"name_shape_candidates"`
	GlobalWarning   string               `json:"warning"`
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type osFileLock interface {
	Close() error
	Waited() bool
}
