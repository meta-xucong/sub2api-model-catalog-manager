package officialcatalog

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const cacheVersion = 6

type diskSnapshot struct {
	Version  int             `json:"version"`
	SourceID string          `json:"source_id"`
	Snapshot CatalogSnapshot `json:"snapshot"`
}

var (
	startupLocalLocks sync.Map
)

func SyncStartup(ctx context.Context, options StartupSyncOptions) StartupSyncResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.CacheDir == "" {
		cacheDir := options.userCacheDir
		if cacheDir == nil {
			cacheDir = os.UserCacheDir
		}
		if base, err := cacheDir(); err == nil {
			options.CacheDir = filepath.Join(base, "sub2api-model-catalog-manager", "official-lifecycle")
		}
	}
	result := StartupSyncResult{Providers: make([]ProviderSync, len(sourceManifest))}
	for i, spec := range sourceManifest {
		result.Providers[i] = ProviderSync{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: "unavailable", SourceURL: spec.rootURL, Limitation: spec.limitation}
	}
	if options.Offline {
		for i, spec := range sourceManifest {
			result.Providers[i] = loadOffline(spec, options)
		}
		return result
	}
	if options.CacheDir == "" {
		for i := range sourceManifest {
			result.Providers[i].ErrorCode = "private_cache_unavailable"
		}
		return result
	}
	if err := validateConfiguredProxy(options.proxyResolver); err != nil {
		for i := range sourceManifest {
			result.Providers[i].ErrorCode = "proxy_configuration_rejected"
		}
		return result
	}
	globalTimeout := options.startupTimeout
	if globalTimeout <= 0 {
		globalTimeout = StartupSyncTimeout
	}
	global, cancel := context.WithTimeout(ctx, globalTimeout)
	defer cancel()
	if err := preparePersistentCache(global, options.CacheDir, options.acquireInitLock); err != nil {
		for i := range sourceManifest {
			result.Providers[i].ErrorCode = "private_cache_unavailable"
		}
		return result
	}
	factory := options.NewDoer
	if factory == nil {
		factory = func() HTTPDoer { return NewHTTPClient() }
	}
	doer := factory()
	if doer == nil {
		for i := range result.Providers {
			result.Providers[i].ErrorCode = "http_client_unavailable"
		}
		return result
	}
	budget := &requestBudget{}
	semaphore := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, spec := range sourceManifest {
		wg.Add(1)
		go func(index int, source sourceSpec) {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
			case <-global.Done():
				result.Providers[index] = failureWithLastGood(source, options, "timeout")
				return
			}
			defer func() { <-semaphore }()
			result.Providers[index] = syncOneSource(global, source, options, doer, budget)
		}(i, spec)
	}
	wg.Wait()
	return result
}

func syncOneSource(ctx context.Context, spec sourceSpec, options StartupSyncOptions, doer HTTPDoer, budget *requestBudget) ProviderSync {
	started := options.Now().UTC()
	var arkCreds *arkCredentials
	var modelStudioAPIKey string
	if spec.adapter == "volcengine_ark" {
		credentialFile := options.ArkCredentialFile
		if credentialFile == "" {
			lookup := options.LookupEnv
			if lookup == nil {
				lookup = os.LookupEnv
			}
			credentialFile, _ = lookup("VOLCENGINE_ARK_CREDENTIAL_FILE")
		}
		if strings.TrimSpace(credentialFile) == "" {
			return statusFromError(spec, nil, "credential_not_configured")
		}
		credentials, err := loadArkCredentials(credentialFile)
		if err != nil {
			return statusFromError(spec, nil, err.Error())
		}
		defer zero(credentials.secretKey)
		accountHash := sha256.Sum256([]byte(credentials.accessKeyID))
		spec.cacheScope = hex.EncodeToString(accountHash[:])
		arkCreds = &credentials
	} else if spec.adapter == "alibaba_model_studio" {
		lookup := options.LookupEnv
		if lookup == nil {
			lookup = os.LookupEnv
		}
		var credentialErr error
		modelStudioAPIKey, credentialErr = modelStudioAPIKeyFromEnv(lookup)
		if credentialErr != nil {
			err := credentialErr
			return statusFromError(spec, nil, err.Error())
		}
		accountHash := sha256.Sum256([]byte(modelStudioAPIKey))
		spec.cacheScope = hex.EncodeToString(accountHash[:])
	}
	lockFn := options.acquireScopeLock
	if lockFn == nil {
		lockFn = acquireOSLock
	}
	lockCtx, cancel := context.WithTimeout(ctx, StartupSyncTimeout)
	defer cancel()
	cacheDir := sourceCacheDir(options.CacheDir, spec)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return failureWithLastGood(spec, options, "private_cache_unavailable")
	}
	lockPath := filepath.Join(cacheDir, "sync.lock")
	if err := securePrivateDir(filepath.Dir(lockPath)); err != nil && !os.IsNotExist(err) {
		return failureWithLastGood(spec, options, "private_cache_unavailable")
	}
	before, beforeErr := readSourceSnapshot(options.CacheDir, spec)
	lock, err := lockFn(lockCtx, lockPath)
	if err != nil {
		return failureWithLastGood(spec, options, "cache_lock_timeout")
	}
	defer lock.Close()
	if err := securePrivateDir(filepath.Dir(lockPath)); err != nil {
		return failureWithLastGood(spec, options, "private_cache_unavailable")
	}
	prior, priorErr := readSourceSnapshot(options.CacheDir, spec)
	if lock.Waited() && priorErr == nil {
		changed := errors.Is(beforeErr, os.ErrNotExist) || beforeErr == nil && (prior.CheckedAt.After(before.CheckedAt) || prior.ContentSHA256 != before.ContentSHA256)
		if changed && !prior.CheckedAt.Before(started) {
			return providerSyncFromSnapshot(spec, prior, true, true, "coalesced")
		}
	}
	if errors.Is(priorErr, os.ErrNotExist) {
		prior = CatalogSnapshot{}
		priorErr = nil
	}
	if priorErr != nil {
		return ProviderSync{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: "unavailable", ErrorCode: "cache_invalid", SourceURL: spec.rootURL, Limitation: spec.limitation}
	}
	var priorPtr *CatalogSnapshot
	if prior.Complete {
		priorPtr = &prior
	}
	var snapshot CatalogSnapshot
	var fetchErr error
	if spec.adapter == "volcengine_ark" {
		snapshot, fetchErr = fetchArkCatalog(ctx, spec, *arkCreds, doer, options.Now)
	} else if spec.adapter == "alibaba_model_studio" {
		snapshot, fetchErr = fetchAlibabaModelStudioCatalog(ctx, spec, modelStudioAPIKey, doer, budget, options.Now)
	} else {
		snapshot, fetchErr = fetchSource(ctx, spec, priorPtr, doer, budget, options.Now)
	}
	if fetchErr != nil {
		return statusFromError(spec, priorPtr, failureCode(fetchErr))
	}
	if err := validateSnapshot(spec, snapshot); err != nil {
		return statusFromError(spec, priorPtr, "snapshot_validation_failed")
	}
	status := "updated"
	if priorPtr != nil && prior.ContentSHA256 == snapshot.ContentSHA256 {
		status = "unchanged"
	}
	if err := writeSourceSnapshot(options.CacheDir, spec, snapshot); err != nil {
		return ProviderSync{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: status, ErrorCode: "private_cache_write_failed", FetchedAt: timePtr(snapshot.FetchedAt), CheckedAt: timePtr(snapshot.CheckedAt), EvidenceCount: len(snapshot.Evidence), Snapshot: &snapshot, SourceURL: spec.rootURL, Limitation: spec.limitation}
	}
	return providerSyncFromSnapshot(spec, snapshot, true, false, status)
}

func modelStudioAPIKeyFromEnv(lookup func(string) (string, bool)) (string, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	if key, ok := lookup("DASHSCOPE_API_KEY"); ok && key != "" {
		if err := validateModelStudioAPIKey(key); err != nil {
			return "", err
		}
		return key, nil
	}
	path, _ := lookup("DASHSCOPE_API_KEY_FILE")
	credentialDir, _ := lookup("CREDENTIALS_DIRECTORY")
	if strings.TrimSpace(path) == "" || strings.TrimSpace(credentialDir) == "" {
		return "", errors.New("credential_not_configured")
	}
	credentialDir, err := filepath.Abs(credentialDir)
	if err != nil {
		return "", errors.New("credential_file_unavailable")
	}
	expectedPath := filepath.Join(credentialDir, "dashscope-api-key")
	path, err = filepath.Abs(path)
	if err != nil || filepath.Clean(path) != expectedPath {
		return "", errors.New("credential_file_unavailable")
	}
	linkInfo, err := os.Lstat(path)
	if err != nil || !linkInfo.Mode().IsRegular() || linkInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("credential_file_unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("credential_file_unavailable")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || openedInfo.Size() <= 0 || openedInfo.Size() > maxModelStudioAPIKey || !os.SameFile(linkInfo, openedInfo) {
		return "", errors.New("credential_file_unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxModelStudioAPIKey+1))
	if err != nil || len(body) == 0 || len(body) > maxModelStudioAPIKey {
		zero(body)
		return "", errors.New("credential_file_unavailable")
	}
	defer zero(body)
	key := strings.TrimSpace(string(body))
	if err := validateModelStudioAPIKey(key); err != nil {
		return "", err
	}
	return key, nil
}

func providerSyncFromSnapshot(spec sourceSpec, snapshot CatalogSnapshot, persisted, coalesced bool, status string) ProviderSync {
	return ProviderSync{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: status, FetchedAt: timePtr(snapshot.FetchedAt), CheckedAt: timePtr(snapshot.CheckedAt), EvidenceCount: len(snapshot.Evidence), CachePersisted: persisted, Coalesced: coalesced, Snapshot: &snapshot, SourceURL: spec.rootURL, ContentSHA256: snapshot.ContentSHA256, PageTitle: firstPageTitle(snapshot.Pages), Limitation: spec.limitation}
}

func firstPageTitle(pages []CachedPage) string {
	for _, page := range pages {
		if page.Title != "" {
			return page.Title
		}
	}
	return ""
}

func statusFromError(spec sourceSpec, prior *CatalogSnapshot, code string) ProviderSync {
	if prior != nil && validateSnapshot(spec, *prior) == nil {
		out := providerSyncFromSnapshot(spec, *prior, true, false, "stale")
		out.ErrorCode = code
		out.CheckedAt = nil
		return out
	}
	return ProviderSync{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: "unavailable", ErrorCode: code, SourceURL: spec.rootURL, Limitation: spec.limitation}
}

func failureWithLastGood(spec sourceSpec, options StartupSyncOptions, code string) ProviderSync {
	if options.Offline {
		return loadOffline(spec, options)
	}
	snapshot, err := readSourceSnapshot(options.CacheDir, spec)
	if err == nil && validateSnapshot(spec, snapshot) == nil {
		out := providerSyncFromSnapshot(spec, snapshot, true, false, "stale")
		out.ErrorCode = code
		return out
	}
	return ProviderSync{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: "unavailable", ErrorCode: code, SourceURL: spec.rootURL, Limitation: spec.limitation}
}

func loadOffline(spec sourceSpec, options StartupSyncOptions) ProviderSync {
	if options.CacheDir == "" {
		if cacheDir := options.userCacheDir; cacheDir != nil {
			if base, err := cacheDir(); err == nil {
				options.CacheDir = filepath.Join(base, "sub2api-model-catalog-manager", "official-lifecycle")
			}
		} else if base, err := os.UserCacheDir(); err == nil {
			options.CacheDir = filepath.Join(base, "sub2api-model-catalog-manager", "official-lifecycle")
		}
	}
	snapshot, err := readSourceSnapshot(options.CacheDir, spec)
	if err != nil || validateSnapshot(spec, snapshot) != nil {
		return ProviderSync{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: "offline_cache_missing", ErrorCode: "cache_missing", SourceURL: spec.rootURL, Limitation: spec.limitation}
	}
	return providerSyncFromSnapshot(spec, snapshot, true, false, "offline_cached")
}

func preparePersistentCache(ctx context.Context, root string, acquire func(context.Context, string) (osFileLock, error)) error {
	if ctx == nil || root == "" {
		return errors.New("private cache unavailable")
	}
	if err := secureCacheTree(root); err != nil {
		return err
	}
	if acquire == nil {
		acquire = acquireOSLock
	}
	lock, err := acquire(ctx, filepath.Join(root, ".init.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := secureCacheTree(root); err != nil {
		return err
	}
	for _, spec := range sourceManifest {
		dir := filepath.Join(root, spec.id)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err := securePrivateDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func readSourceSnapshot(root string, spec sourceSpec) (CatalogSnapshot, error) {
	if root == "" {
		return CatalogSnapshot{}, errors.New("cache unavailable")
	}
	dir := sourceCacheDir(root, spec)
	if err := securePrivateDir(dir); err != nil {
		return CatalogSnapshot{}, err
	}
	path := filepath.Join(dir, "snapshot.json")
	if info, err := os.Lstat(path); err != nil {
		return CatalogSnapshot{}, err
	} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 8<<20 {
		return CatalogSnapshot{}, errors.New("cache file is invalid")
	}
	if err := securePrivateFile(path); err != nil {
		return CatalogSnapshot{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return CatalogSnapshot{}, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil || len(body) == 0 || len(body) > 8<<20 {
		return CatalogSnapshot{}, errors.New("cache file is invalid")
	}
	var disk diskSnapshot
	if json.Unmarshal(body, &disk) != nil {
		return CatalogSnapshot{}, errors.New("cache file is invalid")
	}
	if disk.Version != cacheVersion || disk.SourceID != spec.id {
		return CatalogSnapshot{}, os.ErrNotExist
	}
	if validateSnapshot(spec, disk.Snapshot) != nil {
		return CatalogSnapshot{}, errors.New("cache file is invalid")
	}
	return disk.Snapshot, nil
}

func writeSourceSnapshot(root string, spec sourceSpec, snapshot CatalogSnapshot) error {
	if root == "" || validateSnapshot(spec, snapshot) != nil {
		return errors.New("invalid source snapshot")
	}
	dir := sourceCacheDir(root, spec)
	if err := securePrivateDir(dir); err != nil {
		return err
	}
	body, err := json.Marshal(diskSnapshot{Version: cacheVersion, SourceID: spec.id, Snapshot: snapshot})
	if err != nil || len(body) > 8<<20 {
		return errors.New("source snapshot exceeds cache limit")
	}
	defer zero(body)
	tmp, err := os.CreateTemp(dir, ".snapshot-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := securePrivateFile(tmpPath); err != nil {
		return err
	}
	if err := atomicReplace(tmpPath, filepath.Join(dir, "snapshot.json")); err != nil {
		return err
	}
	return securePrivateFile(filepath.Join(dir, "snapshot.json"))
}

func sourceCacheDir(root string, spec sourceSpec) string {
	dir := filepath.Join(root, spec.id)
	if spec.cacheScope != "" {
		dir = filepath.Join(dir, spec.cacheScope)
	}
	return dir
}

func validateSnapshot(spec sourceSpec, snapshot CatalogSnapshot) error {
	if !snapshot.Complete || snapshot.SourceID != spec.id || snapshot.Provider != spec.provider || snapshot.Scope != spec.scope || snapshot.FetchedAt.IsZero() || snapshot.CheckedAt.IsZero() || len(snapshot.Pages) == 0 || len(snapshot.Pages) > 1+spec.maxChildren {
		return errors.New("snapshot incomplete")
	}
	urls := map[string]bool{}
	for _, page := range snapshot.Pages {
		if validateSourceURL(spec, page.URL) != nil || page.Title == "" || page.ContentSHA256 == "" || page.FetchedAt.IsZero() || urls[page.URL] {
			return errors.New("snapshot page invalid")
		}
		urls[page.URL] = true
		if len(page.Links) > 1000 || len(page.Evidence) > MaxTotalModels || len(page.AvailableModelIDs) > MaxModelsPerAccount {
			return errors.New("snapshot page exceeds limit")
		}
		if spec.catalog && !spec.catalogMayBeEmpty && page.URL == spec.rootURL && len(page.AvailableModelIDs) == 0 {
			return errors.New("official product model list is missing")
		}
		for _, modelID := range page.AvailableModelIDs {
			if !validModelID(modelID) {
				return errors.New("official product model ID is invalid")
			}
		}
		for _, evidence := range page.Evidence {
			if evidence.SourceID != spec.id || evidence.Provider != spec.provider || evidence.Scope != spec.scope || !validModelID(evidence.ModelID) || !validLifecycleStatus(evidence.Status) || evidence.SourceURL != page.URL || evidence.SourceTitle != page.Title || evidence.ContentSHA256 != page.ContentSHA256 || len(evidence.Excerpt) > 360 {
				return errors.New("snapshot evidence invalid")
			}
		}
	}
	if err := validateModelStudioPagination(spec, snapshot); err != nil {
		return err
	}
	pageEvidence := make([]LifecycleEvidence, 0)
	for _, page := range snapshot.Pages {
		pageEvidence = append(pageEvidence, page.Evidence...)
	}
	pageEvidenceJSON, _ := json.Marshal(normalizeEvidence(pageEvidence))
	aggregateEvidenceJSON, _ := json.Marshal(normalizeEvidence(snapshot.Evidence))
	if !bytes.Equal(pageEvidenceJSON, aggregateEvidenceJSON) {
		return errors.New("snapshot aggregate evidence does not match its pages")
	}
	digest, err := snapshotDigest(snapshot.Pages)
	if err != nil || digest != snapshot.ContentSHA256 {
		return errors.New("snapshot hash mismatch")
	}
	return nil
}

func snapshotResults(results StartupSyncResult) ([]ProviderResult, []CatalogSnapshot) {
	providerResults := make([]ProviderResult, 0, len(sourceManifest))
	snapshots := make([]CatalogSnapshot, 0, len(sourceManifest))
	bySource := make(map[string]ProviderSync, len(results.Providers))
	for _, result := range results.Providers {
		bySource[result.SourceID] = result
	}
	for _, spec := range sourceManifest {
		result, ok := bySource[spec.id]
		if !ok {
			result = ProviderSync{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: "unavailable", ErrorCode: "sync_result_missing", SourceURL: spec.rootURL, Limitation: spec.limitation}
		}
		pr := ProviderResult{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: result.Status, SyncStatus: result.Status, CachePersisted: result.CachePersisted, LastFetchedAt: result.FetchedAt, LastCheckedAt: result.CheckedAt, EvidenceCount: result.EvidenceCount, ErrorCode: result.ErrorCode, Limitation: spec.limitation, SourceURL: spec.rootURL, PageTitle: result.PageTitle, ContentSHA256: result.ContentSHA256}
		providerResults = append(providerResults, pr)
		if result.Snapshot != nil && result.Snapshot.Complete {
			snapshots = append(snapshots, *result.Snapshot)
		}
	}
	return providerResults, snapshots
}

func BuildReviewFromStartup(inventory Inventory, syncResult StartupSyncResult, now func() time.Time) (Report, error) {
	if inventory.Digest == "" || inventory.Mode != "inspect" && inventory.Mode != "discover" {
		return Report{}, errors.New("official review dependencies or inventory are invalid")
	}
	if now == nil {
		now = time.Now
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Report{}, errors.New("official review ID could not be created")
	}
	created := now().UTC()
	providerResults, snapshots := snapshotResults(syncResult)
	report := Report{
		SchemaVersion: SchemaVersion, ReportID: hex.EncodeToString(id[:]), CreatedAt: created,
		InputReportMode: inventory.Mode, InputDigest: inventory.Digest,
		ProviderResults: providerResults, Observations: matchObservations(inventory.Observations, snapshots),
		NameShape:     findNameShapeCandidates(inventory),
		GlobalWarning: "Official lifecycle documents are evidence only. No notice found means unknown, not active. This does not prove an intermediary route is retired or available; no mappings are changed automatically.",
	}
	sortReport(&report)
	return report, nil
}

func (r StartupSyncResult) Summary() string {
	parts := make([]string, 0, len(r.Providers))
	for _, provider := range r.Providers {
		part := fmt.Sprintf("%s=%s", provider.SourceID, provider.Status)
		if provider.ErrorCode != "" {
			part += "(" + provider.ErrorCode + ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

func timePtr(t time.Time) *time.Time { return &t }

func snapshotPageURLs(snapshot CatalogSnapshot) []string {
	urls := make([]string, 0, len(snapshot.Pages))
	for _, page := range snapshot.Pages {
		urls = append(urls, page.URL)
	}
	sort.Strings(urls)
	return urls
}
