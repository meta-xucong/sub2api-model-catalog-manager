package officialcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type modelStudioDoerFunc func(*http.Request) (*http.Response, error)

func (f modelStudioDoerFunc) Do(request *http.Request) (*http.Response, error) { return f(request) }

func modelStudioResponse(payload string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}
}

func modelStudioPayload(total, pageNo, pageSize int, ids ...string) string {
	items := make([]any, 0, len(ids))
	for _, id := range ids {
		items = append(items, map[string]any{"model": id})
	}
	body, _ := json.Marshal(map[string]any{
		"success": true,
		"output":  map[string]any{"total": total, "page_no": pageNo, "page_size": pageSize, "models": items},
	})
	return string(body)
}

func TestFetchAlibabaModelStudioCatalogPaginatesAndValidatesEndpoint(t *testing.T) {
	spec, ok := sourceForID("alibaba-model-studio-models")
	if !ok {
		t.Fatal("Model Studio source is missing from the manifest")
	}
	const apiKey = "sk-ws-unit-secret"
	now := time.Date(2026, 10, 18, 5, 0, 0, 0, time.UTC)
	requests := 0
	doer := modelStudioDoerFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		query := request.URL.Query()
		if request.Method != http.MethodGet || request.URL.Host != "ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com" || request.URL.Path != "/api/v1/models" || request.Header.Get("Authorization") != "Bearer "+apiKey || query.Get("page_size") != "200" {
			t.Fatal("Model Studio fetch used an unexpected endpoint or authorization")
		}
		if requests == 1 && query.Get("page_no") == "1" {
			return modelStudioResponse(modelStudioPayload(3, 1, 2, "qwen3.7-plus", "glm-5")), nil
		}
		if requests == 2 && query.Get("page_no") == "2" {
			return modelStudioResponse(modelStudioPayload(3, 2, 2, "qwen3.8-max")), nil
		}
		t.Fatalf("unexpected pagination request %s", request.URL.String())
		return nil, nil
	})
	snapshot, err := fetchAlibabaModelStudioCatalog(context.Background(), spec, apiKey, doer, &requestBudget{}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("Model Studio catalog fetch failed: %v", err)
	}
	if requests != 2 || !snapshot.Complete || len(snapshot.Pages) != 2 || len(snapshot.Pages[0].AvailableModelIDs) != 2 || len(snapshot.Pages[1].AvailableModelIDs) != 1 {
		t.Fatalf("catalog response was not normalized as a complete paginated inventory: requests=%d snapshot=%+v", requests, snapshot)
	}
	if err := validateSnapshot(spec, snapshot); err != nil {
		t.Fatalf("complete Model Studio snapshot did not validate: %v", err)
	}
}

func TestFetchAlibabaModelStudioCatalogRejectsIncompleteOrUnsafeResponses(t *testing.T) {
	spec, _ := sourceForID("alibaba-model-studio-models")
	const apiKey = "sk-ws-test-key"
	now := time.Date(2026, 10, 18, 5, 0, 0, 0, time.UTC)
	valid := modelStudioPayload(1, 1, 1, "model-a")
	var missingSuccess map[string]any
	_ = json.Unmarshal([]byte(valid), &missingSuccess)
	delete(missingSuccess, "success")
	missingSuccessBytes, _ := json.Marshal(missingSuccess)
	for name, payload := range map[string]string{
		"missing success": string(missingSuccessBytes),
		"unsuccessful":    strings.Replace(valid, "true", "false", 1),
		"malformed JSON":  "not-json",
		"missing total":   `{"success":true,"output":{"page_no":1,"page_size":1,"models":[{"model":"model-a"}]}}`,
		"wrong page":      modelStudioPayload(1, 2, 1, "model-a"),
		"empty catalog":   modelStudioPayload(0, 1, 200),
		"short page":      modelStudioPayload(2, 1, 2, "model-a"),
		"long page":       modelStudioPayload(1, 1, 1, "model-a", "model-b"),
		"duplicate IDs":   modelStudioPayload(2, 1, 2, "model-a", "MODEL-A"),
		"missing model":   "{\"success\":true,\"output\":{\"total\":1,\"page_no\":1,\"page_size\":1,\"models\":[{}]}}",
		"padded model":    "{\"success\":true,\"output\":{\"total\":1,\"page_no\":1,\"page_size\":1,\"models\":[{\"model\":\" model-a \"}]}}",
	} {
		t.Run(name, func(t *testing.T) {
			doer := modelStudioDoerFunc(func(*http.Request) (*http.Response, error) { return modelStudioResponse(payload), nil })
			if _, err := fetchAlibabaModelStudioCatalog(context.Background(), spec, apiKey, doer, &requestBudget{}, func() time.Time { return now }); err == nil {
				t.Fatal("incomplete or unsafe model-list response was accepted")
			}
		})
	}
	badSpec := spec
	badSpec.rootURL = "https://example.invalid/api/v1/models"
	if _, err := fetchAlibabaModelStudioCatalog(context.Background(), badSpec, apiKey, modelStudioDoerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("rejected source URL triggered a request")
		return nil, nil
	}), &requestBudget{}, func() time.Time { return now }); failureCode(err) != "source_url_rejected" {
		t.Fatalf("non-official source URL was not rejected: %v", err)
	}
	if err := validateModelStudioAPIKey("sk-sp-plan-key"); err == nil {
		t.Fatal("Coding Plan key format was accepted for the Model Studio API catalog")
	}
}

func TestFetchAlibabaModelStudioCatalogRejectsCrossPageDriftAndDuplicates(t *testing.T) {
	spec, _ := sourceForID("alibaba-model-studio-models")
	const apiKey = "sk-ws-test-key"
	now := time.Date(2026, 10, 18, 5, 0, 0, 0, time.UTC)
	for name, secondPage := range map[string]string{
		"total changed":       modelStudioPayload(4, 2, 2, "model-c", "model-d"),
		"page size changed":   modelStudioPayload(3, 2, 1, "model-c"),
		"duplicate next page": modelStudioPayload(3, 2, 2, "model-a"),
		"short next page":     modelStudioPayload(4, 2, 2, "model-c"),
		"long next page":      modelStudioPayload(3, 2, 2, "model-c", "model-d"),
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			doer := modelStudioDoerFunc(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Query().Get("page_no") == "1" {
					return modelStudioResponse(modelStudioPayload(3, 1, 2, "model-a", "model-b")), nil
				}
				return modelStudioResponse(secondPage), nil
			})
			if _, err := fetchAlibabaModelStudioCatalog(context.Background(), spec, apiKey, doer, &requestBudget{}, func() time.Time { return now }); err == nil {
				t.Fatalf("cross-page inconsistency was accepted after %d requests", calls)
			}
		})
	}
}

func TestFetchAlibabaModelStudioCatalogEnforcesRequestAndBodyBudgets(t *testing.T) {
	spec, _ := sourceForID("alibaba-model-studio-models")
	const apiKey = "sk-ws-test-key"
	now := time.Date(2026, 10, 18, 5, 0, 0, 0, time.UTC)

	t.Run("request budget", func(t *testing.T) {
		budget := &requestBudget{}
		budget.used.Store(MaxHTTPGets)
		calls := 0
		_, err := fetchAlibabaModelStudioCatalog(context.Background(), spec, apiKey, modelStudioDoerFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return modelStudioResponse(modelStudioPayload(1, 1, 1, "model-a")), nil
		}), budget, func() time.Time { return now })
		if failureCode(err) != "request_budget_exhausted" || calls != 0 {
			t.Fatalf("exhausted request budget was not enforced before the request: calls=%d err=%v", calls, err)
		}
	})

	t.Run("response body limit", func(t *testing.T) {
		oversized := `{"success":true,"output":{"total":1,"page_no":1,"page_size":1,"models":[{"model":"model-a"}]},"padding":"` + strings.Repeat("x", MaxResponseBytes) + `"}`
		_, err := fetchAlibabaModelStudioCatalog(context.Background(), spec, apiKey, modelStudioDoerFunc(func(*http.Request) (*http.Response, error) {
			return modelStudioResponse(oversized), nil
		}), &requestBudget{}, func() time.Time { return now })
		if failureCode(err) != "response_too_large_or_empty" {
			t.Fatalf("oversized Model Studio response was not rejected: %v", err)
		}
	})
}

func TestModelStudioSnapshotHashCoversPaginationMetadata(t *testing.T) {
	spec, _ := sourceForID("alibaba-model-studio-models")
	now := time.Date(2026, 10, 18, 5, 0, 0, 0, time.UTC)
	page := CachedPage{
		URL: spec.rootURL, Title: "Alibaba Bailian Model Studio model catalog", ContentSHA256: strings.Repeat("a", 64), FetchedAt: now,
		CatalogTotal: 2, CatalogPageNo: 1, CatalogPageSize: 200, AvailableModelIDs: []string{"model-a", "model-b"},
	}
	snapshot := CatalogSnapshot{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Pages: []CachedPage{page}, Evidence: []LifecycleEvidence{}, FetchedAt: now, CheckedAt: now, Complete: true}
	snapshot.ContentSHA256, _ = snapshotDigest(snapshot.Pages)
	if err := validateSnapshot(spec, snapshot); err != nil {
		t.Fatalf("valid paginated snapshot rejected: %v", err)
	}
	snapshot.Pages[0].CatalogPageSize = 2
	if err := validateSnapshot(spec, snapshot); err == nil || err.Error() != "snapshot hash mismatch" {
		t.Fatalf("pagination metadata tampering did not fail the snapshot digest: %v", err)
	}
}

func TestAlibabaModelStudioCacheIsIsolatedAndContainsNoCredential(t *testing.T) {
	cacheDir := t.TempDir()
	if err := preparePersistentCache(context.Background(), cacheDir, nil); err != nil {
		t.Fatal("private cache could not be prepared")
	}
	spec, _ := sourceForID("alibaba-model-studio-models")
	now := time.Date(2026, 10, 18, 5, 0, 0, 0, time.UTC)
	keyA, keyB := "sk-ws-account-a-secret", "sk-ws-account-b-secret"
	good := modelStudioDoerFunc(func(*http.Request) (*http.Response, error) {
		return modelStudioResponse(modelStudioPayload(1, 1, 200, "qwen3.7-plus")), nil
	})
	optionsFor := func(key string, at time.Time) StartupSyncOptions {
		return StartupSyncOptions{CacheDir: cacheDir, LookupEnv: func(name string) (string, bool) { return key, name == "DASHSCOPE_API_KEY" }, Now: func() time.Time { return at }}
	}
	first := syncOneSource(context.Background(), spec, optionsFor(keyA, now), good, &requestBudget{})
	if first.Status != "updated" || !first.CachePersisted {
		t.Fatalf("first key's catalog did not sync: %+v", first)
	}
	failing := modelStudioDoerFunc(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("offline") })
	second := syncOneSource(context.Background(), spec, optionsFor(keyB, now.Add(time.Minute)), failing, &requestBudget{})
	if second.Status != "unavailable" || second.Snapshot != nil || second.ErrorCode != "network_transport_error" {
		t.Fatalf("second key reused another key's cache: %+v", second)
	}
	keyHash := sha256.Sum256([]byte(keyA))
	scopedSpec := spec
	scopedSpec.cacheScope = hex.EncodeToString(keyHash[:])
	body, err := os.ReadFile(sourceCacheDir(cacheDir, scopedSpec) + "/snapshot.json")
	if err != nil {
		t.Fatal("workspace-scoped cache could not be read")
	}
	if strings.Contains(string(body), keyA) || strings.Contains(string(body), keyB) {
		t.Fatal("API key was written into the private catalog cache")
	}
	var stored diskSnapshot
	if json.Unmarshal(body, &stored) != nil || !stored.Snapshot.Complete || len(stored.Snapshot.Pages) != 1 {
		t.Fatal("private cache did not preserve a complete model inventory")
	}
}

func TestAlibabaModelStudioLoadsAPIKeyFromCredentialFile(t *testing.T) {
	cacheDir := t.TempDir()
	if err := preparePersistentCache(context.Background(), cacheDir, nil); err != nil {
		t.Fatal("private cache could not be prepared")
	}
	credentialDir := t.TempDir()
	path := filepath.Join(credentialDir, "dashscope-api-key")
	key := "sk-ws-credential-file-test"
	if err := os.WriteFile(path, []byte(key+"\n"), 0600); err != nil {
		t.Fatal("credential file could not be created")
	}
	spec, _ := sourceForID("alibaba-model-studio-models")
	doer := modelStudioDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer "+key {
			t.Fatal("credential file key was not used for the official request")
		}
		return modelStudioResponse(modelStudioPayload(1, 1, 200, "qwen3.7-plus")), nil
	})
	options := StartupSyncOptions{
		CacheDir: cacheDir,
		LookupEnv: func(name string) (string, bool) {
			if name == "DASHSCOPE_API_KEY_FILE" {
				return path, true
			}
			if name == "CREDENTIALS_DIRECTORY" {
				return credentialDir, true
			}
			return "", false
		},
		Now: func() time.Time { return time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC) },
	}
	result := syncOneSource(context.Background(), spec, options, doer, &requestBudget{})
	if result.Status != "updated" || !result.CachePersisted || result.Snapshot == nil {
		t.Fatalf("credential-file source sync failed: status=%s code=%s", result.Status, result.ErrorCode)
	}
	badOptions := options
	badOptions.LookupEnv = func(name string) (string, bool) {
		if name == "DASHSCOPE_API_KEY_FILE" {
			return filepath.Join(t.TempDir(), "dashscope-api-key"), true
		}
		if name == "CREDENTIALS_DIRECTORY" {
			return credentialDir, true
		}
		return "", false
	}
	if bad := syncOneSource(context.Background(), spec, badOptions, doer, &requestBudget{}); bad.ErrorCode != "credential_file_unavailable" {
		t.Fatalf("non-file credential path was accepted: %+v", bad)
	}
}

func TestEvaluateAlibabaModelStudioAvailabilityIsExactPlatformWorkspaceAndFreshOnly(t *testing.T) {
	spec, _ := sourceForID("alibaba-model-studio-models")
	now := time.Date(2026, 10, 18, 5, 0, 0, 0, time.UTC)
	workspaceURL := "https://ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
	pages := []CachedPage{
		{URL: spec.rootURL, Title: "Alibaba Bailian Model Studio model catalog", ContentSHA256: strings.Repeat("a", 64), FetchedAt: now.Add(-time.Hour), CatalogTotal: 2, CatalogPageNo: 1, CatalogPageSize: 200, AvailableModelIDs: []string{"glm-5", "qwen3.7-plus"}},
	}
	snapshot := CatalogSnapshot{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Pages: pages, Evidence: []LifecycleEvidence{}, FetchedAt: pages[0].FetchedAt, CheckedAt: pages[0].FetchedAt, Complete: true}
	snapshot.ContentSHA256, _ = snapshotDigest(snapshot.Pages)
	result := StartupSyncResult{Providers: []ProviderSync{{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: "updated", Snapshot: &snapshot}}}
	got := EvaluateAlibabaModelStudioAvailability(result, "alibaba", workspaceURL, []string{"qwen3.7-plus", "qwen3.5-plus", "glm-5"}, now)
	if len(got) != 3 || got[0].ModelID != "glm-5" || got[0].Status != "available" || got[1].Status != "unavailable" || got[1].MatchKind != "official_api_catalog_absence" || got[2].Status != "available" {
		t.Fatalf("Model Studio catalog evaluation mismatch: %+v", got)
	}
	for _, platform := range []string{"volcengine", "Alibaba", " alibaba", "alibaba "} {
		if mismatched := EvaluateAlibabaModelStudioAvailability(result, platform, workspaceURL, []string{"qwen3.5-plus"}, now); len(mismatched) != 0 {
			t.Fatalf("Model Studio evidence escaped literal Alibaba platform %q: %+v", platform, mismatched)
		}
	}
	for _, sourceURL := range []string{
		"https://other-workspace.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
		"https://ws-soph8gi8iynvs7lh.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1",
		"http://ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
	} {
		if mismatch := EvaluateAlibabaModelStudioAvailability(result, "alibaba", sourceURL, []string{"qwen3.5-plus"}, now); len(mismatch) != 1 || mismatch[0].Status != "insufficient_evidence" {
			t.Fatalf("Beijing workspace evidence was applied to a different source URL %q: %+v", sourceURL, mismatch)
		}
	}
	result.Providers[0].Status = "stale"
	if stale := EvaluateAlibabaModelStudioAvailability(result, "alibaba", workspaceURL, []string{"qwen3.7-plus"}, now); len(stale) != 1 || stale[0].Status != "insufficient_evidence" {
		t.Fatalf("stale Model Studio list was treated as current: %+v", stale)
	}
	result.Providers[0].Status = "updated"
	old := *result.Providers[0].Snapshot
	old.FetchedAt = now.Add(-MaxBailianModelStudioCatalogAge - time.Minute)
	result.Providers[0].Snapshot = &old
	if expired := EvaluateAlibabaModelStudioAvailability(result, "alibaba", workspaceURL, []string{"qwen3.7-plus"}, now); len(expired) != 1 || expired[0].Status != "insufficient_evidence" {
		t.Fatalf("expired Model Studio list was treated as current: %+v", expired)
	}
}

func TestLiveAlibabaModelStudioCatalogOptIn(t *testing.T) {
	if os.Getenv("DASHSCOPE_MODEL_STUDIO_LIVE_TEST") != "1" {
		t.Skip("set DASHSCOPE_MODEL_STUDIO_LIVE_TEST=1 to call the read-only official Model Studio model-list API")
	}
	apiKey := os.Getenv("DASHSCOPE_API_KEY")
	if err := validateModelStudioAPIKey(apiKey); err != nil {
		t.Fatalf("DASHSCOPE_API_KEY is unavailable or invalid: %s", err.Error())
	}
	spec, _ := sourceForID("alibaba-model-studio-models")
	cacheDir := t.TempDir()
	if err := preparePersistentCache(context.Background(), cacheDir, nil); err != nil {
		t.Fatalf("private catalog cache could not be prepared: %v", err)
	}
	options := StartupSyncOptions{CacheDir: cacheDir, LookupEnv: func(name string) (string, bool) { return apiKey, name == "DASHSCOPE_API_KEY" }, Now: time.Now}
	result := syncOneSource(context.Background(), spec, options, NewHTTPClient(), &requestBudget{})
	if result.Status != "updated" || !result.CachePersisted || result.Snapshot == nil {
		t.Fatalf("official Model Studio model-list fetch failed: status=%s code=%s", result.Status, result.ErrorCode)
	}
	keyHash := sha256.Sum256([]byte(apiKey))
	spec.cacheScope = hex.EncodeToString(keyHash[:])
	cached, err := readSourceSnapshot(cacheDir, spec)
	if err != nil || !cached.Complete || len(cached.Pages) == 0 {
		t.Fatalf("complete Model Studio model list was not privately cached: err=%v", err)
	}
	ids := make([]string, 0)
	for _, page := range cached.Pages {
		ids = append(ids, page.AvailableModelIDs...)
	}
	idsJSON, _ := json.Marshal(ids)
	t.Logf("official Beijing Model Studio catalog fetched: complete=%t models=%d sha256=%s ids=%s", cached.Complete, len(ids), cached.ContentSHA256, idsJSON)
}
