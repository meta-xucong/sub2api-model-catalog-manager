package officialcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type arkDoerFunc func(*http.Request) (*http.Response, error)

func (f arkDoerFunc) Do(request *http.Request) (*http.Response, error) { return f(request) }

func TestParseArkCredentialFileAcceptsLabeledPairsWithoutReturningSecrets(t *testing.T) {
	access, secret, ok := parseArkCredentialFile([]byte("Access Key ID\nAK-test-value\nSecret Access Key\nSK-test-value\n"))
	if !ok || access != "AK-test-value" || string(secret) != "SK-test-value" {
		t.Fatal("labeled AK/SK file was not parsed")
	}
	for _, body := range []string{
		"unknown\nvalue\nSecret Access Key\nsecret",
		"Access Key ID: first\nAK: second\nSecret Access Key: secret",
		"AK: key\nSK: \n",
	} {
		if _, _, valid := parseArkCredentialFile([]byte(body)); valid {
			t.Fatal("invalid or ambiguous credentials were accepted")
		}
	}
}

func TestFetchArkCatalogSignsFilteredRequestAndValidatesPagination(t *testing.T) {
	credentialPath := t.TempDir() + "/ark-credentials.txt"
	if err := osWriteFilePrivate(credentialPath, "Access Key ID\nAK-unit\nSecret Access Key\nSK-unit-secret\n"); err != nil {
		t.Fatal("could not create credential fixture")
	}
	now := time.Date(2026, 10, 18, 4, 5, 6, 0, time.UTC)
	requests := 0
	doer := arkDoerFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Method != http.MethodPost || request.URL.Host != "ark.cn-beijing.volcengineapi.com" || request.URL.RawQuery != "Action=ListModelActivations&Version=2024-01-01" {
			t.Fatal("Ark request used an unexpected endpoint")
		}
		if request.Header.Get("Content-Type") != "application/json" || !strings.HasPrefix(request.Header.Get("Authorization"), "HMAC-SHA256 Credential=AK-unit/20261018/cn-beijing/ark/request,") {
			t.Fatal("Ark request was not signed with the expected scope")
		}
		if strings.Contains(request.Header.Get("Authorization"), "SK-unit-secret") {
			t.Fatal("secret key appeared in Authorization")
		}
		body, _ := io.ReadAll(request.Body)
		if !strings.Contains(string(body), `"States":["Available"]`) || !strings.Contains(string(body), `"IncludeDeprecatedModels":false`) || !strings.Contains(string(body), `"PageNumber":`) {
			t.Fatal("Ark request did not restrict results to current available models")
		}
		page := requests
		items := make([]string, 0, arkPageSize)
		count := arkPageSize
		if page == 2 {
			count = 1
		}
		for i := 0; i < count; i++ {
			id := "model-" + fmt.Sprintf("%03d", (page-1)*arkPageSize+i)
			if page == 1 && i == 0 {
				id = "doubao-seed-2-1-pro"
			} else if page == 2 {
				id = "deepseek-v4-pro"
			}
			items = append(items, `{"FoundationModelName":"`+id+`","State":"Available","IsDeprecated":false}`)
		}
		payload := fmt.Sprintf(`{"Result":{"TotalCount":101,"PageNumber":%d,"PageSize":100,"Items":[%s]}}`, page, strings.Join(items, ","))
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
	})
	spec, ok := sourceForID("volcengine-ark-account-models")
	if !ok {
		t.Fatal("Ark source is missing from the manifest")
	}
	credentials, err := loadArkCredentials(credentialPath)
	if err != nil {
		t.Fatal("Ark credentials could not be loaded")
	}
	snapshot, err := fetchArkCatalog(context.Background(), spec, credentials, doer, func() time.Time { return now })
	zero(credentials.secretKey)
	if err != nil {
		t.Fatalf("Ark catalog fetch failed: %v", err)
	}
	if requests != 2 || !snapshot.Complete || len(snapshot.Pages) != 1 || len(snapshot.Pages[0].AvailableModelIDs) != 101 {
		t.Fatalf("catalog did not aggregate both complete pages: requests=%d snapshot=%+v", requests, snapshot)
	}
	if err := validateSnapshot(spec, snapshot); err != nil {
		t.Fatalf("complete Ark snapshot did not validate: %v", err)
	}
}

func TestFetchArkCatalogRejectsIncompleteOrContradictoryResponses(t *testing.T) {
	credentialPath := t.TempDir() + "/ark-credentials.txt"
	if err := osWriteFilePrivate(credentialPath, "AK: key\nSK: secret\n"); err != nil {
		t.Fatal("could not create credential fixture")
	}
	spec, _ := sourceForID("volcengine-ark-account-models")
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	for name, payload := range map[string]string{
		"short page":       `{"Result":{"TotalCount":2,"PageNumber":1,"PageSize":100,"Items":[{"FoundationModelName":"model-a","State":"Available"}]}}`,
		"non available":    `{"Result":{"TotalCount":1,"PageNumber":1,"PageSize":100,"Items":[{"FoundationModelName":"model-a","State":"Unavailable"}]}}`,
		"deprecated":       `{"Result":{"TotalCount":1,"PageNumber":1,"PageSize":100,"Items":[{"FoundationModelName":"model-a","State":"Available","IsDeprecated":true}]}}`,
		"duplicate ids":    `{"Result":{"TotalCount":2,"PageNumber":1,"PageSize":100,"Items":[{"FoundationModelName":"model-a","State":"Available"},{"FoundationModelName":"MODEL-A","State":"Available"}]}}`,
		"padded model id":  `{"Result":{"TotalCount":1,"PageNumber":1,"PageSize":100,"Items":[{"FoundationModelName":" model-a ","State":"Available"}]}}`,
		"missing total":    `{"Result":{"PageNumber":1,"PageSize":100,"Items":[]}}`,
		"missing result":   `{"ResponseMetadata":{"RequestId":"public-request-id"}}`,
		"empty successful": `{"Result":{"TotalCount":0,"PageNumber":1,"PageSize":100,"Items":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			doer := arkDoerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(payload))}, nil
			})
			credentials, err := loadArkCredentials(credentialPath)
			if err != nil {
				t.Fatal("Ark credentials could not be loaded")
			}
			snapshot, err := fetchArkCatalog(context.Background(), spec, credentials, doer, func() time.Time { return now })
			zero(credentials.secretKey)
			if name == "empty successful" {
				if err != nil || !snapshot.Complete || len(snapshot.Pages[0].AvailableModelIDs) != 0 {
					t.Fatalf("complete empty catalog was rejected: snapshot=%+v err=%v", snapshot, err)
				}
			} else if err == nil {
				t.Fatalf("contradictory or incomplete response was accepted: %+v", snapshot)
			}
		})
	}
}

func TestArkCatalogCachePersistsOnlyInventoryData(t *testing.T) {
	cacheDir := t.TempDir()
	if err := preparePersistentCache(context.Background(), cacheDir, nil); err != nil {
		t.Fatal("private cache could not be prepared")
	}
	credentialPath := t.TempDir() + "/ark-credentials.txt"
	if err := osWriteFilePrivate(credentialPath, "AK: AK-cache-test\nSK: SK-cache-test-secret\n"); err != nil {
		t.Fatal("credential fixture could not be created")
	}
	spec, _ := sourceForID("volcengine-ark-account-models")
	now := time.Date(2026, 10, 18, 4, 5, 6, 0, time.UTC)
	doer := arkDoerFunc(func(*http.Request) (*http.Response, error) {
		body := `{"Result":{"TotalCount":1,"PageNumber":1,"PageSize":100,"Items":[{"FoundationModelName":"doubao-seed-2-1-pro","State":"Available","IsDeprecated":false}]}}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	result := syncOneSource(context.Background(), spec, StartupSyncOptions{CacheDir: cacheDir, ArkCredentialFile: credentialPath, Now: func() time.Time { return now }}, doer, &requestBudget{})
	if result.Status != "updated" || !result.CachePersisted {
		t.Fatalf("Ark snapshot did not persist: %+v", result)
	}
	credentials, err := loadArkCredentials(credentialPath)
	if err != nil {
		t.Fatal("Ark credentials could not be loaded")
	}
	accountHash := sha256.Sum256([]byte(credentials.accessKeyID))
	zero(credentials.secretKey)
	scopedSpec := spec
	scopedSpec.cacheScope = hex.EncodeToString(accountHash[:])
	cachedBytes, err := os.ReadFile(sourceCacheDir(cacheDir, scopedSpec) + "/snapshot.json")
	if err != nil {
		t.Fatal("persisted Ark snapshot could not be read")
	}
	serialized := string(cachedBytes)
	if strings.Contains(serialized, "AK-cache-test") || strings.Contains(serialized, "SK-cache-test-secret") || !strings.Contains(serialized, "doubao-seed-2-1-pro") {
		t.Fatal("snapshot did not isolate inventory data from credentials")
	}
}

func TestArkCatalogCacheIsIsolatedByCredentialAccount(t *testing.T) {
	cacheDir := t.TempDir()
	if err := preparePersistentCache(context.Background(), cacheDir, nil); err != nil {
		t.Fatal("private cache could not be prepared")
	}
	now := time.Date(2026, 10, 18, 4, 5, 6, 0, time.UTC)
	makeCredentialFile := func(name, access string) string {
		path := t.TempDir() + "/" + name
		if err := osWriteFilePrivate(path, "AK: "+access+"\nSK: local-test-secret\n"); err != nil {
			t.Fatal("credential fixture could not be created")
		}
		return path
	}
	accountA := makeCredentialFile("account-a.txt", "AK-account-a")
	accountB := makeCredentialFile("account-b.txt", "AK-account-b")
	spec, _ := sourceForID("volcengine-ark-account-models")
	good := arkDoerFunc(func(*http.Request) (*http.Response, error) {
		body := `{"Result":{"TotalCount":1,"PageNumber":1,"PageSize":100,"Items":[{"FoundationModelName":"account-a-only-model","State":"Available","IsDeprecated":false}]}}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	first := syncOneSource(context.Background(), spec, StartupSyncOptions{CacheDir: cacheDir, ArkCredentialFile: accountA, Now: func() time.Time { return now }}, good, &requestBudget{})
	if first.Status != "updated" {
		t.Fatalf("first account inventory did not sync: %+v", first)
	}
	failing := arkDoerFunc(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("network unavailable") })
	second := syncOneSource(context.Background(), spec, StartupSyncOptions{CacheDir: cacheDir, ArkCredentialFile: accountB, Now: func() time.Time { return now.Add(time.Minute) }}, failing, &requestBudget{})
	if second.Status != "unavailable" || second.Snapshot != nil || second.ErrorCode != "network_transport_error" {
		t.Fatalf("second account reused another account's snapshot: %+v", second)
	}
	credentials, err := loadArkCredentials(accountA)
	if err != nil {
		t.Fatal("first account credentials could not be loaded")
	}
	accountHash := sha256.Sum256([]byte(credentials.accessKeyID))
	zero(credentials.secretKey)
	spec.cacheScope = hex.EncodeToString(accountHash[:])
	cached, err := readSourceSnapshot(cacheDir, spec)
	if err != nil || len(cached.Pages) != 1 || cached.Pages[0].AvailableModelIDs[0] != "account-a-only-model" {
		t.Fatalf("first account last-good snapshot was not retained in its own scope: err=%v", err)
	}
}

func TestEvaluateArkAvailabilityIsExactPlatformScopedAndFreshOnly(t *testing.T) {
	now := time.Date(2026, 10, 18, 4, 5, 6, 0, time.UTC)
	spec, _ := sourceForID("volcengine-ark-account-models")
	page := CachedPage{URL: spec.rootURL, Title: "Volcengine Ark account model activations", ContentSHA256: strings.Repeat("a", 64), FetchedAt: now.Add(-time.Hour), AvailableModelIDs: []string{"doubao-seed-2-1-pro", "deepseek-v4-pro"}}
	snapshot := CatalogSnapshot{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Pages: []CachedPage{page}, Evidence: []LifecycleEvidence{}, FetchedAt: page.FetchedAt, CheckedAt: page.FetchedAt, Complete: true}
	snapshot.ContentSHA256, _ = snapshotDigest(snapshot.Pages)
	result := StartupSyncResult{Providers: []ProviderSync{{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: "updated", Snapshot: &snapshot}}}
	got := EvaluateArkAccountAvailability(result, "volcengine", []string{"doubao-seed-2-1-pro", "doubao-seed-2-0-lite", "doubao-seed-2-1-pro"}, now)
	if len(got) != 2 || got[0].Status != "unavailable" || got[0].MatchKind != "official_account_absence" || got[1].Status != "available" || got[1].MatchKind != "exact" {
		t.Fatalf("exact Ark account screening mismatch: %+v", got)
	}
	if other := EvaluateArkAccountAvailability(result, "alibaba", []string{"doubao-seed-2-0-lite"}, now); len(other) != 0 {
		t.Fatalf("Ark evidence escaped into another source platform: %+v", other)
	}
	for _, platform := range []string{"Volcengine", " volcengine", "volcengine "} {
		if mismatched := EvaluateArkAccountAvailability(result, platform, []string{"doubao-seed-2-0-lite"}, now); len(mismatched) != 0 {
			t.Fatalf("non-literal platform %q received Ark evidence: %+v", platform, mismatched)
		}
	}
	result.Providers[0].Status = "stale"
	stale := EvaluateArkAccountAvailability(result, "volcengine", []string{"doubao-seed-2-1-pro"}, now)
	if len(stale) != 1 || stale[0].Status != "insufficient_evidence" {
		t.Fatalf("cached failure result was treated as current evidence: %+v", stale)
	}
	result.Providers[0].Status = "updated"
	old := *result.Providers[0].Snapshot
	old.FetchedAt = now.Add(-MaxArkAccountCatalogAge - time.Minute)
	result.Providers[0].Snapshot = &old
	expired := EvaluateArkAccountAvailability(result, "volcengine", []string{"doubao-seed-2-1-pro"}, now)
	if len(expired) != 1 || expired[0].Status != "insufficient_evidence" {
		t.Fatalf("expired Ark evidence was treated as current: %+v", expired)
	}
}

func TestLiveArkCatalogOptIn(t *testing.T) {
	if os.Getenv("VOLCENGINE_ARK_LIVE_TEST") != "1" {
		t.Skip("set VOLCENGINE_ARK_LIVE_TEST=1 to call the read-only official Ark API")
	}
	path := os.Getenv("VOLCENGINE_ARK_CREDENTIAL_FILE")
	if path == "" {
		t.Fatal("VOLCENGINE_ARK_CREDENTIAL_FILE must point to the local AK/SK file")
	}
	spec, ok := sourceForID("volcengine-ark-account-models")
	if !ok {
		t.Fatal("Ark source is missing from the manifest")
	}
	cacheDir := t.TempDir()
	if err := preparePersistentCache(context.Background(), cacheDir, nil); err != nil {
		t.Fatalf("private catalog cache could not be prepared: %v", err)
	}
	options := StartupSyncOptions{CacheDir: cacheDir, ArkCredentialFile: path, Now: time.Now}
	result := syncOneSource(context.Background(), spec, options, NewHTTPClient(), &requestBudget{})
	if result.Status != "updated" || !result.CachePersisted || result.Snapshot == nil {
		t.Fatalf("official Ark catalog sync failed: status=%s code=%s", result.Status, result.ErrorCode)
	}
	credentials, err := loadArkCredentials(path)
	if err != nil {
		t.Fatalf("Ark credentials could not be loaded: %v", err)
	}
	accountHash := sha256.Sum256([]byte(credentials.accessKeyID))
	zero(credentials.secretKey)
	spec.cacheScope = hex.EncodeToString(accountHash[:])
	cached, err := readSourceSnapshot(cacheDir, spec)
	if err != nil || !cached.Complete || len(cached.Pages) != 1 {
		t.Fatalf("complete official Ark snapshot was not cached privately: err=%v", err)
	}
	t.Logf("official Ark account catalog fetched and cached: complete=%t models=%d sha256=%s", cached.Complete, len(cached.Pages[0].AvailableModelIDs), cached.ContentSHA256)
	t.Logf("available model IDs: %s", strings.Join(cached.Pages[0].AvailableModelIDs, ", "))
}

func osWriteFilePrivate(path, body string) error {
	return os.WriteFile(path, []byte(body), 0600)
}
