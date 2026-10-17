package officialselectability

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sub2api-model-catalog-manager/internal/catalog"
	"sub2api-model-catalog-manager/internal/config"
	"sub2api-model-catalog-manager/internal/securecred"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func source(scope, provider string) config.OfficialSelectabilitySource {
	return config.OfficialSelectabilitySource{Scope: scope, Provider: provider, Product: "api", Credential: config.CredentialConfig{WindowsCredentialTarget: "provider-key-" + provider}}
}

func TestRuleBindingsRequireMatchingAutomaticAPISourceButPreserveUIMode(t *testing.T) {
	scope := "official-account:api-account"
	profile := catalog.SourceProfile{
		Source:  catalog.Source{Platform: "openai", AccountType: "api_key", APIProtocol: "openai", BaseURL: "https://api.openai.com"},
		BuildID: "build", APIContractID: "admin-catalog-v1", Decision: "approved",
		OfficialSelectabilityScope: scope, OfficialSelectabilityProduct: "api", OfficialSelectabilityProvider: "openai-api",
		Evidence: "approved fixture", ReviewedAt: "2026-10-17",
	}
	rules := catalog.Rules{SourceProfiles: []catalog.SourceProfile{profile}}
	if err := ValidateRuleBindings(rules, nil); err == nil {
		t.Fatal("API scope without an automatic source fell back to manual evidence")
	}
	wrongProvider := source(scope, "anthropic-api")
	if err := ValidateRuleBindings(rules, []config.OfficialSelectabilitySource{wrongProvider}); err == nil {
		t.Fatal("provider mismatch was accepted")
	}
	apiSource := source(scope, "openai-api")
	uiProfile := profile
	uiProfile.OfficialSelectabilityScope = "official-account:chatgpt-ui"
	uiProfile.OfficialSelectabilityProduct = "ui"
	uiProfile.OfficialSelectabilityProvider = ""
	uiRules := catalog.Rules{SourceProfiles: []catalog.SourceProfile{profile, uiProfile}}
	if err := ValidateRuleBindings(uiRules, []config.OfficialSelectabilitySource{apiSource}); err != nil {
		t.Fatalf("matching API source plus manual UI scope was rejected: %v", err)
	}
	if err := ValidateRuleBindings(catalog.Rules{SourceProfiles: []catalog.SourceProfile{uiProfile}}, nil); err != nil {
		t.Fatalf("manual UI scope was incorrectly required to use an API collector: %v", err)
	}
	legacyUnclassified := profile
	legacyUnclassified.OfficialSelectabilityProduct = ""
	legacyUnclassified.OfficialSelectabilityProvider = ""
	if err := ValidateRuleBindings(catalog.Rules{SourceProfiles: []catalog.SourceProfile{legacyUnclassified}}, nil); err == nil {
		t.Fatal("unclassified legacy product scope was allowed to use a manual snapshot")
	}
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestProviderAdaptersUseFixedOfficialHostsAndAuth(t *testing.T) {
	cases := []struct {
		provider, wantURL, wantHeader, wantValue, body string
	}{
		{"openai-api", "https://api.openai.com/v1/models", "Authorization", "Bearer test-secret", `{"object":"list","data":[{"id":"gpt-x"}]}`},
		{"anthropic-api", "https://api.anthropic.com/v1/models?limit=1000", "x-api-key", "test-secret", `{"data":[{"id":"claude-x"}],"has_more":false}`},
		{"xai-api", "https://api.x.ai/v1/models", "Authorization", "Bearer test-secret", `{"data":[{"id":"grok-x"}]}`},
		{"deepseek-api", "https://api.deepseek.com/models", "Authorization", "Bearer test-secret", `{"object":"list","data":[{"id":"deepseek-x"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			called := 0
			ids, err := fetchIDs(context.Background(), tc.provider, []byte("test-secret"), doerFunc(func(req *http.Request) (*http.Response, error) {
				called++
				if req.URL.String() != tc.wantURL {
					t.Fatalf("URL=%s want %s", req.URL, tc.wantURL)
				}
				if req.Header.Get(tc.wantHeader) != tc.wantValue {
					t.Fatalf("auth header %s=%q", tc.wantHeader, req.Header.Get(tc.wantHeader))
				}
				if tc.provider == "anthropic-api" && req.Header.Get("anthropic-version") != "2023-06-01" {
					t.Fatal("Anthropic version header missing")
				}
				if req.URL.Host != strings.TrimPrefix(strings.Split(tc.wantURL, "/")[2], "") {
					t.Fatal("unexpected host")
				}
				return response(200, tc.body), nil
			}))
			if err != nil || len(ids) != 1 {
				t.Fatalf("ids=%v err=%v", ids, err)
			}
			if called != 1 {
				t.Fatalf("calls=%d", called)
			}
		})
	}
}

func TestAnthropicPaginationMustAdvanceAndCollectEveryPage(t *testing.T) {
	var requests int
	ids, err := fetchIDs(context.Background(), "anthropic-api", []byte("key"), doerFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		switch requests {
		case 1:
			if req.URL.Query().Get("after_id") != "" {
				t.Fatalf("unexpected first cursor: %s", req.URL)
			}
			return response(200, `{"data":[{"id":"claude-a"}],"has_more":true,"last_id":"claude-a"}`), nil
		case 2:
			if req.URL.Query().Get("after_id") != "claude-a" {
				t.Fatalf("missing cursor: %s", req.URL)
			}
			return response(200, `{"data":[{"id":"claude-b"}],"has_more":false,"last_id":"claude-b"}`), nil
		default:
			t.Fatal("unexpected extra page")
			return nil, nil
		}
	}))
	if err != nil || strings.Join(ids, ",") != "claude-a,claude-b" || requests != 2 {
		t.Fatalf("ids=%v requests=%d err=%v", ids, requests, err)
	}
}

func TestRefreshPublishesCompleteBoundSnapshotAndLoadChecksBinding(t *testing.T) {
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	sources := []config.OfficialSelectabilitySource{source("official-account:team-a", "openai-api")}
	path := t.TempDir() + "/official.json"
	secretReader := func(config.CredentialConfig) (securecred.Value, error) {
		return securecred.Value{APIKey: []byte("secret")}, nil
	}
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		return response(200, `{"data":[{"id":"model-a"},{"id":"model-b"}]}`), nil
	})
	if err := Refresh(context.Background(), path, sources, secretReader, doer, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	snapshots, digest, err := LoadWithDigest(path, sources, now.Add(time.Minute))
	if err != nil || len(snapshots) != 1 || len(snapshots[0].ModelIDs) != 2 || len(digest) != 64 {
		t.Fatalf("snapshots=%+v digest=%s err=%v", snapshots, digest, err)
	}
	if _, _, err := LoadWithDigest(path, []config.OfficialSelectabilitySource{source("official-account:team-b", "openai-api")}, now.Add(time.Minute)); err == nil {
		t.Fatal("different scope reused snapshot")
	}
	if _, err := Load(path, sources, now.Add(MaxAge)); err == nil {
		t.Fatal("expired snapshot accepted")
	}
}

func TestFailedRefreshDoesNotReplaceLastCompleteBundle(t *testing.T) {
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	sources := []config.OfficialSelectabilitySource{source("official-account:team-a", "openai-api")}
	path := t.TempDir() + "/official.json"
	readSecret := func(config.CredentialConfig) (securecred.Value, error) {
		return securecred.Value{APIKey: []byte("secret")}, nil
	}
	good := doerFunc(func(*http.Request) (*http.Response, error) { return response(200, `{"data":[{"id":"model-a"}]}`), nil })
	if err := Refresh(context.Background(), path, sources, readSecret, good, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	before, err := Load(path, sources, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	bad := doerFunc(func(*http.Request) (*http.Response, error) { return response(200, `{"data":[]}`), nil })
	if err := Refresh(context.Background(), path, sources, readSecret, bad, func() time.Time { return now.Add(2 * time.Minute) }); err == nil {
		t.Fatal("empty official list accepted")
	}
	after, err := Load(path, sources, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(before[0].ModelIDs, ",") != strings.Join(after[0].ModelIDs, ",") {
		t.Fatal("failed refresh replaced the complete snapshot")
	}
}

func TestRedirectHTTPErrorAndMalformedIDsAreRejected(t *testing.T) {
	for name, doer := range map[string]Doer{
		"redirect": doerFunc(func(*http.Request) (*http.Response, error) {
			r := response(302, "redirect")
			r.Header.Set("Location", "https://attacker.invalid")
			return r, nil
		}),
		"unauthorized": doerFunc(func(*http.Request) (*http.Response, error) { return response(401, `{"error":"secret details"}`), nil }),
		"invalid id":   doerFunc(func(*http.Request) (*http.Response, error) { return response(200, `{"data":[{"id":" bad "}]}`), nil }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fetchIDs(context.Background(), "openai-api", []byte("key"), doer); err == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
}

func TestResponseBoundsDuplicateIDsAndProviderErrorsAreSafe(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "duplicate IDs", body: `{"data":[{"id":"model-a"},{"id":"model-a"}]}`},
		{name: "empty list", body: `{"data":[]}`},
		{name: "malformed shape", body: `{"data":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := fetchIDs(context.Background(), "openai-api", []byte("key"), doerFunc(func(*http.Request) (*http.Response, error) {
				return response(200, tc.body), nil
			})); err == nil {
				t.Fatal("unsafe or incomplete model list was accepted")
			}
		})
	}
	t.Run("oversized response", func(t *testing.T) {
		body := `{"data":[{"id":"` + strings.Repeat("a", MaxResponseSize) + `"}]}`
		if _, err := fetchIDs(context.Background(), "openai-api", []byte("key"), doerFunc(func(*http.Request) (*http.Response, error) {
			return response(200, body), nil
		})); err == nil {
			t.Fatal("oversized provider response was accepted")
		}
	})
	t.Run("provider error body is not exposed", func(t *testing.T) {
		const privateDetail = "provider-private-error-detail"
		_, err := fetchIDs(context.Background(), "openai-api", []byte("key"), doerFunc(func(*http.Request) (*http.Response, error) {
			return response(401, `{"error":"`+privateDetail+`"}`), nil
		}))
		if err == nil || strings.Contains(err.Error(), privateDetail) {
			t.Fatalf("provider body leaked through the error: %v", err)
		}
	})
}

func TestRefreshClearsExternalCredentialBuffer(t *testing.T) {
	now := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	sources := []config.OfficialSelectabilitySource{source("official-account:team-a", "openai-api")}
	secretBytes := []byte("external-test-secret")
	reader := func(config.CredentialConfig) (securecred.Value, error) {
		return securecred.Value{APIKey: secretBytes}, nil
	}
	doer := doerFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer external-test-secret" {
			t.Fatal("the configured provider key was not used for the official request")
		}
		return response(200, `{"data":[{"id":"model-a"}]}`), nil
	})
	if err := Refresh(context.Background(), filepath.Join(t.TempDir(), "snapshot.json"), sources, reader, doer, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	for _, value := range secretBytes {
		if value != 0 {
			t.Fatal("credential source buffer was not cleared after refresh")
		}
	}
}
