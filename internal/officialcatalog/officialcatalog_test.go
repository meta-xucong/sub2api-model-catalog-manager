package officialcatalog

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func specFor(t *testing.T, provider string) sourceSpec {
	t.Helper()
	spec, ok := sourceForProvider(provider)
	if !ok {
		t.Fatalf("source missing: %s", provider)
	}
	return spec
}

func specForID(t *testing.T, sourceID string) sourceSpec {
	t.Helper()
	spec, ok := sourceForID(sourceID)
	if !ok {
		t.Fatalf("source missing: %s", sourceID)
	}
	return spec
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestOfficialLifecycleParsersUseAPIProductSources(t *testing.T) {
	now := time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct{ provider, fixture, model, status string }{
		{"openai", "openai-deprecations.html", "gpt-retiring-test", "announced_deprecated"},
		{"anthropic", "anthropic-deprecations.html", "claude-retiring-test", "announced_deprecated"},
		{"deepseek", "deepseek-updates.html", "deepseek-old-test", "retired_with_compatibility_route"},
		{"xai", "xai-release-notes.html", "grok-retiring-test", "announced_deprecated"},
	}
	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			parsed, err := parseSourcePage(specFor(t, tc.provider), specFor(t, tc.provider).rootURL, fixture(t, tc.fixture), now)
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Evidence) == 0 {
				t.Fatal("expected explicit lifecycle evidence")
			}
			found := false
			for _, evidence := range parsed.Evidence {
				if evidence.ModelID == tc.model {
					found = evidence.Status == tc.status
					if evidence.SourceURL == "" || evidence.SourceTitle == "" || evidence.ContentSHA256 == "" || evidence.Excerpt == "" {
						t.Fatalf("incomplete source evidence: %+v", evidence)
					}
				}
			}
			if !found {
				t.Fatalf("missing expected evidence %s status=%s: %+v", tc.model, tc.status, parsed.Evidence)
			}
			for _, evidence := range parsed.Evidence {
				if evidence.ModelID == "gpt-successor-test" || evidence.ModelID == "grok-current-test" || evidence.ModelID == "deepseek-current-test" {
					t.Fatalf("replacement was incorrectly marked retired: %+v", evidence)
				}
			}
		})
	}
	rootSpec := specFor(t, "alibaba")
	root, err := parseSourcePage(rootSpec, rootSpec.rootURL, fixture(t, "alibaba-depreciation.html"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(root.Links) != 1 || len(root.Evidence) != 0 {
		t.Fatalf("Alibaba index should yield only bounded announcement links: %+v", root)
	}
	bulletinURL := alibabaBulletinURL("123456")
	child, err := parseSourcePage(rootSpec, bulletinURL, fixture(t, "alibaba-bulletin-response.json"), now)
	if err != nil {
		t.Fatal(err)
	}
	gotAlibaba := make(map[string]LifecycleEvidence)
	alibabaReplacementFound := false
	for _, evidence := range child.Evidence {
		if _, exists := gotAlibaba[evidence.ModelID]; !exists || evidence.Replacement != "" {
			gotAlibaba[evidence.ModelID] = evidence
		}
		if evidence.ModelID == "qwen-old-test" && evidence.Replacement == "qwen-new-test" {
			alibabaReplacementFound = true
		}
	}
	for _, model := range []string{"qwen-old-test", "gte-rerank", "qwen-list-old-a", "qwen-list-old-b"} {
		if evidence, ok := gotAlibaba[model]; !ok || evidence.Status != "announced_deprecated" {
			t.Fatalf("Alibaba notice missed expected lifecycle model %q: %+v", model, child.Evidence)
		}
	}
	for _, replacement := range []string{"qwen-new-test", "qwen-list-successor"} {
		if _, ok := gotAlibaba[replacement]; ok {
			t.Fatalf("Alibaba recommended replacement was incorrectly marked retired: %s (%+v)", replacement, child.Evidence)
		}
	}
	if gotAlibaba["gte-rerank"].EffectiveAt != "2099-03-04" {
		t.Fatalf("Alibaba prose effective date mismatch: %+v", gotAlibaba["gte-rerank"])
	}
	if !alibabaReplacementFound {
		t.Fatalf("Alibaba explicit table replacement metadata was lost: %+v", child.Evidence)
	}
	for _, body := range [][]byte{
		[]byte(`{"data":{"success":false,"info":{"title":"残留标题","detailList":[{"contentHtml":"<table><tr><td>qwen-footer-link</td><td>2099-02-03</td><td>该模型将下线</td></tr></table>"}]}}`),
		[]byte(`{"data":{"success":true,"info":{"title":" ","detailList":[{"contentHtml":"<p>content</p>"}]}}`),
		[]byte(`{"data":{"success":true,"info":{"title":"标题","detailList":[]}}}`),
		[]byte(`{"data":{"success":true,"info":{"title":"标题","detailList":[{"contentHtml":"  "}]}}}`),
		[]byte(`{"data":{"success":true,"info":{"title":"标题","detailList":[{"contentHtml":"<p>残缺响应"}]}} trailing`),
	} {
		if _, err := parseSourcePage(rootSpec, bulletinURL, body, now); err == nil {
			t.Fatal("invalid/failed Alibaba renderer response was accepted")
		}
	}
	xaiChild, err := parseSourcePage(specFor(t, "xai"), "https://docs.x.ai/developers/migration/retirement-test", fixture(t, "xai-migration.html"), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(xaiChild.Evidence) != 1 || xaiChild.Evidence[0].ModelID != "grok-retiring-test" || xaiChild.Evidence[0].Status != "announced_deprecated" {
		t.Fatalf("xAI migration page parse mismatch: %+v", xaiChild.Evidence)
	}
}

func TestProductLifecycleSourcesUseExactClientScopeEvidence(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		sourceID string
		fixture  string
		want     map[string]string
	}{
		{"openai-codex-models", "openai-codex-models.html", map[string]string{"GPT-5.5": "retired", "gpt-5.3-codex-spark": "retired", "gpt-5.4": "retired", "gpt-5.4-mini": "retired", "gpt-5.2": "deprecated", "gpt-5.3-codex": "deprecated"}},
		{"openai-cross-product-lifecycle-v2", "openai-cross-product-lifecycle.html", map[string]string{"GPT-5.5": "retired"}},
		{"anthropic-claude-release-notes", "anthropic-claude-release-notes.html", map[string]string{"claude-opus-4-20250514": "retired", "claude-opus-4-1-20250805": "retired"}},
		{"kimi-code-models", "kimi-code-models.html", map[string]string{}},
		{"kimi-code-whats-new", "kimi-code-whats-new.html", map[string]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.sourceID, func(t *testing.T) {
			spec := specForID(t, tc.sourceID)
			parsed, err := parseSourcePage(spec, spec.rootURL, fixture(t, tc.fixture), now)
			if err != nil {
				t.Fatal(err)
			}
			got := make(map[string]string)
			for _, evidence := range parsed.Evidence {
				if evidence.SourceID != spec.id || evidence.Scope != spec.scope || evidence.Provider != spec.provider {
					t.Fatalf("product evidence escaped its exact source scope: %+v", evidence)
				}
				got[evidence.ModelID] = evidence.Status
			}
			if len(got) != len(tc.want) {
				t.Fatalf("evidence IDs=%v want %v", got, tc.want)
			}
			for id, want := range tc.want {
				if got[id] != want {
					t.Errorf("%s status=%q want %q", id, got[id], want)
				}
			}
		})
	}
}

func TestOpenAIUnionRetirementRequiresExplicitChatGPTProductSurface(t *testing.T) {
	spec := specForID(t, "openai-cross-product-lifecycle-v2")
	cases := []string{
		"gpt-5.5 retires from ChatGPT and Codex on October 14, 2026.",
		"gpt-5.4 retires from Codex with ChatGPT sign-in on August 31, 2026.",
	}
	for _, notice := range cases {
		t.Run(notice, func(t *testing.T) {
			body := []byte("<!doctype html><html><head><title>ChatGPT &amp; Codex Changelog</title></head><body><h1>ChatGPT and Codex Changelog</h1><ul><li data-product=\"codex\" data-products=\"codex\"><h3>Notice</h3><p>" + notice + "</p></li></ul></body></html>")
			parsed, err := parseSourcePage(spec, spec.rootURL, body, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Evidence) != 0 {
				t.Fatalf("non-specific ChatGPT wording must not establish accepted-union retirement: %+v", parsed.Evidence)
			}
		})
	}
}

func TestExactProductLifecycleMentionsExcludeSuccessorModel(t *testing.T) {
	when := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		text string
		want []string
	}{
		{
			name: "old model replaced by successor",
			text: "gpt-5.3-codex-spark was retired on September 14, 2026 and is replaced by gpt-6.1-codex.",
			want: []string{"gpt-5.3-codex-spark"},
		},
		{
			name: "successor replaces old model",
			text: "gpt-6.1-codex replaces gpt-5.3-codex-spark, which was retired on September 14, 2026.",
			want: []string{"gpt-5.3-codex-spark"},
		},
		{
			name: "two explicitly retired models",
			text: "gpt-5.4 and gpt-5.4-mini were retired.",
			want: []string{"gpt-5.4", "gpt-5.4-mini"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseExactLifecycleMentions(tc.text, "gpt-", when)
			ids := make([]string, 0, len(got))
			for _, item := range got {
				if item.Status != "retired" {
					t.Fatalf("lifecycle status=%q want retired: %+v", item.Status, item)
				}
				ids = append(ids, item.ModelID)
			}
			if !reflect.DeepEqual(ids, tc.want) {
				t.Fatalf("lifecycle subjects=%v want %v", ids, tc.want)
			}
		})
	}
}

func TestLifecycleStatusDoesNotTreatDeprecatedDatesOrFutureWordingAsRetired(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		text            string
		want            string
		wantEffectiveAt string
	}{
		{text: "gpt-test will be retired", want: "announced_deprecated"},
		{text: "gpt-test is scheduled to be retired", want: "announced_deprecated"},
		{text: "gpt-test was deprecated on September 14, 2026", want: "deprecated"},
		{text: "gpt-test will be retired on September 14, 2026", want: "retired", wantEffectiveAt: "2026-09-14"},
		{text: "gpt-test will be retired on December 13, 2026", want: "announced_deprecated", wantEffectiveAt: "2026-12-13"},
		{text: "gpt-test is no longer available", want: "retired"},
		{text: "gpt-test was released on September 1, 2026 and will be retired", want: "announced_deprecated"},
		{text: "gpt-test was released on September 1, 2026 and will be retired on December 13, 2026", want: "announced_deprecated", wantEffectiveAt: "2026-12-13"},
	}
	for _, tc := range cases {
		got, effectiveAt := lifecycleStatusInContext(tc.text, now)
		if got != tc.want {
			t.Errorf("lifecycleStatusInContext(%q)=%q want %q", tc.text, got, tc.want)
		}
		if effectiveAt != tc.wantEffectiveAt {
			t.Errorf("lifecycleStatusInContext(%q) effective date=%q want %q", tc.text, effectiveAt, tc.wantEffectiveAt)
		}
	}

	if !exclusionEligible(LifecycleEvidence{Status: "deprecated"}, now) {
		t.Fatal("an official model already marked deprecated was not eligible for removal")
	}
	if exclusionEligible(LifecycleEvidence{Status: "announced_deprecated", EffectiveAt: "2026-09-14"}, now) {
		t.Fatal("an old deprecation date without a retirement status must not auto-exclude")
	}
	if !exclusionEligible(LifecycleEvidence{Status: "announced_deprecated", EffectiveAt: "2026-12-13"}, now) {
		t.Fatal("a retirement date exactly 60 days away should remain eligible")
	}
	if exclusionEligible(LifecycleEvidence{Status: "announced_deprecated", EffectiveAt: "2026-12-14"}, now) {
		t.Fatal("a retirement date 61 days away should not be eligible")
	}
}

func TestProductLifecycleParserKeepsSuccessorMentionsOutOfRetiredSubjects(t *testing.T) {
	when := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for _, text := range []string{
		"gpt-5.3-codex-spark was retired; use gpt-6.1-codex instead.",
		"The replacement is gpt-6.1-codex; gpt-5.3-codex-spark was retired.",
		"gpt-5.3-codex-spark was retired and the successor gpt-6.1-codex is available.",
		"Use gpt-6.1-codex instead of retired gpt-5.3-codex-spark.",
	} {
		got := parseExactLifecycleMentions(text, "gpt-", when)
		if len(got) != 1 || got[0].ModelID != "gpt-5.3-codex-spark" || got[0].Status != "retired" {
			t.Errorf("successor leaked into retired subjects for %q: %+v", text, got)
		}
	}

	claude := parseClaudeProductLifecycle("Claude Code says Opus 4.1 was retired and replaced by Opus 5.0.", when)
	if len(claude) != 1 || claude[0].ModelID != "claude-opus-4-1-20250805" || claude[0].Status != "retired" {
		t.Fatalf("Claude replacement sentence should retain only retired Opus 4.1: %+v", claude)
	}
	claudeInsteadOf := parseClaudeProductLifecycle("Claude Code recommends Opus 4.1 instead of retired Opus 4.", when)
	if len(claudeInsteadOf) != 1 || claudeInsteadOf[0].ModelID != "claude-opus-4-20250514" || claudeInsteadOf[0].Status != "retired" {
		t.Fatalf("Claude instead-of sentence should identify only retired Opus 4: %+v", claudeInsteadOf)
	}
	claudeOpus45 := parseClaudeProductLifecycle("Claude Code says Opus 4.5 was retired.", when)
	if len(claudeOpus45) != 0 {
		t.Fatalf("Opus 4.5 must not be crosswalked to the distinct Opus 4 model ID: %+v", claudeOpus45)
	}
	claudeOpus4And45 := parseClaudeProductLifecycle("Claude Code says Opus 4 was retired; Opus 4.5 remains available.", when)
	if len(claudeOpus4And45) != 1 || claudeOpus4And45[0].ModelID != "claude-opus-4-20250514" {
		t.Fatalf("Opus 4.5 must remain distinct while an explicit Opus 4 retirement is retained: %+v", claudeOpus4And45)
	}
	claudeSuccessorOnly := parseClaudeProductLifecycle("Claude Code recommends the replacement Opus 4.1 for an older retired model.", when)
	if len(claudeSuccessorOnly) != 0 {
		t.Fatalf("Claude successor-only mention must not become retired evidence: %+v", claudeSuccessorOnly)
	}
}

func TestFixedSourceFixturesBuildValidSnapshots(t *testing.T) {
	when := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	doer := fixtureRouter(t, false)
	for _, spec := range sourceManifest {
		t.Run(spec.id, func(t *testing.T) {
			if spec.adapter != "" {
				t.Skip("authenticated API adapter has dedicated request tests")
			}
			snapshot, err := fetchSource(context.Background(), spec, nil, doer, &requestBudget{}, func() time.Time { return when })
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSnapshot(spec, snapshot); err != nil {
				var pageEvidence []LifecycleEvidence
				for _, page := range snapshot.Pages {
					pageEvidence = append(pageEvidence, page.Evidence...)
				}
				t.Fatalf("fixture snapshot invalid: %v; pages=%+v aggregate=%+v", err, normalizeEvidence(pageEvidence), normalizeEvidence(snapshot.Evidence))
			}
			available := make([]string, 0)
			for _, page := range snapshot.Pages {
				available = append(available, page.AvailableModelIDs...)
			}
			if spec.catalog && !spec.catalogMayBeEmpty && len(available) == 0 {
				t.Fatalf("official current model list was not parsed for %s", spec.id)
			}
			if spec.id == "kimi-code-models" {
				got := snapshot.Pages[0].AvailableModelIDs
				want := []string{"k3", "k3-256k", "kimi-for-coding", "kimi-for-coding-highspeed"}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("Kimi official model table mismatch: got=%v want=%v", got, want)
				}
			}
			if spec.id == "openai-cross-product-lifecycle-v2" && len(snapshot.Pages[0].Links) != 0 {
				t.Fatalf("non-recursive Codex changelog should not persist unused links: %d", len(snapshot.Pages[0].Links))
			}
			if spec.id == "xai-grok-web-models" {
				if !containsString(available, "grok-4.5") || containsString(available, "grok-4.7") {
					t.Fatalf("Grok news catalog accepted wrong-surface or missed web models: %v", available)
				}
			}
		})
	}
}

func TestOfficialWebProductCatalogParsersAndReviewedAliases(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		sourceID string
		fixture  string
		want     []string
		absent   []string
	}{
		{"openai-chatgpt-models", "openai-chatgpt-models.html", []string{"gpt-5.6", "gpt-6"}, []string{"gpt-6.1", "gpt-9-api-only"}},
		{"openai-chatgpt-gpt6-announcement", "openai-gpt6-for-everyone.html", []string{"gpt-6"}, []string{"gpt-6.1", "gpt-9-api-only"}},
		{"anthropic-claude-web-models", "anthropic-claude-web-models.html", []string{
			"claude-fable-5-1", "claude-fable-5", "claude-opus-5-5", "claude-opus-5", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6",
			"claude-sonnet-5-5", "claude-sonnet-5", "claude-sonnet-4-6", "claude-haiku-5-5",
		}, []string{"claude-haiku-4-5-20251001"}},
		{"kimi-web-models", "kimi-web-models.html", []string{"k3"}, []string{"k2.6", "k3-256k"}},
	}
	for _, tc := range cases {
		t.Run(tc.sourceID, func(t *testing.T) {
			spec := specForID(t, tc.sourceID)
			parsed, err := parseSourcePage(spec, spec.rootURL, fixture(t, tc.fixture), now)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !containsString(parsed.AvailableModelIDs, want) {
					t.Errorf("available IDs %v miss %q", parsed.AvailableModelIDs, want)
				}
			}
			for _, absent := range tc.absent {
				if containsString(parsed.AvailableModelIDs, absent) {
					t.Errorf("unlisted or unsupported display alias %q was admitted: %v", absent, parsed.AvailableModelIDs)
				}
			}
		})
	}
	for _, pair := range []struct {
		webSourceID, webFixture   string
		codeSourceID, codeFixture string
	}{
		{"anthropic-claude-web-models", "anthropic-claude-web-models.html", "anthropic-claude-code-models", "anthropic-claude-code-models.html"},
		{"kimi-web-models", "kimi-web-models.html", "kimi-code-models", "kimi-code-models.html"},
	} {
		webSpec, codeSpec := specForID(t, pair.webSourceID), specForID(t, pair.codeSourceID)
		webCatalog, err := parseSourcePage(webSpec, webSpec.rootURL, fixture(t, pair.webFixture), now)
		if err != nil {
			t.Fatal(err)
		}
		codeCatalog, err := parseSourcePage(codeSpec, codeSpec.rootURL, fixture(t, pair.codeFixture), now)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range webCatalog.AvailableModelIDs {
			if !containsString(codeCatalog.AvailableModelIDs, id) {
				t.Errorf("reviewed web alias %q has no exact ID in the official companion Code model list", id)
			}
		}
	}
	// Cross-check each reviewed Claude consumer display-name alias against the
	// exact display-name/ID pair on the official Claude Code model list. A set
	// membership check alone would allow two valid IDs to be accidentally swapped.
	claudeWeb, ok := extractHTMLHeadingSection(string(fixture(t, "anthropic-claude-web-models.html")), "Chatting with Claude", "Claude Code")
	if !ok {
		t.Fatal("Claude consumer model section is missing")
	}
	claudeCode, ok := extractHTMLHeadingSection(string(fixture(t, "anthropic-claude-code-models.html")), "Supported models", "Change model for current session only")
	if !ok {
		t.Fatal("Claude Code supported-model section is missing")
	}
	codeTagRE := regexp.MustCompile(`(?is)<code\b[^>]*>(.*?)</code>`)
	claudeCodePairs := make(map[string]string)
	for _, item := range listItemRE.FindAllString(claudeCode, -1) {
		match := codeTagRE.FindStringSubmatch(item)
		if len(match) != 2 {
			continue
		}
		id := strings.ToLower(cleanFragment(match[1]))
		label := strings.ToLower(strings.TrimSuffix(cleanFragment(codeTagRE.ReplaceAllString(item, "")), ","))
		claudeCodePairs[label] = id
	}
	for _, row := range extractTableRows(claudeWeb) {
		if len(row) == 0 || strings.EqualFold(strings.TrimSpace(row[0]), "Model") {
			continue
		}
		displayName := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(row[0]), "Claude ")))
		wantID := claudeConsumerModelAliases[strings.ToLower(strings.TrimSpace(row[0]))]
		if wantID == "" {
			continue
		}
		if gotID := claudeCodePairs[displayName]; gotID != wantID {
			t.Errorf("Claude display alias %q maps to %q; official Code list pairs it with %q", row[0], wantID, gotID)
		}
	}

	// Preserve the already supported Codex, Claude Code, and Kimi Code sources.
	for _, tc := range []struct {
		sourceID string
		fixture  string
		want     string
	}{
		{"openai-codex-models", "openai-codex-models.html", "gpt-6-astra"},
		{"anthropic-claude-code-models", "anthropic-claude-code-models.html", "claude-sonnet-5-5"},
		{"kimi-code-models", "kimi-code-models.html", "k3-256k"},
	} {
		spec := specForID(t, tc.sourceID)
		parsed, err := parseSourcePage(spec, spec.rootURL, fixture(t, tc.fixture), now)
		if err != nil || !containsString(parsed.AvailableModelIDs, tc.want) {
			t.Fatalf("existing source %s failed: IDs=%v err=%v", tc.sourceID, parsed.AvailableModelIDs, err)
		}
	}
}

func TestOfficialWebProductCatalogParsersRejectStructureDrift(t *testing.T) {
	cases := []struct {
		sourceID string
		fixture  string
		needle   string
	}{
		{"openai-chatgpt-models", "openai-chatgpt-models.html", "Choose a thinking level"},
		{"anthropic-claude-web-models", "anthropic-claude-web-models.html", "Chatting with Claude"},
		{"kimi-web-models", "kimi-web-models.html", "Choose a model"},
		{"xai-grok-web-models", "xai-grok-4-5-everywhere.html", "now on grok.com"},
	}
	for _, tc := range cases {
		t.Run(tc.sourceID, func(t *testing.T) {
			spec := specForID(t, tc.sourceID)
			body := string(fixture(t, tc.fixture))
			mutated := strings.ReplaceAll(body, tc.needle, "unexpected heading")
			if mutated == body {
				t.Fatal("fixture mutation did not apply")
			}
			if _, err := parseSourcePage(spec, spec.rootURL, []byte(mutated), time.Now()); err == nil {
				t.Fatal("catalog page with missing structure anchor was accepted")
			}
		})
	}
}

func TestGrokWebCatalogRequiresExplicitConsumerSurfaceAndReviewedAlias(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	spec := specForID(t, "xai-grok-web-models")
	valid, err := parseSourcePage(spec, spec.rootURL, fixture(t, "xai-grok-4-5-everywhere.html"), now)
	if err != nil || !reflect.DeepEqual(valid.AvailableModelIDs, []string{"grok-4.5"}) {
		t.Fatalf("reviewed Grok 4.5 web alias mismatch: IDs=%v err=%v", valid.AvailableModelIDs, err)
	}
	wrongSurface, err := parseSourcePage(spec, "https://x.ai/news/grok-4-7", fixture(t, "xai-grok-4-7-wrong-surface.html"), now)
	if err != nil || len(wrongSurface.AvailableModelIDs) != 0 {
		t.Fatalf("Grok 4.7 API/Build announcement was admitted as web availability: IDs=%v err=%v", wrongSurface.AvailableModelIDs, err)
	}
}

func TestGrokWebCatalogPositiveEvidenceFlowsThroughProductAvailability(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	spec := specForID(t, "xai-grok-web-models")
	snapshot, err := fetchSource(context.Background(), spec, nil, fixtureRouter(t, false), &requestBudget{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	result := StartupSyncResult{Providers: []ProviderSync{{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: "updated", Snapshot: &snapshot}}}
	availability := EvaluateProductAvailability(result, []string{"grok-4.5", "grok-4.7"}, now)
	byID := map[string]ProductModelAvailability{}
	for _, item := range availability {
		byID[item.ModelID] = item
	}
	if byID["grok-4.5"].Status != "available" || byID["grok-4.5"].MatchKind != "exact" {
		t.Fatalf("official Grok web evidence did not flow to positive eligibility: %+v", byID["grok-4.5"])
	}
	if byID["grok-4.7"].Status != "insufficient_evidence" {
		t.Fatalf("wrong-surface Grok 4.7 should remain unknown: %+v", byID["grok-4.7"])
	}
}

func TestLifecycleScopeFreshnessAndNearRetirementBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	base := makeProductScopeResult(t, "openai_codex_chatgpt_login", now, false, false)
	if !LifecycleScopeReady(base, "openai_codex_chatgpt_login", now) {
		t.Fatal("fresh complete Codex source set should be ready")
	}
	current, ok := CurrentModelCatalog(base, "openai_codex_chatgpt_login", now)
	currentIDs := map[string]bool{}
	for _, modelID := range current.ModelIDs {
		currentIDs[modelID] = true
	}
	if !ok || !currentIDs["gpt-6.1-sol"] || !currentIDs["gpt-6-sol"] || !currentIDs["GPT-5.6"] || currentIDs["gpt-5.2"] {
		t.Fatalf("official exact current model list was not extracted: %+v, ready=%t", current, ok)
	}
	if currentIDs["gpt-5.5"] || currentIDs["gpt-5.4"] || currentIDs["gpt-5.4-mini"] {
		t.Fatalf("retired IDs leaked back into the current catalog because of case differences: %+v", current.ModelIDs)
	}
	if !CurrentCatalogIncludes("openai_codex_chatgpt_login", "gpt-5.6-terra", current.ModelIDs) || CurrentCatalogIncludes("openai_codex_chatgpt_login", "gpt-5.6-terra-openai-compact", current.ModelIDs) {
		t.Fatalf("only explicit GPT-5.6 aliases should survive: %+v", current.ModelIDs)
	}
	if !CurrentCatalogIncludes("openai_codex_chatgpt_login", "gpt-6-sol", current.ModelIDs) || CurrentCatalogIncludes("openai_codex_chatgpt_login", "gpt-image-2", current.ModelIDs) {
		t.Fatalf("Codex article extraction should keep listed GPT-6 Sol and exclude unrelated image IDs: %+v", current.ModelIDs)
	}
	got := AutomaticExclusions(base, []string{"openai_codex_chatgpt_login"}, now)
	if len(got) != 1 || !strings.EqualFold(got[0].ModelID, "gpt-5.5") || got[0].Status != "retired" {
		t.Fatalf("only the exact cross-product GPT-5.5 retirement should remove a model from the accepted union: %+v", got)
	}
	codexRetirements := productSurfaceRetirements(base, "openai_codex", now)
	if !containsLifecycleModel(codexRetirements, "gpt-5.5") {
		t.Fatalf("accepted-union retirement must suppress contradictory positive Codex evidence: %+v", codexRetirements)
	}
	if leaked := productSurfaceRetirements(base, "anthropic_claude_consumer", now); containsLifecycleModel(leaked, "gpt-5.5") {
		t.Fatalf("OpenAI accepted-union evidence leaked into the Anthropic product surface: %+v", leaked)
	}
	availability := EvaluateProductAvailability(base, []string{
		"gpt-6-sol", "gpt-5.6-terra", "gpt-5.5", "gpt-5.4", "gpt-4o-audio-preview",
		"gpt-4o-realtime-preview", "gpt-5.6-terra-openai-compact", "deepseek-flash", "qwen3.8-flash",
	}, now)
	byID := make(map[string]ProductModelAvailability, len(availability))
	for _, item := range availability {
		byID[strings.ToLower(item.ModelID)] = item
	}
	for _, id := range []string{"gpt-6-sol", "gpt-5.6-terra"} {
		if byID[id].Status != "available" {
			t.Errorf("exact product evidence should keep %s available: %+v", id, byID[id])
		}
	}
	if byID["gpt-5.5"].Status != "unavailable" || byID["gpt-5.5"].MatchKind != "accepted_union_retirement" {
		t.Errorf("explicit cross-product retirement should remove gpt-5.5 from the accepted union: %+v", byID["gpt-5.5"])
	}
	// Prove the new accepted-union source alone suppresses a conflicting Codex
	// positive. The same-surface Codex retirement must not mask a broken union path.
	unionOnly := base
	unionOnly.Providers = append([]ProviderSync(nil), base.Providers...)
	for i := range unionOnly.Providers {
		provider := &unionOnly.Providers[i]
		if provider.SourceID != "openai-codex-models" || provider.Snapshot == nil {
			continue
		}
		snapshot := *provider.Snapshot
		snapshot.Pages = append([]CachedPage(nil), snapshot.Pages...)
		snapshot.Evidence = append([]LifecycleEvidence(nil), snapshot.Evidence...)
		filtered := snapshot.Evidence[:0]
		for _, evidence := range snapshot.Evidence {
			if !strings.EqualFold(evidence.ModelID, "gpt-5.5") {
				filtered = append(filtered, evidence)
			}
		}
		snapshot.Evidence = filtered
		for pageIndex := range snapshot.Pages {
			page := snapshot.Pages[pageIndex]
			page.Evidence = append([]LifecycleEvidence(nil), page.Evidence...)
			pageFiltered := page.Evidence[:0]
			for _, evidence := range page.Evidence {
				if !strings.EqualFold(evidence.ModelID, "gpt-5.5") {
					pageFiltered = append(pageFiltered, evidence)
				}
			}
			page.Evidence = pageFiltered
			snapshot.Pages[pageIndex] = page
		}
		var err error
		snapshot.ContentSHA256, err = snapshotDigest(snapshot.Pages)
		if err != nil {
			t.Fatal(err)
		}
		provider.Snapshot = &snapshot
	}
	unionOnlyAvailability := EvaluateProductAvailability(unionOnly, []string{"gpt-5.5"}, now)
	if len(unionOnlyAvailability) != 1 || unionOnlyAvailability[0].Status != "unavailable" || unionOnlyAvailability[0].MatchKind != "accepted_union_retirement" {
		t.Fatalf("cross-product lifecycle evidence alone must suppress a conflicting Codex positive: %+v", unionOnlyAvailability)
	}
	for _, id := range []string{"gpt-4o-audio-preview", "gpt-4o-realtime-preview", "gpt-5.6-terra-openai-compact", "deepseek-flash", "qwen3.8-flash"} {
		if byID[id].Status != "insufficient_evidence" {
			t.Errorf("product-specific retirement, omission, alias suffix, or another vendor must remain insufficient for %s: %+v", id, byID[id])
		}
	}
	if byID["qwen3.8-flash"].Provider != "alibaba" {
		t.Errorf("Qwen versioned namespace was not recognized independently of relay platform: %+v", byID["qwen3.8-flash"])
	}
	if byID["gpt-5.6-terra"].MatchKind != "explicit_alias" {
		t.Errorf("GPT-5.6 product alias should be visibly marked explicit: %+v", byID["gpt-5.6-terra"])
	}

	exactSevenDays := makeProductScopeResult(t, "openai_codex_chatgpt_login", now.Add(-MaxLifecycleCacheAge), false, false)
	if !LifecycleScopeReady(exactSevenDays, "openai_codex_chatgpt_login", now) {
		t.Fatal("exact seven-day cache boundary must remain eligible")
	}
	stale := makeProductScopeResult(t, "openai_codex_chatgpt_login", now.Add(-MaxLifecycleCacheAge-time.Second), false, false)
	if LifecycleScopeReady(stale, "openai_codex_chatgpt_login", now) || len(AutomaticExclusions(stale, []string{"openai_codex_chatgpt_login"}, now)) != 0 {
		t.Fatal("cache older than seven days must block the whole product scope")
	}
	future := makeProductScopeResult(t, "openai_codex_chatgpt_login", now.Add(time.Second), false, false)
	if LifecycleScopeReady(future, "openai_codex_chatgpt_login", now) {
		t.Fatal("future-dated source snapshots must fail closed")
	}
	missing := makeProductScopeResult(t, "openai_codex_chatgpt_login", now, true, false)
	if LifecycleScopeReady(missing, "openai_codex_chatgpt_login", now) {
		t.Fatal("a missing required official source must block the entire product scope")
	}

	near60 := makeProductScopeResult(t, "openai_codex_chatgpt_login", now, false, true)
	selected := AutomaticExclusions(near60, []string{"openai_codex_chatgpt_login"}, now)
	selectedIDs := map[string]bool{}
	for _, item := range selected {
		selectedIDs[strings.ToLower(item.ModelID)] = true
	}
	for _, id := range []string{"gpt-5.5", "gpt-near-sixty-test", "gpt-retired-today-test", "gpt-retired-past-test"} {
		if !selectedIDs[id] {
			t.Errorf("explicit accepted-union lifecycle event %q was not selected: %+v", id, selected)
		}
	}
	if selectedIDs["gpt-near-sixty-one-test"] {
		t.Fatalf("retirement outside the 60-day horizon was selected: %+v", selected)
	}
}

func TestFailedCurrentFetchCannotUseLastGoodSnapshotForProductDecisions(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	for _, staleStatus := range []string{"stale", "offline_cached"} {
		t.Run(staleStatus, func(t *testing.T) {
			result := makeProductScopeResult(t, "openai_codex_chatgpt_login", now, false, false)
			for index := range result.Providers {
				result.Providers[index].Status = staleStatus
				result.Providers[index].ErrorCode = "current_fetch_failed"
			}

			if LifecycleScopeReady(result, "openai_codex_chatgpt_login", now) {
				t.Fatal("last-good snapshots incorrectly made the product scope actionable")
			}
			if exclusions := AutomaticExclusions(result, []string{"openai_codex_chatgpt_login"}, now); len(exclusions) != 0 {
				t.Fatalf("stale lifecycle evidence authorized exclusions: %+v", exclusions)
			}
			if _, ok := CurrentModelCatalog(result, "openai_codex_chatgpt_login", now); ok {
				t.Fatal("last-good product page was exposed as a current catalog")
			}
			availability := EvaluateProductAvailability(result, []string{"gpt-5.6", "gpt-5.5", "gpt-5.4"}, now)
			for _, item := range availability {
				if item.Status != "insufficient_evidence" {
					t.Errorf("cached page authorized a %s decision for %s: %+v", item.Status, item.ModelID, item)
				}
			}
		})
	}
}

func containsLifecycleModel(evidence []LifecycleEvidence, modelID string) bool {
	for _, item := range evidence {
		if strings.EqualFold(item.ModelID, modelID) {
			return true
		}
	}
	return false
}

func TestCurrentCatalogIncludesOpenAIVersionFamiliesButNotOtherProductIDs(t *testing.T) {
	catalog := []string{"gpt-5.6", "gpt-6", "gpt-6.1", "gpt-6-astra", "gpt-6-luna"}
	tests := []struct {
		id      string
		want    bool
		compare bool
	}{
		{id: "gpt-5.6-sol", want: true, compare: true},
		{id: "gpt-5.6-terra", want: true, compare: true},
		{id: "gpt-5.6-terra-openai-compact", want: false, compare: false},
		{id: "gpt-5.5-openai-compact", want: false, compare: false},
		{id: "gpt-5.4-mini", want: false, compare: false},
		{id: "gpt-7.0-preview", want: false, compare: false},
		{id: "gpt-4o-audio-preview", want: false, compare: false},
		{id: "gpt-image-2.5-flare", want: false, compare: false},
		{id: "gpt-5.5-fast", want: false, compare: false},
		{id: "deepseek-flash", want: false, compare: false},
	}
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			if got := CurrentCatalogIncludes("openai_codex_chatgpt_login", test.id, catalog); got != test.want {
				t.Errorf("CurrentCatalogIncludes(%q)=%t want %t", test.id, got, test.want)
			}
			if got := HasComparableModelFamily("openai_codex_chatgpt_login", test.id, catalog); got != test.compare {
				t.Errorf("HasComparableModelFamily(%q)=%t want %t", test.id, got, test.compare)
			}
		})
	}
	if CurrentCatalogIncludes("kimi_code_login", "k3-256k", []string{"k3", "k3-256k"}) != true {
		t.Fatal("non-OpenAI catalog should retain exact official IDs")
	}
}

func TestAPILifecycleCatalogNeverEstablishesProductAvailability(t *testing.T) {
	got := EvaluateProductAvailability(StartupSyncResult{Providers: []ProviderSync{{
		SourceID: "openai-api-deprecations", Provider: "openai", Scope: "api", Status: "updated",
	}}}, []string{"gpt-6-sol", "gpt-5.5"}, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
	for _, item := range got {
		if item.Status != "insufficient_evidence" || item.MatchKind != "none" {
			t.Fatalf("API lifecycle source must not qualify login-product model %s: %+v", item.ModelID, item)
		}
	}
}

func TestConsumerRetirementDoesNotCancelClaudeCodePositiveEvidence(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	startup := makeProductScopeResult(t, "anthropic_claude_code_login", now, false, false)
	addTestProductLifecycleEvidence(t, &startup, "anthropic-claude-release-notes", "claude-sonnet-5-5", "announced_deprecated", "2026-10-29", now)
	retirements := productSurfaceRetirements(startup, "anthropic_claude_consumer", now)
	foundRetirement := false
	for _, item := range retirements {
		foundRetirement = foundRetirement || item.ModelID == "claude-sonnet-5-5"
	}
	if !foundRetirement {
		t.Fatalf("consumer retirement fixture was not captured: %+v", retirements)
	}
	if codeRetirements := productSurfaceRetirements(startup, "anthropic_claude_code", now); len(codeRetirements) != 0 {
		t.Fatalf("consumer retirement leaked into Claude Code surface: %+v", codeRetirements)
	}
	availability := EvaluateProductAvailability(startup, []string{"claude-sonnet-5-5"}, now)
	if len(availability) != 1 || availability[0].Status != "available" || availability[0].MatchKind != "exact" {
		t.Fatalf("future consumer retirement must not cancel the current exact Claude Code model listing: %+v", availability)
	}
}

func TestUnavailableRequiresEvidenceCoveringAcceptedProductUnion(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	startup := makeProductScopeResult(t, "openai_codex_chatgpt_login", now, false, false)
	ids := EvaluateProductAvailability(startup, []string{"gpt-4o-audio-preview", "gpt-5.4", "gpt-5.5"}, now)
	byID := map[string]ProductModelAvailability{}
	for _, item := range ids {
		byID[item.ModelID] = item
	}
	if byID["gpt-5.4"].Status != "unavailable" || byID["gpt-5.4"].MatchKind != "accepted_union_version_floor" || byID["gpt-5.5"].Status != "unavailable" {
		t.Fatalf("older GPT versions should fall below the official floor while exact cross-product retirement remains attributed separately: %+v", ids)
	}
	if byID["gpt-4o-audio-preview"].Status != "insufficient_evidence" {
		t.Fatalf("specialized product IDs must remain unknown without complete union evidence: %+v", byID["gpt-4o-audio-preview"])
	}

	original := append([]sourceSpec(nil), sourceManifest...)
	defer func() { sourceManifest = original }()
	for i := range sourceManifest {
		if sourceManifest[i].scope == "openai_codex_chatgpt_login" && sourceManifest[i].catalog {
			sourceManifest[i].completeAcceptedUnion = true
		}
		if sourceManifest[i].id == "openai-cross-product-lifecycle-v2" {
			sourceManifest[i].lifecycleCoversAcceptedUnion = true
		}
	}
	fullEvidence := EvaluateProductAvailability(startup, []string{"gpt-4o-audio-preview", "gpt-5.4", "gpt-5.5"}, now)
	byID = map[string]ProductModelAvailability{}
	for _, item := range fullEvidence {
		byID[item.ModelID] = item
	}
	if byID["gpt-4o-audio-preview"].Status != "unavailable" || byID["gpt-4o-audio-preview"].MatchKind != "accepted_union_absence" {
		t.Fatalf("only an audited complete accepted-union catalog can establish absence for specialized model families: %+v", byID["gpt-4o-audio-preview"])
	}
	if byID["gpt-5.4"].Status != "unavailable" || byID["gpt-5.4"].MatchKind != "accepted_union_version_floor" {
		t.Fatalf("version-floor exclusion should remain independently attributed: %+v", byID["gpt-5.4"])
	}
	if byID["gpt-5.5"].Status != "unavailable" || byID["gpt-5.5"].MatchKind != "accepted_union_retirement" {
		t.Fatalf("only an audited accepted-union lifecycle source can establish retirement: %+v", byID["gpt-5.5"])
	}
}

func TestOlderVersionsBelowOfficialProductFloorAreUnavailable(t *testing.T) {
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	openAI := makeProductScopeResult(t, "openai_codex_chatgpt_login", now, false, false)
	openAIAvailability := EvaluateProductAvailability(openAI, []string{
		"gpt-5.2", "gpt-5.4", "gpt-5.5-openai-compact", "gpt-5.6",
	}, now)
	byID := make(map[string]ProductModelAvailability, len(openAIAvailability))
	for _, item := range openAIAvailability {
		byID[item.ModelID] = item
	}
	for _, id := range []string{"gpt-5.2", "gpt-5.4", "gpt-5.5-openai-compact"} {
		item := byID[id]
		if item.Status != "unavailable" || item.MatchKind != "accepted_union_version_floor" || len(item.SourceIDs) != 1 || item.SourceIDs[0] != "openai-codex-models" {
			t.Errorf("older GPT version %s must be rejected by the official current-version floor: %+v", id, item)
		}
	}
	if olderThanProductVersionFloor("openai_codex_chatgpt_login", "gpt-5.3-codex-spark", []string{"gpt-5.6", "gpt-6"}) {
		t.Error("the distinct Codex Spark family must not be compared against the base GPT version floor")
	}
	if byID["gpt-5.6"].Status != "available" {
		t.Errorf("the model at the official version floor must remain available: %+v", byID["gpt-5.6"])
	}

	grok := makeProductScopeResult(t, "xai_grok_web_login", now, false, false)
	grokAvailability := EvaluateProductAvailability(grok, []string{"grok-4.3", "grok-4.5", "grok-4.6", "grok-4.7"}, now)
	byID = make(map[string]ProductModelAvailability, len(grokAvailability))
	for _, item := range grokAvailability {
		byID[item.ModelID] = item
	}
	if byID["grok-4.3"].Status != "unavailable" || byID["grok-4.3"].MatchKind != "accepted_union_version_floor" {
		t.Errorf("older Grok version must be rejected by the official current-version floor: %+v", byID["grok-4.3"])
	}
	if byID["grok-4.5"].Status != "available" {
		t.Errorf("the model at the official Grok web floor must remain available: %+v", byID["grok-4.5"])
	}
	for _, id := range []string{"grok-4.6", "grok-4.7"} {
		if byID[id].Status != "insufficient_evidence" {
			t.Errorf("a newer but unlisted Grok version must remain unknown: %+v", byID[id])
		}
	}
}

func addTestProductLifecycleEvidence(t *testing.T, startup *StartupSyncResult, sourceID, modelID, status, effectiveAt string, now time.Time) {
	t.Helper()
	spec, ok := sourceForID(sourceID)
	if !ok {
		t.Fatalf("test source %q was not found", sourceID)
	}
	for i := range startup.Providers {
		result := &startup.Providers[i]
		if result.SourceID != sourceID || result.Snapshot == nil || len(result.Snapshot.Pages) == 0 {
			continue
		}
		snapshot := *result.Snapshot
		page := snapshot.Pages[0]
		evidence := LifecycleEvidence{
			SourceID: sourceID, Provider: spec.provider, Scope: spec.scope, ModelID: modelID, Status: status,
			EffectiveAt: effectiveAt, SourceURL: page.URL, SourceTitle: page.Title, RetrievedAt: now,
			ContentSHA256: page.ContentSHA256, Excerpt: "synthetic test source-surface evidence",
		}
		page.Evidence = append(page.Evidence, evidence)
		snapshot.Pages[0] = page
		snapshot.Evidence = append(snapshot.Evidence, evidence)
		result.Snapshot = &snapshot
		return
	}
	t.Fatalf("test startup did not include source %q", sourceID)
}

func makeProductScopeResult(t *testing.T, scope string, fetchedAt time.Time, omitLast bool, includeNearRetirement bool) StartupSyncResult {
	t.Helper()
	var result StartupSyncResult
	for _, spec := range sourceManifest {
		if spec.scope != scope {
			continue
		}
		if omitLast && spec.id == "openai-cross-product-lifecycle-v2" {
			continue
		}
		body := fixture(t, map[string]string{
			"openai-codex-models":               "openai-codex-models.html",
			"openai-cross-product-lifecycle-v2": "openai-cross-product-lifecycle.html",
			"openai-chatgpt-models":             "openai-chatgpt-models.html",
			"openai-chatgpt-gpt6-announcement":  "openai-gpt6-for-everyone.html",
			"anthropic-claude-code-models":      "anthropic-claude-code-models.html",
			"anthropic-claude-web-models":       "anthropic-claude-web-models.html",
			"anthropic-claude-release-notes":    "anthropic-claude-release-notes.html",
			"kimi-code-models":                  "kimi-code-models.html",
			"kimi-web-models":                   "kimi-web-models.html",
			"kimi-code-whats-new":               "kimi-code-whats-new.html",
			"xai-grok-web-models":               "xai-grok-4-5-everywhere.html",
		}[spec.id])
		if includeNearRetirement && spec.id == "openai-cross-product-lifecycle-v2" {
			// Boundary dates are added as normalized evidence below.
		}
		parsed, err := parseSourcePage(spec, spec.rootURL, body, fetchedAt)
		if err != nil {
			t.Fatal(err)
		}
		page := CachedPage{URL: spec.rootURL, Title: parsed.Title, ContentSHA256: sha256Hex(body), FetchedAt: fetchedAt, Evidence: parsed.Evidence, AvailableModelIDs: parsed.AvailableModelIDs}
		snapshot := CatalogSnapshot{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Pages: []CachedPage{page}, Evidence: parsed.Evidence, FetchedAt: fetchedAt, CheckedAt: fetchedAt, Complete: true}
		snapshot.ContentSHA256, err = snapshotDigest(snapshot.Pages)
		if err != nil {
			t.Fatal(err)
		}
		result.Providers = append(result.Providers, ProviderSync{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Status: "updated", Snapshot: &snapshot})
	}
	if includeNearRetirement {
		addTestProductLifecycleEvidence(t, &result, "openai-cross-product-lifecycle-v2", "gpt-near-sixty-test", "announced_deprecated", "2026-12-13", fetchedAt)
		addTestProductLifecycleEvidence(t, &result, "openai-cross-product-lifecycle-v2", "gpt-near-sixty-one-test", "announced_deprecated", "2026-12-14", fetchedAt)
		addTestProductLifecycleEvidence(t, &result, "openai-cross-product-lifecycle-v2", "gpt-retired-today-test", "retired", "2026-10-14", fetchedAt)
		addTestProductLifecycleEvidence(t, &result, "openai-cross-product-lifecycle-v2", "gpt-retired-past-test", "retired", "2026-09-14", fetchedAt)
	}
	return result
}

func TestXAIReplacementTargetsAreNotLifecycleSubjects(t *testing.T) {
	parsed, err := parseSourcePage(
		specFor(t, "xai"),
		"https://docs.x.ai/developers/migration/retirement-targets-test",
		fixture(t, "xai-replacement-targets.html"),
		time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string][]LifecycleEvidence)
	for _, evidence := range parsed.Evidence {
		byID[evidence.ModelID] = append(byID[evidence.ModelID], evidence)
	}
	for _, target := range []string{"grok-4.3", "grok-imagine-image-2.0"} {
		if len(byID[target]) != 0 {
			t.Errorf("replacement target %q was mislabeled as lifecycle evidence: %+v", target, byID[target])
		}
	}
	for _, source := range []string{"grok-4-1-fast-non-reasoning", "grok-imagine-image-quality"} {
		if len(byID[source]) != 1 {
			t.Fatalf("expected one lifecycle record for source %q, got %+v", source, byID[source])
		}
	}
	if got := byID["grok-4-1-fast-non-reasoning"][0].Status; got != "retired_with_compatibility_route" {
		t.Errorf("past retirement with active redirect should retain compatibility-route status, got %q", got)
	}
	if got := byID["grok-imagine-image-quality"][0].Status; got != "announced_deprecated" {
		t.Errorf("future retirement must remain announced, not retired; got %q", got)
	}
	if len(byID["grok-imagine-image-quality"]) == 0 {
		t.Fatal("chained source model was lost while filtering its appearance as another model's target")
	}
}

func TestCachedXAIPricingMentionsDoNotClassifyReplacementTargets(t *testing.T) {
	when := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	targets := []string{"grok-4.3", "grok-imagine-image-2.0"}
	evidence := []LifecycleEvidence{
		{Provider: "xai", ModelID: targets[0], Status: "announced_deprecated", EffectiveAt: "May 15", SourceURL: "https://docs.x.ai/developers/migration/may-15-retirement", SourceTitle: "Grok Model Retirement", RetrievedAt: when, ContentSHA256: "a", Excerpt: "Pricing impact If you continue sending requests to a deprecated slug, you will be billed at grok-4.3 pricing."},
		{Provider: "xai", ModelID: targets[1], Status: "announced_deprecated", EffectiveAt: "November 2", SourceURL: "https://docs.x.ai/developers/migration/imagine-image-quality-nov-2", SourceTitle: "Image Quality Retirement", RetrievedAt: when, ContentSHA256: "b", Excerpt: "If you keep sending requests to the retired slug after November 2, you are billed at grok-imagine-image-2.0 low rate."},
		{Provider: "xai", ModelID: "grok-4-1-fast-non-reasoning", Status: "retired_with_compatibility_route", EffectiveAt: "2026-05-15", Replacement: targets[0], SourceURL: "https://docs.x.ai/developers/migration/may-15-retirement", SourceTitle: "Grok Model Retirement", RetrievedAt: when, ContentSHA256: "c", Excerpt: "grok-4-1-fast-non-reasoning is retired; requests are redirected to grok-4.3."},
	}
	observations := make([]InputModel, 0, len(targets)+1)
	for _, model := range append(targets, "grok-4-1-fast-non-reasoning") {
		observations = append(observations, InputModel{AccountID: 28, ModelID: model, ObservedAs: "upstream_id"})
	}
	matched := matchObservations(observations, []CatalogSnapshot{{Provider: "xai", Complete: true, Evidence: evidence}})
	if len(matched) != 3 {
		t.Fatalf("unexpected observation count: %+v", matched)
	}
	for i, model := range targets {
		if matched[i].ModelID != model || matched[i].Status != "unknown/no_official_notice_found" || len(matched[i].Matches) != 0 {
			t.Errorf("replacement target inherited lifecycle evidence from pricing text: %+v", matched[i])
		}
	}
	if matched[2].Status != "retired_with_compatibility_route" || len(matched[2].Matches) != 1 {
		t.Fatalf("actual retired source was discarded with replacement targets: %+v", matched[2])
	}
}

func TestXAILifecycleSubjectsUseExplicitListOrDirectRetirementGrammar(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []string
	}{
		{text: "The following models will be retired from the API: grok-old-a and grok-old-b.", want: []string{"grok-old-a", "grok-old-b"}},
		{text: "Retirement of grok-old-c is scheduled.", want: []string{"grok-old-c"}},
		{text: "Requests to a deprecated slug are billed at grok-new-target pricing.", want: nil},
	} {
		got := xaiLifecycleSubjects(tc.text)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("xAI lifecycle subject parsing mismatch for %q: got=%v want=%v", tc.text, got, tc.want)
		}
	}
}

func TestOpenAIParserOnlyReadsAPIDeprecationTable(t *testing.T) {
	spec := specFor(t, "openai")
	parsed, err := parseSourcePage(spec, spec.rootURL, fixture(t, "openai-deprecations-with-product-table.html"), time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool)
	for _, evidence := range parsed.Evidence {
		got[evidence.ModelID] = true
	}
	if !got["gpt-api-retiring-test"] {
		t.Fatalf("API deprecation row was not parsed: %+v", parsed.Evidence)
	}
	for _, id := range []string{"gpt-chatgpt-only-test", "gpt-chatgpt-successor-test"} {
		if got[id] {
			t.Fatalf("unrelated ChatGPT product table leaked into API lifecycle evidence: %q (%+v)", id, parsed.Evidence)
		}
	}
}

func TestAnthropicAndXAIKeepConflictingExactIDEvidence(t *testing.T) {
	now := time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		provider string
		url      string
		fixture  string
		model    string
		replace  string
	}{
		{provider: "anthropic", url: specFor(t, "anthropic").rootURL, fixture: "anthropic-deprecations.html", model: "claude-conflict-test", replace: "claude-replacement-test"},
		{provider: "xai", url: specFor(t, "xai").rootURL, fixture: "xai-release-notes.html", model: "grok-conflict-test", replace: "grok-replacement-b-test"},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			parsed, err := parseSourcePage(specFor(t, tc.provider), tc.url, fixture(t, tc.fixture), now)
			if err != nil {
				t.Fatal(err)
			}
			var records []LifecycleEvidence
			foundReplacement := false
			for _, evidence := range parsed.Evidence {
				if evidence.ModelID == tc.model {
					records = append(records, evidence)
					foundReplacement = foundReplacement || evidence.Replacement == tc.replace
				}
			}
			if len(records) < 2 || !foundReplacement {
				t.Fatalf("conflicting exact-ID evidence was overwritten: records=%+v", records)
			}
			inv := Inventory{Mode: "inspect", Digest: "digest", Observations: []InputModel{{AccountID: 7, ModelID: tc.model, ObservedAs: "upstream_id"}}}
			snapshot := CatalogSnapshot{Provider: tc.provider, Complete: true, Evidence: parsed.Evidence}
			matched := matchObservations(inv.Observations, []CatalogSnapshot{snapshot})
			if len(matched) != 1 || matched[0].Status != "conflicting_official_lifecycle_evidence" {
				t.Fatalf("same-provider conflicts did not reach downstream conflict marker: %+v", matched)
			}
			for _, reference := range matched[0].Matches {
				if reference.Provider != tc.provider || !reference.Conflict {
					t.Fatalf("unexpected conflict reference: %+v", reference)
				}
			}
		})
	}
}

func TestParsersFailClosedOnMissingAnchorsAndUnknownIsNotActive(t *testing.T) {
	for _, spec := range sourceManifest {
		if _, err := parseSourcePage(spec, spec.rootURL, []byte("<html><title>Some unrelated page</title><body>gpt-test</body></html>"), time.Now()); err == nil {
			t.Errorf("%s parser accepted unrelated HTML", spec.provider)
		}
	}
	inventory := Inventory{Mode: "inspect", Digest: "test-digest", Observations: []InputModel{{AccountID: 4, ModelID: "not-mentioned-model", ObservedAs: "upstream_id"}}}
	report, err := BuildReviewFromStartup(inventory, StartupSyncResult{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if got := report.Observations[0].Status; got != "unknown/no_official_notice_found" {
		t.Fatalf("no notice became %q", got)
	}
	if strings.Contains(strings.ToLower(report.Observations[0].Status), "active") {
		t.Fatal("absence of notice must never imply active")
	}
}

func TestExactMatchAndProviderScopedConflict(t *testing.T) {
	when := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	inv := Inventory{Mode: "inspect", Digest: "digest", Observations: []InputModel{{AccountID: 1, ModelID: "model-x", ObservedAs: "upstream_id"}, {AccountID: 1, ModelID: "Model-x", ObservedAs: "public_id"}}}
	openai := CatalogSnapshot{Provider: "openai", Complete: true, Evidence: []LifecycleEvidence{{Provider: "openai", ModelID: "model-x", Status: "retired", SourceURL: sourceManifest[0].rootURL, SourceTitle: "Deprecations", RetrievedAt: when, ContentSHA256: "a", Excerpt: "retired"}, {Provider: "openai", ModelID: "model-x", Status: "legacy", SourceURL: sourceManifest[0].rootURL, SourceTitle: "Deprecations", RetrievedAt: when, ContentSHA256: "b", Excerpt: "legacy"}}}
	deepseek := CatalogSnapshot{Provider: "deepseek", Complete: true, Evidence: []LifecycleEvidence{{Provider: "deepseek", ModelID: "model-x", Status: "legacy", SourceURL: sourceManifest[2].rootURL, SourceTitle: "Change Log", RetrievedAt: when, ContentSHA256: "c", Excerpt: "legacy"}}}
	observations := matchObservations(inv.Observations, []CatalogSnapshot{openai, deepseek})
	if observations[0].Status != "conflicting_official_lifecycle_evidence" || len(observations[0].Matches) != 3 {
		t.Fatalf("same-provider conflicting evidence was not retained: %+v", observations[0])
	}
	for _, ref := range observations[0].Matches {
		if ref.Provider == "deepseek" && ref.Conflict {
			t.Fatal("same ID from another provider must not create a conflict")
		}
	}
	if observations[1].Status != "unknown/no_official_notice_found" {
		t.Fatalf("match was not exact/case-sensitive: %+v", observations[1])
	}
}

func TestLifecycleMetadataDifferencesDoNotCreateStatusConflict(t *testing.T) {
	when := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	model := "claude-metadata-only-test"
	snapshot := CatalogSnapshot{Provider: "anthropic", Complete: true, Evidence: []LifecycleEvidence{
		{Provider: "anthropic", ModelID: model, Status: "announced_deprecated", AnnouncedAt: "2026-01-01", EffectiveAt: "2026-11-01", Replacement: "claude-replacement-a", SourceURL: sourceManifest[1].rootURL, SourceTitle: "Model deprecations", RetrievedAt: when, ContentSHA256: "a", Excerpt: "current state row"},
		{Provider: "anthropic", ModelID: model, Status: "announced_deprecated", AnnouncedAt: "2026-01-01", EffectiveAt: "2026-12-01", Replacement: "claude-replacement-b", SourceURL: sourceManifest[1].rootURL, SourceTitle: "Model deprecations", RetrievedAt: when, ContentSHA256: "b", Excerpt: "history row"},
	}}
	matched := matchObservations([]InputModel{{AccountID: 7, ModelID: model, ObservedAs: "upstream_id"}}, []CatalogSnapshot{snapshot})
	if len(matched) != 1 || matched[0].Status != "announced_deprecated" || len(matched[0].Matches) != 2 {
		t.Fatalf("metadata-only differences changed lifecycle status: %+v", matched)
	}
	for _, reference := range matched[0].Matches {
		if reference.Conflict {
			t.Fatalf("metadata-only reference was flagged as a lifecycle conflict: %+v", reference)
		}
	}
	if matched[0].Matches[0].Replacement == matched[0].Matches[1].Replacement {
		t.Fatalf("distinct recommendations were not retained for manual context: %+v", matched[0].Matches)
	}
}

type fakeDoer struct {
	mu                sync.Mutex
	handler           func(*http.Request) (*http.Response, error)
	requests          []*http.Request
	active, maxActive int
	delay             time.Duration
}

func (d *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.requests = append(d.requests, req.Clone(req.Context()))
	d.active++
	if d.active > d.maxActive {
		d.maxActive = d.active
	}
	d.mu.Unlock()
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	resp, err := d.handler(req)
	d.mu.Lock()
	d.active--
	d.mu.Unlock()
	return resp, err
}

func htmlResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}, "ETag": []string{"etag-test"}, "Last-Modified": []string{"Mon, 12 Oct 2026 00:00:00 GMT"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func jsonResponse(status int, body string) *http.Response {
	resp := htmlResponse(status, body)
	resp.Header.Set("Content-Type", "application/json; charset=utf-8")
	return resp
}

func fixtureRouter(t *testing.T, fail bool) *fakeDoer {
	return fixtureRouterWithOverrides(t, fail, nil)
}

func fixtureRouterWithOverrides(t *testing.T, fail bool, overrides map[string]string) *fakeDoer {
	t.Helper()
	bodies := map[string]string{
		"developers.openai.com/api/docs/deprecations":                                                 string(fixture(t, "openai-deprecations.html")),
		"platform.claude.com/docs/en/about-claude/model-deprecations":                                 string(fixture(t, "anthropic-deprecations.html")),
		"api-docs.deepseek.com/updates/":                                                              string(fixture(t, "deepseek-updates.html")),
		"help.aliyun.com/zh/model-studio/model-depreciation":                                          string(fixture(t, "alibaba-depreciation.html")),
		"t.aliyun.com/abs/bulletin/bulletinDetail":                                                    string(fixture(t, "alibaba-bulletin-response.json")),
		"docs.x.ai/developers/release-notes":                                                          string(fixture(t, "xai-release-notes.html")),
		"docs.x.ai/developers/migration/retirement-test":                                              string(fixture(t, "xai-migration.html")),
		"x.ai/news/grok-4-7":                                                                          string(fixture(t, "xai-grok-4-7-wrong-surface.html")),
		"x.ai/news/grok-4-6-on-api":                                                                   string(fixture(t, "xai-grok-4-7-wrong-surface.html")),
		"x.ai/news/grok-4-5-everywhere":                                                               string(fixture(t, "xai-grok-4-5-everywhere.html")),
		"openai.com/index/gpt-6-for-everyone/":                                                        string(fixture(t, "openai-gpt6-for-everyone.html")),
		"developers.openai.com/codex/models":                                                          string(fixture(t, "openai-codex-models.html")),
		"help.openai.com/en/articles/20001354-gpt-6-and-other-models-in-chatgpt":                      string(fixture(t, "openai-chatgpt-models.html")),
		"learn.chatgpt.com/docs/changelog":                                                            string(fixture(t, "openai-cross-product-lifecycle.html")),
		"support.claude.com/en/articles/12138966-release-notes":                                       string(fixture(t, "anthropic-claude-release-notes.html")),
		"support.claude.com/en/articles/11940350-claude-code-model-configuration":                     string(fixture(t, "anthropic-claude-code-models.html")),
		"support.claude.com/en/articles/8606394-how-large-is-the-context-window-on-paid-claude-plans": string(fixture(t, "anthropic-claude-web-models.html")),
		"www.kimi.com/en/help/kimi-code/models":                                                       string(fixture(t, "kimi-code-models.html")),
		"www.kimi.com/en/help/new-user-guide/agentic-chat":                                            string(fixture(t, "kimi-web-models.html")),
		"www.kimi.com/code/docs/en/kimi-code/whats-new.html":                                          string(fixture(t, "kimi-code-whats-new.html")),
	}
	for key, body := range overrides {
		bodies[key] = body
	}
	return &fakeDoer{delay: 5 * time.Millisecond, handler: func(req *http.Request) (*http.Response, error) {
		if fail {
			return htmlResponse(http.StatusServiceUnavailable, "unavailable"), nil
		}
		body, ok := bodies[req.URL.Host+req.URL.Path]
		if !ok {
			return nil, &url.Error{Op: "GET", URL: req.URL.String(), Err: os.ErrNotExist}
		}
		if req.URL.Host == "t.aliyun.com" && req.URL.RawQuery != "id=123456&language=zh&website=cn" {
			return htmlResponse(http.StatusBadRequest, "unexpected renderer query"), nil
		}
		if req.URL.Host == "t.aliyun.com" {
			return jsonResponse(http.StatusOK, body), nil
		}
		return htmlResponse(http.StatusOK, body), nil
	}}
}

func TestValidZeroEventOfficialPagesUpdateCompleteSnapshotsAndRemainUnknown(t *testing.T) {
	tests := []struct {
		provider string
		fixture  string
		key      string
		model    string
	}{
		{"openai", "openai-deprecations-zero-events.html", "developers.openai.com/api/docs/deprecations", "gpt-retiring-test"},
		{"anthropic", "anthropic-deprecations-zero-events.html", "platform.claude.com/docs/en/about-claude/model-deprecations", "claude-retiring-test"},
		{"deepseek", "deepseek-updates-zero-events.html", "api-docs.deepseek.com/updates/", "deepseek-old-test"},
		{"alibaba", "alibaba-bulletin-zero-events.json", "t.aliyun.com/abs/bulletin/bulletinDetail", "qwen-old-test"},
		{"xai", "xai-release-notes-zero-events.html", "docs.x.ai/developers/release-notes", "grok-retiring-test"},
	}
	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			spec := specFor(t, tc.provider)
			cache := filepath.Join(t.TempDir(), "cache")
			now := time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC)
			first := SyncStartup(context.Background(), StartupSyncOptions{CacheDir: cache, NewDoer: func() HTTPDoer { return fixtureRouter(t, false) }, Now: func() time.Time { return now }})
			var old ProviderSync
			for _, provider := range first.Providers {
				if provider.SourceID == spec.id {
					old = provider
				}
			}
			if old.Status != "updated" || old.EvidenceCount == 0 || old.Snapshot == nil {
				t.Fatalf("initial lifecycle snapshot missing for replacement test: %+v", old)
			}
			oldHash := old.Snapshot.ContentSHA256
			body := string(fixture(t, tc.fixture))
			second := SyncStartup(context.Background(), StartupSyncOptions{
				CacheDir: cache,
				NewDoer:  func() HTTPDoer { return fixtureRouterWithOverrides(t, false, map[string]string{tc.key: body}) },
				Now:      func() time.Time { return now.Add(time.Hour) },
			})
			var current ProviderSync
			for _, provider := range second.Providers {
				if provider.SourceID == spec.id {
					current = provider
				}
			}
			if current.Status != "updated" || current.ErrorCode != "" || current.EvidenceCount != 0 || !current.CachePersisted || current.Snapshot == nil || !current.Snapshot.Complete || len(current.Snapshot.Evidence) != 0 || current.Snapshot.ContentSHA256 == oldHash {
				t.Fatalf("valid zero-event source did not replace last-good with complete empty snapshot: %+v", current)
			}
			cached, err := readSourceSnapshot(cache, spec)
			if err != nil || !cached.Complete || len(cached.Evidence) != 0 || cached.ContentSHA256 != current.Snapshot.ContentSHA256 {
				t.Fatalf("complete zero-evidence snapshot was not persisted: snapshot=%+v err=%v", cached, err)
			}
			inventory := Inventory{Mode: "inspect", Digest: "zero-event-test-digest", Observations: []InputModel{{AccountID: 1, ModelID: tc.model, ObservedAs: "upstream_id"}}}
			report, err := BuildReviewFromStartup(inventory, second, func() time.Time { return now.Add(2 * time.Hour) })
			if err != nil || report.Observations[0].Status != "unknown/no_official_notice_found" || len(report.Observations[0].Matches) != 0 {
				t.Fatalf("model absent from a successful zero-event source must remain unknown: report=%+v err=%v", report.Observations, err)
			}
		})
	}
	for _, tc := range []struct {
		provider string
		fixture  string
		url      string
		anchor   string
	}{
		{"openai", "openai-deprecations-zero-events.html", specFor(t, "openai").rootURL, "Recommended replacement"},
		{"anthropic", "anthropic-deprecations-zero-events.html", specFor(t, "anthropic").rootURL, "Tentative retirement date"},
		{"xai", "xai-release-notes-zero-events.html", specFor(t, "xai").rootURL, "October"},
	} {
		t.Run("missing_structure_"+tc.provider, func(t *testing.T) {
			body := string(fixture(t, tc.fixture))
			if tc.provider == "xai" {
				body = strings.ReplaceAll(body, tc.anchor, "unexpected heading")
			} else {
				body = strings.Replace(body, tc.anchor, "unexpected heading", 1)
			}
			if _, err := parseSourcePage(specFor(t, tc.provider), tc.url, []byte(body), time.Now()); err == nil {
				t.Fatal("zero-event content with a missing required structure anchor was accepted")
			}
		})
	}
	xaiSpec := specFor(t, "xai")
	xaiMigration, err := parseSourcePage(xaiSpec, "https://docs.x.ai/developers/migration/retirement-test", fixture(t, "xai-migration-zero-events.html"), time.Now())
	if err != nil || len(xaiMigration.Evidence) != 0 {
		t.Fatalf("valid xAI migration page with no event must parse successfully and yield no evidence: %+v err=%v", xaiMigration, err)
	}
	invalidMigration := strings.Replace(string(fixture(t, "xai-migration-zero-events.html")), "Migration guide", "General documentation", 1)
	if _, err := parseSourcePage(xaiSpec, "https://docs.x.ai/developers/migration/retirement-test", []byte(invalidMigration), time.Now()); err == nil {
		t.Fatal("xAI migration page without its required heading was accepted")
	}
}

func TestStartupFixedPublicSourcesAndOptionalAccountCatalogCredentials(t *testing.T) {
	doer := fixtureRouter(t, false)
	envCalls, clientCalls := 0, 0
	var envMu sync.Mutex
	envNames := make([]string, 0, 4)
	result := SyncStartup(context.Background(), StartupSyncOptions{
		CacheDir: filepath.Join(t.TempDir(), "cache"),
		LookupEnv: func(name string) (string, bool) {
			if name != "VOLCENGINE_ARK_CREDENTIAL_FILE" && name != "DASHSCOPE_API_KEY" && name != "DASHSCOPE_API_KEY_FILE" && name != "CREDENTIALS_DIRECTORY" {
				t.Fatalf("unexpected environment variable lookup: %s", name)
			}
			envMu.Lock()
			envCalls++
			envNames = append(envNames, name)
			envMu.Unlock()
			return "", false
		},
		NewDoer: func() HTTPDoer { clientCalls++; return doer },
		Now:     time.Now,
	})
	seenEnv := map[string]int{}
	for _, name := range envNames {
		seenEnv[name]++
	}
	if envCalls != 4 || seenEnv["DASHSCOPE_API_KEY"] != 1 || seenEnv["DASHSCOPE_API_KEY_FILE"] != 1 || seenEnv["CREDENTIALS_DIRECTORY"] != 1 || seenEnv["VOLCENGINE_ARK_CREDENTIAL_FILE"] != 1 {
		t.Fatalf("optional account-catalog credential lookups=%d names=%v", envCalls, envNames)
	}
	if clientCalls != 1 {
		t.Fatalf("HTTP client constructions=%d want 1", clientCalls)
	}
	if len(result.Providers) != 18 {
		t.Fatalf("sources=%d want 18", len(result.Providers))
	}
	doer.mu.Lock()
	requests, max := append([]*http.Request(nil), doer.requests...), doer.maxActive
	doer.mu.Unlock()
	if len(requests) != 18 {
		t.Fatalf("public GET count=%d want 18 after excluding the non-probative Grok overview)", len(requests))
	}
	if max > 4 {
		t.Fatalf("concurrent requests=%d exceeds 4", max)
	}
	for _, req := range requests {
		for _, header := range []string{"Authorization", "X-Api-Key", "Cookie", "Proxy-Authorization"} {
			if req.Header.Get(header) != "" {
				t.Fatalf("anonymous request sent %s", header)
			}
		}
		if validateRequestAllowlist(req.URL.String()) != nil {
			t.Fatalf("request escaped source allowlist: %s", req.URL)
		}
		if req.URL.Host == "t.aliyun.com" {
			if req.Header.Get("Origin") != "https://www.aliyun.com" || req.Header.Get("Accept") != "application/json" {
				t.Fatalf("Alibaba renderer request headers mismatch: Origin=%q Accept=%q", req.Header.Get("Origin"), req.Header.Get("Accept"))
			}
		} else if req.Header.Get("Origin") != "" {
			t.Fatalf("Origin header was added to non-Alibaba source %s", req.URL.Host)
		}
	}
	for _, item := range result.Providers {
		if item.SourceID == "volcengine-ark-account-models" || item.SourceID == "alibaba-model-studio-models" {
			if item.Status != "unavailable" || item.ErrorCode != "credential_not_configured" {
				t.Errorf("unconfigured Ark source unexpectedly made a request: %+v", item)
			}
			continue
		}
		if item.Status != "updated" || item.Snapshot == nil {
			t.Errorf("%s startup result: %+v", item.Provider, item)
		}
	}
	if got := result.Providers[3].EvidenceCount; got != 4 {
		t.Fatalf("Alibaba notice evidence=%d", got)
	}
}

func TestAlibabaRendererUsesAnonymousOriginRequest(t *testing.T) {
	var requestCount int
	doer := &fakeDoer{handler: func(req *http.Request) (*http.Response, error) {
		requestCount++
		if req.Host != "t.aliyun.com" || req.URL.Path != "/abs/bulletin/bulletinDetail" || req.URL.RawQuery != "id=123456&language=zh&website=cn" {
			t.Fatalf("unexpected rendered bulletin request: Host=%q URL=%s", req.Host, req.URL)
		}
		if req.Header.Get("Origin") != "https://www.aliyun.com" || req.Header.Get("Accept") != "application/json" {
			t.Fatalf("required renderer headers missing: Origin=%q Accept=%q", req.Header.Get("Origin"), req.Header.Get("Accept"))
		}
		for _, header := range []string{"Authorization", "X-Api-Key", "Cookie", "Proxy-Authorization"} {
			if req.Header.Get(header) != "" {
				t.Fatalf("anonymous renderer request sent %s", header)
			}
		}
		return jsonResponse(http.StatusOK, string(fixture(t, "alibaba-bulletin-response.json"))), nil
	}}
	page, err := fetchAndParsePage(context.Background(), specFor(t, "alibaba"), alibabaBulletinURL("123456"), CachedPage{}, false, doer, &requestBudget{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if requestCount != 1 || page.Title != "百炼模型下线通知" || len(page.Evidence) != 4 {
		t.Fatalf("renderer fixture did not produce exact lifecycle evidence: requests=%d page=%+v", requestCount, page)
	}
	models := make(map[string]bool)
	for _, evidence := range page.Evidence {
		models[evidence.ModelID] = true
	}
	if !models["qwen-old-test"] || !models["gte-rerank"] || !models["qwen-list-old-a"] || !models["qwen-list-old-b"] || models["qwen-new-test"] || models["qwen-list-successor"] {
		t.Fatalf("renderer fixture evidence contains missing old models or a replacement: %+v", page.Evidence)
	}
}

func TestFetchPreservesHTTPStatusCodeInFailure(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			spec := specFor(t, "openai")
			doer := &fakeDoer{handler: func(*http.Request) (*http.Response, error) {
				return jsonResponse(status, "blocked"), nil
			}}
			_, err := fetchAndParsePage(context.Background(), spec, spec.rootURL, CachedPage{}, false, doer, &requestBudget{}, time.Now)
			want := fmt.Sprintf("http_status_%d", status)
			if got := failureCode(err); got != want {
				t.Fatalf("failure code=%q, want %q", got, want)
			}
		})
	}
}

func TestAlibabaRendererBusinessAndSchemaFailuresRetainLastGood(t *testing.T) {
	spec := specFor(t, "alibaba")
	url := alibabaBulletinURL("123456")
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	body := fixture(t, "alibaba-bulletin-response.json")
	parsed, err := parseSourcePage(spec, url, body, now)
	if err != nil {
		t.Fatal(err)
	}
	prior := CachedPage{URL: url, Title: parsed.Title, ContentSHA256: sha256Hex(body), FetchedAt: now, Evidence: parsed.Evidence}
	snapshot := CatalogSnapshot{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Pages: []CachedPage{prior}, Evidence: parsed.Evidence, FetchedAt: now, CheckedAt: now, Complete: true}
	snapshot.ContentSHA256, err = snapshotDigest(snapshot.Pages)
	if err != nil || validateSnapshot(spec, snapshot) != nil {
		t.Fatalf("last-good renderer snapshot fixture invalid: %v", err)
	}
	failedBodies := []string{
		`{"data":{"success":false,"info":{"title":"残留标题","detailList":[{"contentHtml":"<table><tr><td>qwen-false-test</td><td>2099-02-03</td><td>该模型将下线</td></tr></table>"}]}}`,
		`{"data":{"success":true,"info":{"title":" ","detailList":[{"contentHtml":"<p>residual</p>"}]}}`,
		`{"data":{"success":true,"info":{"title":"标题","detailList":[]}}}`,
		`{"data":{"success":true,"info":{"title":"标题","detailList":[{"contentHtml":"  "}]}}}`,
		`{"data":{"success":true,"info":{"title":"标题","detailList":[{"contentHtml":"<p>residual"}]}} trailing`,
	}
	for index, failedBody := range failedBodies {
		doer := &fakeDoer{handler: func(*http.Request) (*http.Response, error) { return jsonResponse(http.StatusOK, failedBody), nil }}
		_, fetchErr := fetchAndParsePage(context.Background(), spec, url, prior, true, doer, &requestBudget{}, func() time.Time { return now.Add(time.Minute) })
		if failureCode(fetchErr) != "source_parse_error" {
			t.Fatalf("case %d was not rejected as parser failure: %v", index, fetchErr)
		}
		result := statusFromError(spec, &snapshot, failureCode(fetchErr))
		if result.Status != "stale" || result.Snapshot == nil || result.Snapshot.ContentSHA256 != snapshot.ContentSHA256 || result.Snapshot.Pages[0].ContentSHA256 != prior.ContentSHA256 {
			t.Fatalf("case %d did not retain the exact last-good snapshot: %+v", index, result)
		}
	}
	cache := t.TempDir()
	first := SyncStartup(context.Background(), StartupSyncOptions{CacheDir: cache, NewDoer: func() HTTPDoer { return fixtureRouter(t, false) }, Now: func() time.Time { return now }})
	if first.Providers[3].Status != "updated" {
		t.Fatalf("initial Alibaba snapshot was not cached: %+v", first.Providers[3])
	}
	before, err := readSourceSnapshot(cache, spec)
	if err != nil {
		t.Fatal(err)
	}
	failedDoer := fixtureRouter(t, false)
	validHandler := failedDoer.handler
	failedDoer.handler = func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "t.aliyun.com" {
			return jsonResponse(http.StatusOK, failedBodies[0]), nil
		}
		return validHandler(req)
	}
	second := SyncStartup(context.Background(), StartupSyncOptions{CacheDir: cache, NewDoer: func() HTTPDoer { return failedDoer }, Now: func() time.Time { return now.Add(2 * time.Minute) }})
	if second.Providers[3].Status != "stale" || second.Providers[3].ErrorCode != "source_parse_error" {
		t.Fatalf("failed renderer response did not report stale parser error: %+v", second.Providers[3])
	}
	after, err := readSourceSnapshot(cache, spec)
	if err != nil || after.ContentSHA256 != before.ContentSHA256 || !after.CheckedAt.Equal(before.CheckedAt) {
		t.Fatalf("failed renderer response replaced cached last-good: before=%+v after=%+v err=%v", before, after, err)
	}
	redirectDoer := fixtureRouter(t, false)
	redirectHandler := redirectDoer.handler
	redirectDoer.handler = func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "t.aliyun.com" {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{alibabaBulletinURL("654321")}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return redirectHandler(req)
	}
	third := SyncStartup(context.Background(), StartupSyncOptions{CacheDir: cache, NewDoer: func() HTTPDoer { return redirectDoer }, Now: func() time.Time { return now.Add(3 * time.Minute) }})
	if third.Providers[3].Status != "stale" || third.Providers[3].ErrorCode != "redirect_rejected" || third.Providers[3].Snapshot == nil || third.Providers[3].Snapshot.ContentSHA256 != before.ContentSHA256 {
		t.Fatalf("cross-notice redirect did not retain stale last-good evidence: %+v", third.Providers[3])
	}
	afterRedirect, err := readSourceSnapshot(cache, spec)
	if err != nil || afterRedirect.ContentSHA256 != before.ContentSHA256 {
		t.Fatalf("cross-notice redirect overwrote the cached official notice snapshot: %+v err=%v", afterRedirect, err)
	}
	redirectDoer.mu.Lock()
	redirectRequests := append([]*http.Request(nil), redirectDoer.requests...)
	redirectDoer.mu.Unlock()
	for _, request := range redirectRequests {
		if request.URL.Host == "t.aliyun.com" && request.URL.RawQuery == "id=654321&language=zh&website=cn" {
			t.Fatalf("cross-notice redirect target was requested and could be misattributed: %s", request.URL)
		}
	}
}

func TestAlibabaProseLifecycleAnchorExtractsOnlyPrecedingModel(t *testing.T) {
	evidence := alibabaProseEvidence("将于 2099 年 3 月 4 日对 gte-rerank 模型进行下线处理。我们推荐替换为 qwen3-rerank。", "https://example.invalid", "test", time.Now(), "digest")
	if len(evidence) != 1 || evidence[0].ModelID != "gte-rerank" || evidence[0].EffectiveAt != "2099-03-04" {
		t.Fatalf("Alibaba prose lifecycle extraction mismatch: %+v", evidence)
	}
}

func TestCredentialedProxyRejectedBeforeClientOrRequest(t *testing.T) {
	proxy, err := url.Parse("http://user:secret@127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	clientCalls, envCalls, resolverCalls := 0, 0, 0
	result := SyncStartup(context.Background(), StartupSyncOptions{
		CacheDir:      filepath.Join(t.TempDir(), "cache"),
		LookupEnv:     func(string) (string, bool) { envCalls++; return "not-read", true },
		proxyResolver: func(*http.Request) (*url.URL, error) { resolverCalls++; return proxy, nil },
		NewDoer: func() HTTPDoer {
			clientCalls++
			return &fakeDoer{handler: func(*http.Request) (*http.Response, error) {
				t.Fatal("request sent despite credentialed proxy")
				return nil, nil
			}}
		},
	})
	if resolverCalls == 0 || clientCalls != 0 || envCalls != 0 {
		t.Fatalf("proxy credential preflight crossed the request/client boundary: resolver=%d clients=%d env=%d", resolverCalls, clientCalls, envCalls)
	}
	for _, provider := range result.Providers {
		if provider.Status != "unavailable" || provider.ErrorCode != "proxy_configuration_rejected" {
			t.Fatalf("credentialed proxy was not rejected: %+v", provider)
		}
	}
	if _, err := resolveAnonymousProxy(&http.Request{}, func(*http.Request) (*url.URL, error) { return proxy, nil }); err == nil {
		t.Fatal("proxy resolver accepted userinfo")
	}
}

func TestConfiguredProxyValidationCoversOnlyFixedSourceHosts(t *testing.T) {
	seen := map[string]bool{}
	if err := validateConfiguredProxy(func(req *http.Request) (*url.URL, error) {
		if req.Method != http.MethodGet || req.URL.Scheme != "https" || validateRequestAllowlist(req.URL.String()) != nil {
			t.Fatalf("proxy preflight escaped fixed official source set: %s %s", req.Method, req.URL)
		}
		seen[req.URL.Host] = true
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"developers.openai.com", "platform.claude.com", "api-docs.deepseek.com", "help.aliyun.com", "t.aliyun.com", "docs.x.ai", "learn.chatgpt.com", "support.claude.com", "www.kimi.com", "ark.cn-beijing.volcengineapi.com"} {
		if !seen[host] {
			t.Errorf("proxy preflight omitted fixed official host %s", host)
		}
	}
}

func validateRequestAllowlist(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	for _, spec := range sourceManifest {
		if validateSourceURL(spec, raw) == nil {
			return nil
		}
	}
	return errors.New("source request outside allowlist: " + u.Host + u.Path)
}

func TestRedirectAndChildURLAllowlistBudget(t *testing.T) {
	spec := specFor(t, "openai")
	for _, raw := range []string{
		"http://developers.openai.com/api/docs/deprecations",
		"https://user@developers.openai.com/api/docs/deprecations",
		"https://developers.openai.com:443/api/docs/deprecations",
		"https://developers.openai.com/api/docs/deprecations?x=1",
		"https://evil.example/api/docs/deprecations",
	} {
		if validateSourceURL(spec, raw) == nil {
			t.Errorf("unsafe source URL accepted: %s", raw)
		}
	}
	doer := &fakeDoer{handler: func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://evil.example/steal"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	budget := &requestBudget{}
	if _, err := fetchAndParsePage(context.Background(), spec, spec.rootURL, CachedPage{}, false, doer, budget, time.Now); failureCode(err) != "redirect_rejected" {
		t.Fatalf("cross-host redirect error=%v", err)
	}
	if budget.count() != 1 {
		t.Fatalf("rejected redirect must not issue target GET; count=%d want 1", budget.count())
	}

	redirects := &fakeDoer{handler: func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{req.URL.String()}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	budget = &requestBudget{}
	if _, err := fetchAndParsePage(context.Background(), spec, spec.rootURL, CachedPage{}, false, redirects, budget, time.Now); failureCode(err) != "redirect_limit_exceeded" {
		t.Fatalf("redirect limit error=%v", err)
	}
	if budget.count() != 3 {
		t.Fatalf("two-hop redirect should make initial+2 requests: %d", budget.count())
	}

	alibaba := specFor(t, "alibaba")
	links := make([]string, MaxAlibabaNotices+1)
	for i := range links {
		links[i] = "https://www.aliyun.com/notice/" + strconv.Itoa(1000+i)
	}
	if _, err := validateChildren(alibaba, alibaba.rootURL, links); failureCode(err) != "source_link_limit_exceeded" {
		t.Fatalf("Alibaba limit error=%v", err)
	}
	badLinks := []string{"https://evil.example/notice/123"}
	if _, err := validateChildren(alibaba, alibaba.rootURL, badLinks); failureCode(err) != "source_link_rejected" {
		t.Fatalf("unsafe candidate link error=%v", err)
	}
	for _, invalid := range []string{
		"https://www.aliyun.com/notice/not-a-number",
		"https://www.aliyun.com/notice/123456/extra",
		"https://www.aliyun.com/notice/?unexpected=1",
	} {
		if _, err := validateChildren(alibaba, alibaba.rootURL, []string{invalid}); failureCode(err) != "source_link_rejected" {
			t.Errorf("non-canonical Alibaba notice link was not rejected: %s err=%v", invalid, err)
		}
	}
	childURLs, err := validateChildren(alibaba, alibaba.rootURL, []string{"https://www.aliyun.com/notice/123456", "https://www.aliyun.com/notice/123456"})
	if err != nil || len(childURLs) != 1 || childURLs[0] != alibabaBulletinURL("123456") {
		t.Fatalf("official index links were not deduplicated and converted to the fixed renderer endpoint: urls=%v err=%v", childURLs, err)
	}
	childURLs, err = validateChildren(alibaba, alibaba.rootURL, []string{"https://www.aliyun.com/notice/", "https://www.aliyun.com/notice/123456"})
	if err != nil || len(childURLs) != 1 || childURLs[0] != alibabaBulletinURL("123456") {
		t.Fatalf("generic official notice index link was not ignored: urls=%v err=%v", childURLs, err)
	}
	for _, raw := range []string{
		"https://www.aliyun.com/notice/123456",
		"https://t.aliyun.com/abs/bulletin/bulletinDetail?id=123456&language=zh&website=cn&extra=x",
		"https://t.aliyun.com/abs/bulletin/bulletinDetail?id=123456&language=en&website=cn",
		"https://t.aliyun.com/abs/bulletin/bulletinDetail?id=123456&website=cn&language=zh",
		"https://t.aliyun.com/abs/bulletin/bulletinDetail?id=123456&language=zh&website=cn#fragment",
	} {
		if validateSourceURL(alibaba, raw) == nil {
			t.Errorf("Alibaba renderer accepted non-canonical URL: %s", raw)
		}
	}
	validRenderer := alibabaBulletinURL("123456")
	if err := validateSourceURL(alibaba, validRenderer); err != nil {
		t.Fatalf("canonical Alibaba renderer URL rejected: %v", err)
	}
	changedQueryRedirect := &fakeDoer{handler: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://t.aliyun.com/abs/bulletin/bulletinDetail?id=123456&language=zh&website=cn&extra=x"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	budget = &requestBudget{}
	if _, err := fetchAndParsePage(context.Background(), alibaba, validRenderer, CachedPage{}, false, changedQueryRedirect, budget, time.Now); failureCode(err) != "redirect_rejected" {
		t.Fatalf("renderer redirect that changed query was not rejected: %v", err)
	}
	if budget.count() != 1 {
		t.Fatalf("invalid renderer redirect issued a second request: %d", budget.count())
	}
	crossNoticeIDRedirect := &fakeDoer{handler: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{alibabaBulletinURL("654321")}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	budget = &requestBudget{}
	if _, err := fetchAndParsePage(context.Background(), alibaba, validRenderer, CachedPage{}, false, crossNoticeIDRedirect, budget, time.Now); failureCode(err) != "redirect_rejected" {
		t.Fatalf("renderer redirect changed official notice ID but was accepted: %v", err)
	}
	if budget.count() != 1 {
		t.Fatalf("cross-notice redirect issued a second GET: %d", budget.count())
	}
	xai := specFor(t, "xai")
	if err := validateSourceURL(xai, "https://docs.x.ai/developers/migration/Valid-Case"); err == nil {
		t.Fatal("uppercase migration slug accepted")
	}
	if err := validateSourceURL(xai, "https://docs.x.ai/developers/migration/valid-case?token=x"); err == nil {
		t.Fatal("migration query accepted")
	}
	budget = &requestBudget{}
	for i := 0; i < MaxHTTPGets; i++ {
		if !budget.reserve() {
			t.Fatalf("budget stopped early at %d", i)
		}
	}
	if budget.reserve() {
		t.Fatal("GET budget exceeded")
	}
}

func TestGlobal102GETLimitHoldsAcrossManifestRootsAndMaximumGrokChildren(t *testing.T) {
	logicalURLs := make([]string, 0, 10+MaxAlibabaNotices+MaxXAIMigrations)
	for _, provider := range []string{"openai", "anthropic", "deepseek"} {
		logicalURLs = append(logicalURLs, specFor(t, provider).rootURL)
	}
	for _, provider := range []string{"alibaba", "xai"} {
		spec := specFor(t, provider)
		logicalURLs = append(logicalURLs, spec.rootURL)
		childCount := spec.maxChildren
		links := make([]string, childCount)
		for i := range links {
			if provider == "alibaba" {
				links[i] = "https://www.aliyun.com/notice/" + strconv.Itoa(1000+i)
			} else {
				links[i] = "https://docs.x.ai/developers/migration/migration-" + strconv.Itoa(i)
			}
		}
		children, err := validateChildren(spec, spec.rootURL, links)
		if err != nil || len(children) != childCount {
			t.Fatalf("%s logical child URL set=%d err=%v", provider, len(children), err)
		}
		logicalURLs = append(logicalURLs, children...)
	}
	for _, sourceID := range []string{
		"openai-codex-models", "openai-chatgpt-models", "openai-chatgpt-gpt6-announcement", "openai-cross-product-lifecycle-v2",
		"anthropic-claude-code-models", "anthropic-claude-web-models", "anthropic-claude-release-notes",
		"kimi-code-models", "kimi-web-models", "kimi-code-whats-new", "xai-grok-web-models",
		"volcengine-ark-account-models", "alibaba-model-studio-models",
	} {
		logicalURLs = append(logicalURLs, specForID(t, sourceID).rootURL)
	}
	grokSpec := specForID(t, "xai-grok-web-models")
	grokLinks := make([]string, grokSpec.maxChildren)
	for i := range grokLinks {
		grokLinks[i] = "https://x.ai/news/grok-model-" + strconv.Itoa(i)
	}
	grokChildren, err := validateChildren(grokSpec, grokSpec.rootURL, grokLinks)
	if err != nil || len(grokChildren) != MaxXAIGrokNewsArticles {
		t.Fatalf("maximum Grok child URL set=%d err=%v", len(grokChildren), err)
	}
	logicalURLs = append(logicalURLs, grokChildren...)
	if len(logicalURLs) != 106 {
		t.Fatalf("representative logical document set=%d want 106", len(logicalURLs))
	}
	var requestCount int
	doer := &fakeDoer{handler: func(req *http.Request) (*http.Response, error) {
		requestCount++
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{req.URL.String()}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	budget := &requestBudget{}
	budgetExhausted := false
	for _, raw := range logicalURLs {
		var spec sourceSpec
		found := false
		for _, candidate := range sourceManifest {
			if validateSourceURL(candidate, raw) == nil {
				spec, found = candidate, true
				break
			}
		}
		if !found {
			t.Fatalf("logical URL is outside source manifest: %s", raw)
		}
		before := requestCount
		_, err := fetchAndParsePage(context.Background(), spec, raw, CachedPage{}, false, doer, budget, time.Now)
		code := failureCode(err)
		if code == "source_request_budget_exceeded" {
			budgetExhausted = true
			if requestCount != before {
				t.Fatalf("request after global budget was sent for %s", raw)
			}
		} else if code != "redirect_limit_exceeded" {
			t.Fatalf("redirect chain for %s had unexpected result: %v", raw, err)
		}
	}
	if !budgetExhausted || requestCount != MaxHTTPGets || budget.count() != MaxHTTPGets {
		t.Fatalf("worst-case requests=%d budget=%d want %d", requestCount, budget.count(), MaxHTTPGets)
	}
	if _, err := fetchAndParsePage(context.Background(), specFor(t, "openai"), specFor(t, "openai").rootURL, CachedPage{}, false, doer, budget, time.Now); failureCode(err) != "source_request_budget_exceeded" {
		t.Fatalf("request after global budget was not rejected: %v", err)
	}
	if requestCount != MaxHTTPGets {
		t.Fatalf("GET budget overflow sent request %d", requestCount)
	}
}

func TestFetchRejectsEmptyMalformedAndOversizedPagesAndRetainsLastGood(t *testing.T) {
	spec := specFor(t, "openai")
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	goodBody := fixture(t, "openai-deprecations.html")
	parsed, err := parseSourcePage(spec, spec.rootURL, goodBody, now)
	if err != nil {
		t.Fatal(err)
	}
	goodHash := sha256Hex(goodBody)
	page := CachedPage{URL: spec.rootURL, Title: parsed.Title, ContentSHA256: goodHash, FetchedAt: now, Links: parsed.Links, Evidence: parsed.Evidence}
	snapshot := CatalogSnapshot{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Pages: []CachedPage{page}, Evidence: parsed.Evidence, FetchedAt: now, CheckedAt: now, Complete: true}
	snapshot.ContentSHA256, err = snapshotDigest(snapshot.Pages)
	if err != nil || validateSnapshot(spec, snapshot) != nil {
		t.Fatalf("test last-good fixture invalid: %v", err)
	}
	priorHash := snapshot.ContentSHA256
	cases := []struct {
		name string
		body string
		want string
	}{
		{"empty", "", "response_too_large_or_empty"},
		{"malformed", "<html><title>Unrelated</title><p>partial body</p>", "source_parse_error"},
		{"oversized", strings.Repeat("x", int(spec.maxBody)+1), "response_too_large_or_empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doer := &fakeDoer{handler: func(*http.Request) (*http.Response, error) { return htmlResponse(http.StatusOK, tc.body), nil }}
			_, fetchErr := fetchAndParsePage(context.Background(), spec, spec.rootURL, page, true, doer, &requestBudget{}, func() time.Time { return now })
			if got := failureCode(fetchErr); got != tc.want {
				t.Fatalf("failure code=%q want %q err=%v", got, tc.want, fetchErr)
			}
			result := statusFromError(spec, &snapshot, failureCode(fetchErr))
			if result.Status != "stale" || result.Snapshot == nil || result.Snapshot.ContentSHA256 != priorHash {
				t.Fatalf("bad page did not retain last-good snapshot: %+v", result)
			}
		})
	}
	links := strings.Repeat(`<a href="/api/docs/deprecations">x</a>`, MaxParsedLinks+1)
	if _, err := parseSourcePage(spec, spec.rootURL, []byte(strings.Replace(string(goodBody), "</body>", links+"</body>", 1)), now); err == nil {
		t.Fatal("page with too many links was accepted")
	}
}

type liveSmokeDoer struct {
	inner    HTTPDoer
	mu       sync.Mutex
	requests []*http.Request
	results  []liveSmokeHTTPResult
}

type liveSmokeHTTPResult struct {
	URL            string
	StatusCode     int
	TransportError bool
}

func (d *liveSmokeDoer) Do(req *http.Request) (*http.Response, error) {
	resp, err := d.inner.Do(req)
	d.mu.Lock()
	d.requests = append(d.requests, req.Clone(req.Context()))
	result := liveSmokeHTTPResult{URL: req.URL.String(), TransportError: err != nil}
	if resp != nil {
		result.StatusCode = resp.StatusCode
	}
	d.results = append(d.results, result)
	d.mu.Unlock()
	return resp, err
}

func TestLiveSmokeOfficialLifecycleSources(t *testing.T) {
	if os.Getenv("OFFICIAL_LIFECYCLE_LIVE_SMOKE") != "1" {
		t.Skip("set OFFICIAL_LIFECYCLE_LIVE_SMOKE=1 to perform anonymous GET smoke against the five fixed public sources")
	}
	observed := &liveSmokeDoer{inner: NewHTTPClient()}
	result := SyncStartup(context.Background(), StartupSyncOptions{
		CacheDir: t.TempDir(), NewDoer: func() HTTPDoer { return observed }, Now: time.Now,
	})
	parsedCount, parseErrorCount, unavailableCount := 0, 0, 0
	for _, provider := range result.Providers {
		parserStatus := liveParserStatus(provider)
		catalogCount, catalogComplete := 0, false
		catalogIDs := make([]string, 0)
		if provider.Snapshot != nil {
			catalogComplete = provider.Snapshot.Complete
			for _, page := range provider.Snapshot.Pages {
				catalogCount += len(page.AvailableModelIDs)
				catalogIDs = append(catalogIDs, page.AvailableModelIDs...)
			}
		}
		t.Logf("public source id=%s provider=%s http=%s parser=%s status=%s evidence=%d catalog_models=%d catalog_complete=%v catalog_ids=%q error=%s title=%q", provider.SourceID, provider.Provider, liveHTTPStatus(provider.Provider, observed), parserStatus, provider.Status, provider.EvidenceCount, catalogCount, catalogComplete, catalogIDs, provider.ErrorCode, provider.PageTitle)
		if provider.Provider == "alibaba" && provider.Snapshot != nil {
			byModel := make(map[string][]LifecycleEvidence)
			for _, page := range provider.Snapshot.Pages {
				t.Logf("public source detail provider=alibaba page=%s evidence=%d", page.URL, len(page.Evidence))
			}
			for _, evidence := range provider.Snapshot.Evidence {
				byModel[evidence.ModelID] = append(byModel[evidence.ModelID], evidence)
			}
			repeatedIDs, conflictingIDs, replacementHits := 0, 0, 0
			for modelID, evidenceList := range byModel {
				if len(evidenceList) > 1 {
					repeatedIDs++
					statuses := make(map[string]struct{})
					for _, evidence := range evidenceList {
						statuses[evidence.Status] = struct{}{}
					}
					if len(statuses) > 1 {
						conflictingIDs++
					}
					t.Logf("public evidence duplicate provider=alibaba model=%s records=%d statuses=%v evidence=%+v", modelID, len(evidenceList), statuses, evidenceList)
				}
			}
			for _, evidenceList := range provider.Snapshot.Evidence {
				if evidenceList.Replacement != "" {
					if _, ok := byModel[evidenceList.Replacement]; ok {
						replacementHits++
						t.Logf("public evidence replacement-also-listed provider=alibaba deprecated=%s replacement=%s source=%s", evidenceList.ModelID, evidenceList.Replacement, evidenceList.SourceURL)
					}
				}
			}
			t.Logf("public evidence audit provider=alibaba unique_model_ids=%d repeated_ids=%d conflicting_status_ids=%d replacement_ids_also_listed=%d", len(byModel), repeatedIDs, conflictingIDs, replacementHits)
		}
		switch parserStatus {
		case "pass":
			parsedCount++
		case "parse_error":
			parseErrorCount++
		case "not_reached_or_http_failure":
			unavailableCount++
		default:
			t.Errorf("source returned an unclassified parser state: provider=%s status=%s error=%s", provider.Provider, provider.Status, provider.ErrorCode)
		}
	}
	t.Logf("live source summary parsed=%d parse_error=%d unavailable_or_http_failure=%d total=%d", parsedCount, parseErrorCount, unavailableCount, len(result.Providers))
	loggedScopes := make(map[string]bool)
	for _, provider := range result.Providers {
		if provider.Scope == "" || provider.Scope == "api" || provider.Scope == "volcengine_ark_account_activation" || provider.Scope == "alibaba_model_studio_beijing_api_catalog" || loggedScopes[provider.Scope] {
			continue
		}
		loggedScopes[provider.Scope] = true
		catalog, ready := CurrentModelCatalog(result, provider.Scope, time.Now())
		t.Logf("live product union scope=%s ready=%v complete=%v sources=%v model_ids=%q", provider.Scope, ready, catalog.Complete, catalog.SourceIDs, catalog.ModelIDs)
	}
	observed.mu.Lock()
	defer observed.mu.Unlock()
	for _, result := range observed.results {
		if strings.Contains(result.URL, "x.ai/news/") || strings.Contains(result.URL, "help.openai.com/en/articles/20001354") {
			t.Logf("product catalog GET url=%s http=%d transport_error=%v", result.URL, result.StatusCode, result.TransportError)
		}
	}
	if len(observed.requests) == 0 || len(observed.requests) > MaxHTTPGets {
		t.Fatalf("live request count=%d outside 1..%d", len(observed.requests), MaxHTTPGets)
	}
	for _, req := range observed.requests {
		if validateRequestAllowlist(req.URL.String()) != nil {
			t.Errorf("live request escaped the fixed official allowlist: %s", req.URL)
		}
		for _, header := range []string{"Authorization", "X-Api-Key", "Cookie"} {
			if req.Header.Get(header) != "" {
				t.Errorf("anonymous live GET sent prohibited header %s", header)
			}
		}
	}
}

func liveHTTPStatus(provider string, observed *liveSmokeDoer) string {
	observed.mu.Lock()
	defer observed.mu.Unlock()
	statuses := make([]string, 0)
	for _, item := range observed.results {
		for _, spec := range sourceManifest {
			if spec.provider == provider && validateSourceURL(spec, item.URL) == nil {
				status := "transport_error"
				if item.StatusCode != 0 {
					status = fmt.Sprintf("%d", item.StatusCode)
				}
				statuses = append(statuses, status)
				break
			}
		}
	}
	if len(statuses) == 0 {
		return "no-request"
	}
	return strings.Join(statuses, ",")
}

func liveParserStatus(provider ProviderSync) string {
	if provider.Status == "updated" || provider.Status == "unchanged" {
		return "pass"
	}
	if provider.ErrorCode == "source_parse_error" {
		return "parse_error"
	}
	return "not_reached_or_http_failure"
}

func TestStartupFailurePreservesLastGoodAndOfflineDoesNotNetwork(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cache")
	first := SyncStartup(context.Background(), StartupSyncOptions{CacheDir: root, NewDoer: func() HTTPDoer { return fixtureRouter(t, false) }, Now: time.Now})
	for _, item := range first.Providers {
		if item.SourceID == "volcengine-ark-account-models" || item.SourceID == "alibaba-model-studio-models" {
			continue
		}
		if item.Status != "updated" {
			t.Fatalf("initial source sync failed: %+v", item)
		}
	}
	prior, err := readSourceSnapshot(root, specFor(t, "openai"))
	if err != nil {
		t.Fatal(err)
	}
	failedDoer := fixtureRouter(t, true)
	second := SyncStartup(context.Background(), StartupSyncOptions{CacheDir: root, NewDoer: func() HTTPDoer { return failedDoer }, Now: time.Now})
	for _, item := range second.Providers {
		if item.SourceID == "volcengine-ark-account-models" || item.SourceID == "alibaba-model-studio-models" {
			continue
		}
		if item.Status != "stale" || item.Snapshot == nil {
			t.Errorf("failed refresh did not retain last-good: %+v", item)
		}
	}
	after, err := readSourceSnapshot(root, specFor(t, "openai"))
	if err != nil {
		t.Fatal(err)
	}
	if prior.ContentSHA256 != after.ContentSHA256 || !prior.CheckedAt.Equal(after.CheckedAt) {
		t.Fatal("failed refresh replaced the last-good snapshot")
	}
	failedDoer.mu.Lock()
	requestsBeforeOffline := len(failedDoer.requests)
	failedDoer.mu.Unlock()
	lookupCalls, clients := 0, 0
	offline := SyncStartup(context.Background(), StartupSyncOptions{Offline: true, CacheDir: root, LookupEnv: func(string) (string, bool) { lookupCalls++; return "x", true }, NewDoer: func() HTTPDoer { clients++; return failedDoer }})
	failedDoer.mu.Lock()
	requestsAfterOffline := len(failedDoer.requests)
	failedDoer.mu.Unlock()
	if lookupCalls != 0 || clients != 0 || requestsAfterOffline != requestsBeforeOffline {
		t.Fatalf("offline path touched network or credentials: lookups=%d clients=%d requests before=%d after=%d", lookupCalls, clients, requestsBeforeOffline, requestsAfterOffline)
	}
	for _, item := range offline.Providers {
		if item.SourceID == "volcengine-ark-account-models" {
			if item.Status != "offline_cache_missing" {
				t.Errorf("unconfigured Ark offline state is unexpected: %+v", item)
			}
			continue
		}
		if item.SourceID == "alibaba-model-studio-models" {
			if item.Status != "offline_cache_missing" {
				t.Errorf("unconfigured Model Studio offline state is unexpected: %+v", item)
			}
			continue
		}
		if item.Status != "offline_cached" {
			t.Errorf("offline cache status=%+v", item)
		}
	}
}

func TestConditionalGet304RequiresAndReusesGoodSnapshot(t *testing.T) {
	spec := specFor(t, "openai")
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	parsed, err := parseSourcePage(spec, spec.rootURL, fixture(t, "openai-deprecations.html"), now)
	if err != nil {
		t.Fatal(err)
	}
	body := fixture(t, "openai-deprecations.html")
	hash := sha256Hex(body)
	prior := CachedPage{URL: spec.rootURL, Title: parsed.Title, ContentSHA256: hash, FetchedAt: now, ETag: "etag-old", LastModified: "old-date", Evidence: parsed.Evidence}
	seenHeaders := false
	doer := &fakeDoer{handler: func(req *http.Request) (*http.Response, error) {
		seenHeaders = req.Header.Get("If-None-Match") == "etag-old" && req.Header.Get("If-Modified-Since") == "old-date"
		return &http.Response{StatusCode: http.StatusNotModified, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	got, err := fetchAndParsePage(context.Background(), spec, spec.rootURL, prior, true, doer, &requestBudget{}, func() time.Time { return now.Add(time.Minute) })
	if err != nil || !seenHeaders || got.ContentSHA256 != prior.ContentSHA256 || len(got.Evidence) != 1 {
		t.Fatalf("304 reuse failed: headers=%v got=%+v err=%v", seenHeaders, got, err)
	}
	if _, err := fetchAndParsePage(context.Background(), spec, spec.rootURL, CachedPage{}, false, doer, &requestBudget{}, time.Now); failureCode(err) != "invalid_not_modified_response" {
		t.Fatalf("304 without cached body accepted: %v", err)
	}
}

func TestPersistentSnapshotHasPrivatePermissions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cache")
	result := SyncStartup(context.Background(), StartupSyncOptions{CacheDir: root, NewDoer: func() HTTPDoer { return fixtureRouter(t, false) }, Now: time.Now})
	if result.Providers[0].Status != "updated" {
		t.Fatalf("sync failed: %+v", result.Providers[0])
	}
	path := filepath.Join(root, sourceManifest[0].id, "snapshot.json")
	if err := securePrivateFile(path); err != nil {
		t.Fatalf("cache file security validation failed: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatalf("cache is not private: %v", info.Mode().Perm())
		}
	}
}

func sha256Hex(body []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(body))
}
