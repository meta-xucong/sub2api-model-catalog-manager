package officialcatalog

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	StartupSyncTimeout     = 60 * time.Second
	ProviderSyncTimeout    = 10 * time.Second
	MaxHTTPGets            = 102
	MaxRedirects           = 2
	MaxAlibabaNotices      = 16
	MaxXAIMigrations       = 8
	MaxXAIGrokNewsArticles = 64
	MaxParsedLinks         = 4096
)

var sourceOrder = []string{"openai", "anthropic", "deepseek", "alibaba", "xai"}

type sourceSpec struct {
	id       string
	provider string
	scope    string
	adapter  string
	// cacheScope isolates account-scoped catalogs while keeping public source identity stable.
	cacheScope string
	// productSurface distinguishes accepted user-facing products within a
	// provider. Lifecycle on one surface must not cancel a positive on another.
	productSurface    string
	rootURL           string
	limitation        string
	maxBody           int64
	maxChildren       int
	catalog           bool
	catalogMayBeEmpty bool
	// completeAcceptedUnion is true only when this source is a complete current
	// catalog covering every accepted web/login product for this vendor.
	completeAcceptedUnion bool
	// versionFloorCatalog is an official signed-in product listing whose lowest
	// canonical model version may be used to retire older versions of that same
	// model family. It does not make newer or differently surfaced IDs available.
	versionFloorCatalog bool
	// lifecycleCoversAcceptedUnion is true only when lifecycle statements on
	// this source explicitly cover every accepted web/login product for the
	// vendor. A product-specific notice must leave it false.
	lifecycleCoversAcceptedUnion bool
}

var sourceManifest = []sourceSpec{
	{id: "openai-api-deprecations", provider: "openai", scope: "api", rootURL: "https://developers.openai.com/api/docs/deprecations", limitation: "Official OpenAI API deprecation evidence only; ChatGPT product changes and proxy routes may differ.", maxBody: 2 << 20},
	{id: "anthropic-model-deprecations", provider: "anthropic", scope: "api", rootURL: "https://platform.claude.com/docs/en/about-claude/model-deprecations", limitation: "Anthropic-operated API lifecycle only; partner-platform routes may differ.", maxBody: 2 << 20},
	{id: "deepseek-api-updates", provider: "deepseek", scope: "api", rootURL: "https://api-docs.deepseek.com/updates/", limitation: "Only explicit lifecycle notices on the official API change log; unmentioned IDs remain unknown.", maxBody: 2 << 20},
	{id: "alibaba-model-deprecation", provider: "alibaba", scope: "api", rootURL: "https://help.aliyun.com/zh/model-studio/model-depreciation", limitation: "Official Model Studio lifecycle notices only; proxy routes may differ.", maxBody: 2 << 20, maxChildren: MaxAlibabaNotices},
	{id: "xai-api-release-notes", provider: "xai", scope: "api", rootURL: "https://docs.x.ai/developers/release-notes", limitation: "Official xAI API release notes only; compatibility redirects do not prove third-party routing.", maxBody: 2 << 20, maxChildren: MaxXAIMigrations},
	{id: "openai-codex-models", provider: "openai", scope: "openai_codex_chatgpt_login", productSurface: "openai_codex", rootURL: "https://developers.openai.com/codex/models", limitation: "Codex with ChatGPT sign-in model list; not an exhaustive ChatGPT web catalog or API-key catalog.", maxBody: 2 << 20, catalog: true, versionFloorCatalog: true},
	{id: "openai-chatgpt-models", provider: "openai", scope: "openai_codex_chatgpt_login", productSurface: "openai_chatgpt_web", rootURL: "https://help.openai.com/en/articles/20001354-gpt-6-and-other-models-in-chatgpt", limitation: "ChatGPT signed-in web model guide; exact visible GPT family names only, with no exhaustive selector inventory or API-key catalog.", maxBody: 2 << 20, catalog: true},
	{id: "openai-chatgpt-gpt6-announcement", provider: "openai", scope: "openai_codex_chatgpt_login", productSurface: "openai_chatgpt_web", rootURL: "https://openai.com/index/gpt-6-for-everyone/", limitation: "Positive ChatGPT web launch evidence for GPT-6 only; partial product announcement, not a complete selector inventory or API-key catalog.", maxBody: 2 << 20, catalog: true},
	{id: "openai-cross-product-lifecycle-v2", provider: "openai", scope: "openai_codex_chatgpt_login", productSurface: "openai_chatgpt_web", rootURL: "https://learn.chatgpt.com/docs/changelog", limitation: "Accepted-union retirement only when one explicit official sentence retires an exact model from both ChatGPT web and Codex; Codex-only, product-specific, or API-only notices do not establish union retirement.", maxBody: 2 << 20, lifecycleCoversAcceptedUnion: true},
	{id: "anthropic-claude-code-models", provider: "anthropic", scope: "anthropic_claude_code_login", productSurface: "anthropic_claude_code", rootURL: "https://support.claude.com/en/articles/11940350-claude-code-model-configuration", limitation: "Claude Code supported-model list for normal sign-in; not an exhaustive consumer Claude selector or API-key catalog.", maxBody: 2 << 20, catalog: true},
	{id: "anthropic-claude-web-models", provider: "anthropic", scope: "anthropic_claude_code_login", productSurface: "anthropic_claude_consumer", rootURL: "https://support.claude.com/en/articles/8606394-how-large-is-the-context-window-on-paid-claude-plans", limitation: "Paid Claude consumer chat model names; exact IDs are admitted only through explicit aliases cross-checked against the Claude Code model configuration list.", maxBody: 2 << 20, catalog: true},
	{id: "anthropic-claude-release-notes", provider: "anthropic", scope: "anthropic_claude_code_login", productSurface: "anthropic_claude_consumer", rootURL: "https://support.claude.com/en/articles/12138966-release-notes", limitation: "Consumer Claude release notes; product/plan-specific retirements do not establish Claude Code or API availability.", maxBody: 2 << 20},
	{id: "kimi-code-models", provider: "kimi", scope: "kimi_code_login", productSurface: "kimi_code", rootURL: "https://www.kimi.com/en/help/kimi-code/models", limitation: "Kimi Code positive model/plan listing only; page absence is not evidence about Kimi chat.", maxBody: 2 << 20, catalog: true},
	{id: "kimi-web-models", provider: "kimi", scope: "kimi_code_login", productSurface: "kimi_web", rootURL: "https://www.kimi.com/en/help/new-user-guide/agentic-chat", limitation: "Kimi web selector names; only the K3 display name has a currently defensible exact ID crosswalk, while other labels remain unclassified.", maxBody: 2 << 20, catalog: true},
	{id: "kimi-code-whats-new", provider: "kimi", scope: "kimi_code_login", productSurface: "kimi_code", rootURL: "https://www.kimi.com/code/docs/en/kimi-code/whats-new.html", limitation: "Kimi Code lifecycle notices only; product/plan-specific limits are not global retirement.", maxBody: 2 << 20},
	{id: "volcengine-ark-account-models", provider: "volcengine", scope: "volcengine_ark_account_activation", adapter: "volcengine_ark", rootURL: "https://ark.cn-beijing.volcengineapi.com/?Action=ListModelActivations&Version=2024-01-01", limitation: "Current Ark account activation inventory only; exact IDs are scoped to the configured AK/SK account, not a global manufacturer or consumer-product catalog.", maxBody: 2 << 20, catalog: true, catalogMayBeEmpty: true},
	{id: "alibaba-model-studio-models", provider: "alibaba", scope: "alibaba_model_studio_beijing_api_catalog", adapter: "alibaba_model_studio", rootURL: "https://ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com/api/v1/models?page_no=1&page_size=200", limitation: "Official Beijing Model Studio API model catalog for the configured workspace; this is regional API catalog evidence, not web-product availability or account inference entitlement.", maxBody: 2 << 20, maxChildren: 99, catalog: true},
	{id: "xai-grok-web-models", provider: "xai", scope: "xai_grok_web_login", productSurface: "xai_grok_web", rootURL: "https://x.ai/news/grok-4-5-everywhere", limitation: "Positive Grok web evidence from the official Grok 4.5 web announcement; the x.ai/news index and sitemap are Cloudflare-blocked from this runtime, so future announcements cannot be discovered automatically yet. Never an API or Grok Build catalog.", maxBody: 2 << 20, maxChildren: MaxXAIGrokNewsArticles, catalog: true, versionFloorCatalog: true},
}

var (
	tagRE                    = regexp.MustCompile(`(?is)<[^>]+>`)
	spaceRE                  = regexp.MustCompile(`[\s\x{00a0}]+`)
	scriptRE                 = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<nav\b[^>]*>.*?</nav>|<footer\b[^>]*>.*?</footer>`)
	titleRE                  = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title>`)
	mainArticleRE            = regexp.MustCompile(`(?is)<article\b[^>]*id=["']mainContent["'][^>]*>(.*?)</article>`)
	openAIChangelogEntry     = regexp.MustCompile(`(?is)<li\b([^>]*)>(.*?)</li>`)
	openAIChangelogProducts  = regexp.MustCompile(`(?is)\bdata-products=["']([^"']*)["']`)
	openAIChangelogHeading   = regexp.MustCompile(`(?is)<h[1-6]\b[^>]*>(.*?)</h[1-6]>`)
	openAIChangelogFullDate  = regexp.MustCompile(`(?i)\b(?:on|effective(?:\s+on)?)\s+([A-Z][a-z]+\s+\d{1,2},\s+\d{4})`)
	openAIChangelogShortDate = regexp.MustCompile(`(?i)\s+on\s+[A-Z][a-z]+\s+\d{1,2}\s*$`)
	h1RE                     = regexp.MustCompile(`(?is)<h1\b[^>]*>(.*?)</h1>`)
	headingRE                = regexp.MustCompile(`(?is)<h[1-6]\b[^>]*>(.*?)</h[1-6]>`)
	rowRE                    = regexp.MustCompile(`(?is)<tr\b[^>]*>(.*?)</tr>`)
	cellRE                   = regexp.MustCompile(`(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>`)
	tableRE                  = regexp.MustCompile(`(?is)<table\b[^>]*>.*?</table>`)
	listItemRE               = regexp.MustCompile(`(?is)<li\b[^>]*>(.*?)</li>`)
	listBlockRE              = regexp.MustCompile(`(?is)<(?:ul|ol)\b[^>]*>.*?</(?:ul|ol)>`)
	linkRE                   = regexp.MustCompile(`(?is)<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>`)
	metaTagRE                = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
	metaNameRE               = regexp.MustCompile(`(?is)\b(?:name|property)\s*=\s*["']([^"']+)["']`)
	metaContentRE            = regexp.MustCompile(`(?is)\bcontent\s*=\s*["']([^"']*)["']`)
	modelTokenRE             = regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9]*(?:[._:-][a-zA-Z0-9]+)+\b`)
	dateISORe                = regexp.MustCompile(`\b(20\d{2}-\d{2}-\d{2})\b`)
	dateUSRe                 = regexp.MustCompile(`(?i)\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+([0-3]?\d),?\s+(20\d{2})\b`)
	dateCNRe                 = regexp.MustCompile(`(20\d{2})\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日`)
	monthDayRe               = regexp.MustCompile(`(?i)\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+([0-3]?\d)\b`)
	aliyunPath               = regexp.MustCompile(`^/notice/([0-9]+)$`)
	aliyunID                 = regexp.MustCompile(`^[0-9]+$`)
	alibabaLifecycleAnchorRE = regexp.MustCompile(`不再提供|停止服务|下线|退役|停服`)
	xaiPath                  = regexp.MustCompile(`^/developers/migration/[a-z0-9-]+$`)
	xaiNewsPath              = regexp.MustCompile(`^/news/[a-z0-9-]+$`)
)

const alibabaBulletinRenderer = "https://t.aliyun.com/abs/bulletin/bulletinDetail"

type alibabaBulletinResponse struct {
	Data struct {
		Success bool `json:"success"`
		Info    struct {
			Title      string `json:"title"`
			DetailList []struct {
				ContentHTML string `json:"contentHtml"`
			} `json:"detailList"`
		} `json:"info"`
	} `json:"data"`
}

type fetchFailure struct{ code string }

func (f fetchFailure) Error() string { return f.code }

type requestBudget struct{ used atomic.Int64 }

func (b *requestBudget) reserve() bool {
	for {
		current := b.used.Load()
		if current >= MaxHTTPGets {
			return false
		}
		if b.used.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (b *requestBudget) count() int { return int(b.used.Load()) }

func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: anonymousEnvironmentProxy, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		Timeout:   ProviderSyncTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func anonymousEnvironmentProxy(req *http.Request) (*url.URL, error) {
	proxy, err := resolveAnonymousProxy(req, http.ProxyFromEnvironment)
	return proxy, err
}

func resolveAnonymousProxy(req *http.Request, resolve func(*http.Request) (*url.URL, error)) (*url.URL, error) {
	if resolve == nil {
		return nil, errors.New("proxy resolver unavailable")
	}
	proxy, err := resolve(req)
	if err != nil || proxy == nil {
		return proxy, err
	}
	if proxy.User != nil {
		return nil, errors.New("credentialed proxy is disabled")
	}
	return proxy, nil
}

func validateConfiguredProxy(resolve func(*http.Request) (*url.URL, error)) error {
	if resolve == nil {
		resolve = http.ProxyFromEnvironment
	}
	urls := make([]string, 0, 5+MaxAlibabaNotices+MaxXAIMigrations)
	for _, spec := range sourceManifest {
		urls = append(urls, spec.rootURL)
		for i := 0; i < spec.maxChildren; i++ {
			if spec.provider == "alibaba" {
				urls = append(urls, alibabaBulletinURL(fmt.Sprintf("%d", 1+i)))
			} else if spec.id == "xai-grok-web-models" {
				urls = append(urls, fmt.Sprintf("https://x.ai/news/proxy-check-%d", i))
			} else if spec.provider == "xai" {
				urls = append(urls, fmt.Sprintf("https://docs.x.ai/developers/migration/proxy-check-%d", i))
			}
		}
	}
	for _, raw := range urls {
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			return errors.New("proxy_configuration_rejected")
		}
		if _, err := resolveAnonymousProxy(req, resolve); err != nil {
			return errors.New("proxy_configuration_rejected")
		}
	}
	return nil
}

type parsedPage struct {
	Title             string
	Links             []string
	Evidence          []LifecycleEvidence
	AvailableModelIDs []string
}

func sourceForProvider(provider string) (sourceSpec, bool) {
	for _, spec := range sourceManifest {
		if spec.provider == provider {
			return spec, true
		}
	}
	return sourceSpec{}, false
}

func sourceForID(id string) (sourceSpec, bool) {
	for _, spec := range sourceManifest {
		if spec.id == id {
			return spec, true
		}
	}
	return sourceSpec{}, false
}

func validateSourceURL(spec sourceSpec, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" || u.ForceQuery {
		return fetchFailure{code: "source_url_rejected"}
	}
	switch spec.id {
	case "volcengine-ark-account-models":
		if u.Host != "ark.cn-beijing.volcengineapi.com" || u.Path != "/" || u.RawQuery != "Action=ListModelActivations&Version=2024-01-01" {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "alibaba-model-studio-models":
		if u.Host != "ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com" || u.Path != "/api/v1/models" || u.Fragment != "" {
			return fetchFailure{code: "source_url_rejected"}
		}
		query := u.Query()
		pageNo, pageSize := query.Get("page_no"), query.Get("page_size")
		if len(query) != 2 || len(query["page_no"]) != 1 || len(query["page_size"]) != 1 || pageNo == "" || pageSize != "200" {
			return fetchFailure{code: "source_url_rejected"}
		}
		pageNumber, err := strconv.Atoi(pageNo)
		if err != nil || pageNumber < 1 || pageNumber > 100 || strconv.Itoa(pageNumber) != pageNo {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "openai-codex-models":
		if u.RawQuery != "" || !((u.Host == "developers.openai.com" && u.Path == "/codex/models") || (u.Host == "learn.chatgpt.com" && u.Path == "/docs/models")) {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "openai-chatgpt-models":
		if u.Host != "help.openai.com" || u.Path != "/en/articles/20001354-gpt-6-and-other-models-in-chatgpt" || u.RawQuery != "" {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "openai-chatgpt-gpt6-announcement":
		if u.Host != "openai.com" || u.Path != "/index/gpt-6-for-everyone/" || u.RawQuery != "" {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "openai-cross-product-lifecycle-v2":
		if u.Host != "learn.chatgpt.com" || u.Path != "/docs/changelog" || u.RawQuery != "" {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "anthropic-claude-release-notes":
		if u.Host != "support.claude.com" || u.Path != "/en/articles/12138966-release-notes" || u.RawQuery != "" {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "anthropic-claude-code-models":
		if u.Host != "support.claude.com" || u.Path != "/en/articles/11940350-claude-code-model-configuration" || u.RawQuery != "" {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "anthropic-claude-web-models":
		if u.Host != "support.claude.com" || u.Path != "/en/articles/8606394-how-large-is-the-context-window-on-paid-claude-plans" || u.RawQuery != "" {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "kimi-code-models":
		if u.Host != "www.kimi.com" || u.Path != "/en/help/kimi-code/models" || u.RawQuery != "" {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "kimi-web-models":
		if u.Host != "www.kimi.com" || u.Path != "/en/help/new-user-guide/agentic-chat" || u.RawQuery != "" {
			return fetchFailure{code: "source_url_rejected"}
		}
	case "kimi-code-whats-new":
		if u.Host != "www.kimi.com" || u.Path != "/code/docs/en/kimi-code/whats-new.html" || u.RawQuery != "" {
			return fetchFailure{code: "source_url_rejected"}
		}
	default:
		switch spec.provider {
		case "openai":
			if u.Host != "developers.openai.com" || u.Path != "/api/docs/deprecations" || u.RawQuery != "" {
				return fetchFailure{code: "source_url_rejected"}
			}
		case "anthropic":
			if u.Host != "platform.claude.com" || u.Path != "/docs/en/about-claude/model-deprecations" || u.RawQuery != "" {
				return fetchFailure{code: "source_url_rejected"}
			}
		case "deepseek":
			if u.Host != "api-docs.deepseek.com" || u.Path != "/updates" && u.Path != "/updates/" || u.RawQuery != "" {
				return fetchFailure{code: "source_url_rejected"}
			}
		case "alibaba":
			if u.Host == "help.aliyun.com" && u.Path == "/zh/model-studio/model-depreciation" {
				if u.RawQuery == "" {
					return nil
				}
			}
			if !isAlibabaRendererURL(u) {
				return fetchFailure{code: "source_url_rejected"}
			}
		case "xai":
			if spec.id == "xai-grok-web-models" {
				if u.Host != "x.ai" || (u.Path != "/news" && !xaiNewsPath.MatchString(u.Path)) || u.RawQuery != "" {
					return fetchFailure{code: "source_url_rejected"}
				}
			} else if u.Host != "docs.x.ai" || (u.Path != "/developers/release-notes" && !xaiPath.MatchString(u.Path)) || u.RawQuery != "" {
				return fetchFailure{code: "source_url_rejected"}
			}
		default:
			return fetchFailure{code: "source_url_rejected"}
		}
	}
	return nil
}

func aliyunNoticeIDFromIndexURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "www.aliyun.com" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", false
	}
	match := aliyunPath.FindStringSubmatch(u.Path)
	if len(match) != 2 || !aliyunID.MatchString(match[1]) {
		return "", false
	}
	return match[1], true
}

func isAlibabaNoticeLandingURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Host == "www.aliyun.com" && u.User == nil && u.Port() == "" && u.Path == "/notice/" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

func alibabaBulletinURL(id string) string {
	if !aliyunID.MatchString(id) {
		return ""
	}
	return fmt.Sprintf("%s?id=%s&language=zh&website=cn", alibabaBulletinRenderer, id)
}

func isAlibabaRendererURL(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.Host != "t.aliyun.com" || u.User != nil || u.Port() != "" || u.Path != "/abs/bulletin/bulletinDetail" || u.Fragment != "" {
		return false
	}
	if !strings.HasPrefix(u.RawQuery, "id=") {
		return false
	}
	parts := strings.Split(u.RawQuery, "&")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "id=") || !aliyunID.MatchString(strings.TrimPrefix(parts[0], "id=")) {
		return false
	}
	return parts[1] == "language=zh" && parts[2] == "website=cn"
}

func isAlibabaRendererRequestURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && isAlibabaRendererURL(u)
}

func fetchSource(ctx context.Context, spec sourceSpec, prior *CatalogSnapshot, doer HTTPDoer, budget *requestBudget, now func() time.Time) (CatalogSnapshot, error) {
	if ctx == nil || doer == nil || budget == nil {
		return CatalogSnapshot{}, fetchFailure{code: "source_fetch_unavailable"}
	}
	if now == nil {
		now = time.Now
	}
	oldPages := make(map[string]CachedPage)
	if prior != nil {
		for _, page := range prior.Pages {
			oldPages[page.URL] = page
		}
	}
	urls := []string{spec.rootURL}
	pages := make(map[string]CachedPage, 1+spec.maxChildren)
	for len(urls) > 0 {
		current := urls[0]
		urls = urls[1:]
		if _, exists := pages[current]; exists {
			continue
		}
		if err := validateSourceURL(spec, current); err != nil {
			return CatalogSnapshot{}, err
		}
		old, hasOld := oldPages[current]
		page, err := fetchAndParsePage(ctx, spec, current, old, hasOld, doer, budget, now)
		if err != nil {
			return CatalogSnapshot{}, err
		}
		pages[current] = page
		if current == spec.rootURL {
			children, err := validateChildren(spec, current, page.Links)
			if err != nil {
				return CatalogSnapshot{}, err
			}
			urls = append(urls, children...)
		}
	}
	ordered := make([]CachedPage, 0, len(pages))
	for _, page := range pages {
		ordered = append(ordered, page)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].URL < ordered[j].URL })
	all := make([]LifecycleEvidence, 0)
	for _, page := range ordered {
		all = append(all, page.Evidence...)
	}
	all = normalizeEvidence(all)
	checked := now().UTC()
	fetched := time.Time{}
	for _, page := range ordered {
		if page.FetchedAt.After(fetched) {
			fetched = page.FetchedAt
		}
	}
	if fetched.IsZero() {
		fetched = checked
	}
	digest, err := snapshotDigest(ordered)
	if err != nil {
		return CatalogSnapshot{}, fetchFailure{code: "source_parse_error"}
	}
	return CatalogSnapshot{SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Pages: ordered, Evidence: all, FetchedAt: fetched, CheckedAt: checked, ContentSHA256: digest, Complete: true}, nil
}

func fetchAndParsePage(ctx context.Context, spec sourceSpec, rawURL string, prior CachedPage, hasPrior bool, doer HTTPDoer, budget *requestBudget, now func() time.Time) (CachedPage, error) {
	if err := validateSourceURL(spec, rawURL); err != nil {
		return CachedPage{}, err
	}
	current := rawURL
	for redirects := 0; redirects <= MaxRedirects; redirects++ {
		if !budget.reserve() {
			return CachedPage{}, fetchFailure{code: "source_request_budget_exceeded"}
		}
		reqCtx, cancel := context.WithTimeout(ctx, ProviderSyncTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, current, nil)
		if err != nil {
			cancel()
			return CachedPage{}, fetchFailure{code: "source_request_invalid"}
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1")
		req.Header.Set("User-Agent", "sub2api-model-catalog-manager/official-lifecycle-review")
		if spec.provider == "alibaba" && isAlibabaRendererRequestURL(current) {
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Origin", "https://www.aliyun.com")
		}
		if current == rawURL && hasPrior {
			if prior.ETag != "" {
				req.Header.Set("If-None-Match", prior.ETag)
			}
			if prior.LastModified != "" {
				req.Header.Set("If-Modified-Since", prior.LastModified)
			}
		}
		resp, err := doer.Do(req)
		if err != nil || resp == nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			cancel()
			return CachedPage{}, fetchFailure{code: "http_error"}
		}
		if isRedirect(resp.StatusCode) {
			location := resp.Header.Get("Location")
			_ = resp.Body.Close()
			cancel()
			if redirects >= MaxRedirects || location == "" {
				return CachedPage{}, fetchFailure{code: "redirect_limit_exceeded"}
			}
			base, _ := url.Parse(current)
			ref, parseErr := url.Parse(location)
			if parseErr != nil {
				return CachedPage{}, fetchFailure{code: "redirect_rejected"}
			}
			current = base.ResolveReference(ref).String()
			if isAlibabaRendererRequestURL(rawURL) && current != rawURL {
				return CachedPage{}, fetchFailure{code: "redirect_rejected"}
			}
			if err := validateSourceURL(spec, current); err != nil {
				return CachedPage{}, fetchFailure{code: "redirect_rejected"}
			}
			continue
		}
		if resp.StatusCode == http.StatusNotModified {
			_ = resp.Body.Close()
			cancel()
			if !hasPrior || prior.URL != rawURL || prior.ContentSHA256 == "" || prior.Title == "" {
				return CachedPage{}, fetchFailure{code: "invalid_not_modified_response"}
			}
			prior.FetchedAt = now().UTC()
			for i := range prior.Evidence {
				prior.Evidence[i].RetrievedAt = prior.FetchedAt
			}
			return prior, nil
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			cancel()
			return CachedPage{}, fetchFailure{code: "http_error"}
		}
		limit := spec.maxBody
		if rawURL != spec.rootURL {
			limit = 1 << 20
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		closeErr := resp.Body.Close()
		cancel()
		if readErr != nil || closeErr != nil {
			return CachedPage{}, fetchFailure{code: "http_error"}
		}
		if len(body) == 0 || int64(len(body)) > limit {
			return CachedPage{}, fetchFailure{code: "response_too_large_or_empty"}
		}
		parsed, parseErr := parseSourcePage(spec, rawURL, body, now().UTC())
		if parseErr != nil {
			return CachedPage{}, fetchFailure{code: "source_parse_error"}
		}
		hash := sha256.Sum256(body)
		return CachedPage{
			URL: rawURL, Title: parsed.Title, ContentSHA256: hex.EncodeToString(hash[:]), FetchedAt: now().UTC(),
			ETag: safeHeader(resp.Header.Get("ETag")), LastModified: safeHeader(resp.Header.Get("Last-Modified")),
			Links: parsed.Links, Evidence: parsed.Evidence, AvailableModelIDs: parsed.AvailableModelIDs,
		}, nil
	}
	return CachedPage{}, fetchFailure{code: "redirect_limit_exceeded"}
}

func validateChildren(spec sourceSpec, root string, links []string) ([]string, error) {
	if spec.maxChildren == 0 {
		return nil, nil
	}
	if spec.id == "xai-grok-web-models" {
		children := make([]string, 0, len(links))
		seen := make(map[string]bool, len(links))
		for _, link := range links {
			if link == root || seen[link] {
				continue
			}
			if validateSourceURL(spec, link) != nil {
				return nil, fetchFailure{code: "source_link_rejected"}
			}
			seen[link] = true
			children = append(children, link)
			if len(children) == spec.maxChildren {
				break
			}
		}
		return children, nil
	}
	rootURL, _ := url.Parse(root)
	set := make(map[string]bool)
	children := make([]string, 0)
	for _, href := range links {
		parsed, err := url.Parse(href)
		if err != nil {
			return nil, fetchFailure{code: "source_parse_error"}
		}
		resolved := rootURL.ResolveReference(parsed).String()
		if spec.provider == "alibaba" {
			id, validNotice := aliyunNoticeIDFromIndexURL(resolved)
			if !validNotice {
				candidateURL, _ := url.Parse(resolved)
				if candidateURL != nil && strings.HasPrefix(candidateURL.Path, "/notice/") {
					if isAlibabaNoticeLandingURL(candidateURL) {
						continue
					}
					return nil, fetchFailure{code: "source_link_rejected"}
				}
				continue
			}
			target := alibabaBulletinURL(id)
			if !set[target] {
				set[target] = true
				children = append(children, target)
			}
			continue
		}
		if validateSourceURL(spec, resolved) != nil {
			candidateURL, _ := url.Parse(resolved)
			alibabaNoticeCandidate := candidateURL != nil && strings.HasPrefix(candidateURL.Path, "/notice/") && candidateURL.Path != "/notice/"
			xaiMigrationCandidate := candidateURL != nil && strings.Contains(candidateURL.Path, "/developers/migration/")
			if alibabaNoticeCandidate || xaiMigrationCandidate {
				return nil, fetchFailure{code: "source_link_rejected"}
			}
			continue
		}
		if resolved == root || set[resolved] {
			continue
		}
		set[resolved] = true
		children = append(children, resolved)
	}
	sort.Strings(children)
	if len(children) > spec.maxChildren {
		return nil, fetchFailure{code: "source_link_limit_exceeded"}
	}
	return children, nil
}

func parseAlibabaBulletin(spec sourceSpec, sourceURL string, body []byte, retrievedAt time.Time) (parsedPage, error) {
	var response alibabaBulletinResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return parsedPage{}, errors.New("Alibaba bulletin response is not valid JSON")
	}
	if !response.Data.Success {
		return parsedPage{}, errors.New("Alibaba bulletin response reports failure")
	}
	title := strings.TrimSpace(response.Data.Info.Title)
	if title == "" {
		return parsedPage{}, errors.New("Alibaba bulletin title is empty")
	}
	contents := make([]string, 0, len(response.Data.Info.DetailList))
	for _, detail := range response.Data.Info.DetailList {
		if strings.TrimSpace(detail.ContentHTML) != "" {
			contents = append(contents, detail.ContentHTML)
		}
	}
	if len(contents) == 0 {
		return parsedPage{}, errors.New("Alibaba bulletin has no rendered content")
	}
	page := parsedPage{Title: shortText(title, 200)}
	hash := sha256.Sum256(body)
	for _, contentHTML := range contents {
		visible := extractVisibleText(contentHTML)
		proseHTML := tableRE.ReplaceAllString(contentHTML, " ")
		proseHTML = listBlockRE.ReplaceAllString(proseHTML, " ")
		prose := extractVisibleText(proseHTML)
		page.Evidence = append(page.Evidence, alibabaProseEvidence(prose, sourceURL, page.Title, retrievedAt, hex.EncodeToString(hash[:]))...)
		page.Evidence = append(page.Evidence, alibabaListEvidence(contentHTML, visible, sourceURL, page.Title, retrievedAt, hex.EncodeToString(hash[:]))...)
		page.Evidence = append(page.Evidence, alibabaTableEvidence(contentHTML, visible, sourceURL, page.Title, retrievedAt, hex.EncodeToString(hash[:]))...)
	}
	for i := range page.Evidence {
		page.Evidence[i].SourceID = spec.id
		page.Evidence[i].Scope = spec.scope
	}
	page.Evidence = normalizeEvidence(page.Evidence)
	return page, nil
}

func alibabaProseEvidence(prose, sourceURL, title string, retrievedAt time.Time, digest string) []LifecycleEvidence {
	var evidence []LifecycleEvidence
	for _, anchor := range alibabaLifecycleAnchorRE.FindAllStringIndex(prose, -1) {
		start := strings.LastIndexAny(prose[:anchor[0]], "。！？；：:\n") + 1
		prefix := strings.TrimSpace(prose[start:anchor[0]])
		after := strings.TrimSpace(prose[anchor[0]:])
		if containsAny(prefix, "清单", "名单") || strings.HasPrefix(after, "下线清单") || strings.HasPrefix(after, "下线名单") {
			continue
		}
		ids := extractAlibabaModelIDs([]string{prefix})
		if len(ids) == 0 {
			// Support explicit titles such as “下线模型：qwen-x”; do not
			// treat a navigation/list label or replacement paragraph as a model.
			end := strings.IndexAny(after, "。！？；：:\n")
			if end < 0 || end > 100 {
				end = len(after)
				if end > 100 {
					end = 100
				}
			}
			candidate := after[:end]
			if !containsAny(candidate, "清单", "名单", "如下", "推荐", "替换", "方案") {
				ids = extractAlibabaModelIDs([]string{candidate})
			}
		}
		if len(ids) == 0 {
			continue
		}
		contextEnd := len(prose)
		if next := strings.IndexAny(prose[anchor[1]:], "。！？；\n"); next >= 0 {
			contextEnd = anchor[1] + next
		}
		context := strings.TrimSpace(prose[start:contextEnd])
		status := "announced_deprecated"
		if containsAny(context, "已下线", "已退役", "已停止服务", "已停服", "已不再提供") {
			status = "retired"
		}
		for _, id := range ids {
			evidence = append(evidence, LifecycleEvidence{
				Provider: "alibaba", ModelID: id, Status: status, EffectiveAt: findDate(context),
				SourceURL: sourceURL, SourceTitle: title, RetrievedAt: retrievedAt,
				ContentSHA256: digest, Excerpt: shortText(context, 360),
			})
		}
	}
	return evidence
}

func alibabaListEvidence(contentHTML, visible, sourceURL, title string, retrievedAt time.Time, digest string) []LifecycleEvidence {
	lower := strings.ToLower(visible)
	labels := []string{"具体下线清单如下", "下线清单如下", "下线名单如下", "下线模型清单如下"}
	ends := []string{"推荐替换方案", "推荐替换模型", "推荐替代方案", "替换方案", "替代模型"}
	var evidence []LifecycleEvidence
	for _, label := range labels {
		start := strings.Index(lower, strings.ToLower(label))
		if start < 0 {
			continue
		}
		start += len(label)
		end := len(visible)
		for _, marker := range ends {
			if pos := strings.Index(lower[start:], strings.ToLower(marker)); pos >= 0 && start+pos < end {
				end = start + pos
			}
		}
		segment := strings.TrimSpace(visible[start:end])
		ids := make([]string, 0)
		for _, itemMatch := range listItemRE.FindAllStringSubmatch(contentHTML, -1) {
			if len(itemMatch) != 2 {
				continue
			}
			item := cleanFragment(itemMatch[1])
			compactSegment := strings.ToLower(strings.ReplaceAll(segment, " ", ""))
			compactItem := strings.ToLower(strings.ReplaceAll(item, " ", ""))
			if item == "" || !strings.Contains(compactSegment, compactItem) {
				continue
			}
			for _, separator := range []string{"：", ":"} {
				if colon := strings.Index(item, separator); colon >= 0 {
					item = strings.TrimSpace(item[colon+len(separator):])
					break
				}
			}
			ids = append(ids, extractAlibabaModelIDs([]string{item})...)
		}
		ids = uniqueStrings(ids)
		if len(ids) == 0 {
			continue
		}
		prefix := visible[:start]
		if len(prefix) > 300 {
			prefix = prefix[len(prefix)-300:]
		}
		contextText := prefix + " " + segment
		status := "announced_deprecated"
		if containsAny(contextText, "已下线", "已退役", "已停止服务", "已停服") {
			status = "retired"
		}
		for _, id := range ids {
			evidence = append(evidence, LifecycleEvidence{
				Provider: "alibaba", ModelID: id, Status: status, EffectiveAt: findDate(contextText),
				SourceURL: sourceURL, SourceTitle: title, RetrievedAt: retrievedAt,
				ContentSHA256: digest, Excerpt: shortText(segment, 360),
			})
		}
		break
	}
	return evidence
}

func alibabaTableEvidence(contentHTML, visible, sourceURL, title string, retrievedAt time.Time, digest string) []LifecycleEvidence {
	if !containsAny(visible, "下线", "退役", "停止服务", "停服") || !containsAny(visible, "下表", "下线清单", "下线名单") {
		return nil
	}
	var evidence []LifecycleEvidence
	for _, tableMatch := range tableRE.FindAllStringIndex(contentHTML, -1) {
		table := contentHTML[tableMatch[0]:tableMatch[1]]
		rows := extractTableRows(table)
		if len(rows) < 2 || !containsAny(strings.Join(rows[0], " "), "模型名称", "模型名") {
			continue
		}
		replacementColumn := -1
		for index, header := range rows[0] {
			if isAlibabaReplacementHeader(header) {
				replacementColumn = index
				break
			}
		}
		prefixStart := tableMatch[0] - 1200
		if prefixStart < 0 {
			prefixStart = 0
		}
		prefix := extractVisibleText(contentHTML[prefixStart:tableMatch[0]])
		if !containsAny(prefix, "下表", "下线清单", "下线名单") || !containsAny(prefix, "下线", "退役", "停止服务", "停服") {
			continue
		}
		for _, row := range rows[1:] {
			if len(row) == 0 {
				continue
			}
			ids := extractAlibabaModelIDs([]string{row[0]})
			status := "announced_deprecated"
			rowText := strings.Join(row, " | ")
			if containsAny(prefix+" "+rowText, "已下线", "已退役", "已停止服务", "已停服") {
				status = "retired"
			}
			date := findDate(rowText)
			if date == "" {
				date = findDate(prefix)
			}
			for _, id := range ids {
				replacement := ""
				if replacementColumn >= 0 && replacementColumn < len(row) {
					if replacementIDs := extractAlibabaModelIDs([]string{row[replacementColumn]}); len(replacementIDs) == 1 && replacementIDs[0] != id {
						replacement = replacementIDs[0]
					}
				}
				evidence = append(evidence, LifecycleEvidence{
					Provider: "alibaba", ModelID: id, Status: status, EffectiveAt: date,
					Replacement: replacement,
					SourceURL:   sourceURL, SourceTitle: title, RetrievedAt: retrievedAt,
					ContentSHA256: digest, Excerpt: shortText(rowText, 360),
				})
			}
		}
	}
	return evidence
}

func isAlibabaReplacementHeader(header string) bool {
	header = strings.ToLower(strings.TrimSpace(header))
	return containsAny(header, "推荐替换模型", "推荐替代模型", "推荐替换型号", "推荐替代型号", "替换模型", "替代模型", "replacement model", "recommended replacement")
}

func openAIDeprecationRows(source string) ([][]string, bool) {
	var rows [][]string
	foundTable := false
	for _, table := range tableRE.FindAllString(source, -1) {
		tableRows := extractTableRows(table)
		if len(tableRows) == 0 {
			continue
		}
		shutdownIndex, modelIndex, replacementIndex := -1, -1, -1
		for index, rawHeader := range tableRows[0] {
			header := strings.ToLower(strings.TrimSpace(rawHeader))
			switch header {
			case "shutdown date":
				shutdownIndex = index
			case "model", "model / system", "model/system":
				modelIndex = index
			case "recommended replacement":
				replacementIndex = index
			}
		}
		if shutdownIndex < 0 || modelIndex < 0 || replacementIndex < 0 {
			continue
		}
		foundTable = true
		for _, row := range tableRows[1:] {
			if shutdownIndex >= len(row) || modelIndex >= len(row) || replacementIndex >= len(row) {
				continue
			}
			rows = append(rows, []string{row[shutdownIndex], row[modelIndex], row[replacementIndex]})
		}
	}
	return rows, foundTable
}

func parseSourcePage(spec sourceSpec, sourceURL string, body []byte, retrievedAt time.Time) (parsedPage, error) {
	if spec.adapter != "" {
		return parsedPage{}, errors.New("source requires its authenticated API adapter")
	}
	if validateSourceURL(spec, sourceURL) != nil {
		return parsedPage{}, errors.New("source URL is outside the fixed manifest")
	}
	if spec.provider == "alibaba" && sourceURL != spec.rootURL {
		return parseAlibabaBulletin(spec, sourceURL, body, retrievedAt)
	}
	text := extractVisibleText(string(body))
	title := extractPageTitle(string(body))
	headings := extractHeadings(string(body))
	if title == "" {
		return parsedPage{}, errors.New("source title missing")
	}
	page := parsedPage{Title: title}
	if len(linkRE.FindAllString(string(body), MaxParsedLinks+1)) > MaxParsedLinks {
		return parsedPage{}, errors.New("source has too many links")
	}
	if spec.maxChildren > 0 {
		if spec.id == "xai-grok-web-models" && sourceURL == spec.rootURL {
			page.Links = extractXAINewsLinks(sourceURL, string(body))
		} else {
			page.Links = extractLinks(sourceURL, string(body))
		}
	}
	addEvidence := func(e LifecycleEvidence) {
		e.SourceID, e.Provider, e.Scope, e.SourceURL, e.SourceTitle, e.RetrievedAt = spec.id, spec.provider, spec.scope, sourceURL, title, retrievedAt
		hash := sha256.Sum256(body)
		e.ContentSHA256 = hex.EncodeToString(hash[:])
		e.Excerpt = shortText(e.Excerpt, 360)
		page.Evidence = append(page.Evidence, e)
	}
	if spec.scope != "api" {
		if spec.catalog {
			available, err := parseProductAvailableModels(spec, sourceURL, string(body), text)
			if err != nil {
				return parsedPage{}, err
			}
			page.AvailableModelIDs = available
		}
		productEvidence, err := parseProductLifecycle(spec, sourceURL, body, text, retrievedAt)
		if err != nil {
			return parsedPage{}, err
		}
		for _, evidence := range productEvidence {
			addEvidence(evidence)
		}
		page.Evidence = normalizeEvidence(page.Evidence)
		return page, nil
	}
	switch spec.provider {
	case "openai":
		apiRows, hasAPIDeprecationTable := openAIDeprecationRows(string(body))
		if !strings.Contains(strings.ToLower(title), "deprecations") || !strings.Contains(text, "Upcoming deprecations") || !strings.Contains(text, "Past deprecations") || !hasAPIDeprecationTable {
			return parsedPage{}, errors.New("OpenAI page structure changed")
		}
		for _, row := range apiRows {
			if len(row) < 3 || !looksLikeDate(row[0]) || !validLifecycleModelCell(row[1]) {
				continue
			}
			effective := normalizeDate(row[0])
			status := "announced_deprecated"
			if parsed, err := parseAnyDate(effective); err == nil && parsed.Before(retrievedAt) {
				status = "retired"
			}
			replacementIDs := splitModelIDs(row[2])
			replacement := ""
			if len(replacementIDs) == 1 {
				replacement = replacementIDs[0]
			}
			for _, id := range splitModelIDs(row[1]) {
				addEvidence(LifecycleEvidence{ModelID: id, Status: status, EffectiveAt: effective, Replacement: replacement, Excerpt: strings.Join(row, " | ")})
			}
		}
	case "anthropic":
		if !strings.Contains(strings.ToLower(title), "model deprecations") || !tableHasHeaders(string(body), "API model name", "Current state", "Deprecated", "Tentative retirement date") {
			return parsedPage{}, errors.New("Anthropic page structure changed")
		}
		states := map[string][]LifecycleEvidence{}
		for _, row := range extractTableRows(string(body)) {
			if len(row) < 4 || !validModelID(strings.TrimSpace(row[0])) {
				continue
			}
			state := strings.ToLower(strings.TrimSpace(row[1]))
			status := map[string]string{"deprecated": "announced_deprecated", "retired": "retired", "legacy": "legacy"}[state]
			if status == "" {
				continue
			}
			e := LifecycleEvidence{ModelID: strings.TrimSpace(row[0]), Status: status, AnnouncedAt: normalizeDate(row[2]), EffectiveAt: normalizeDate(row[3]), Excerpt: strings.Join(row, " | ")}
			states[e.ModelID] = append(states[e.ModelID], e)
		}
		for _, row := range extractTableRows(string(body)) {
			if len(row) < 3 || !strings.Contains(strings.ToLower(strings.Join(row, " ")), "claude-") || !looksLikeDate(row[0]) {
				continue
			}
			for _, id := range splitModelIDs(row[1]) {
				stateEvidence := states[id]
				if len(stateEvidence) == 0 {
					status := "announced_deprecated"
					if parsed, err := parseAnyDate(normalizeDate(row[0])); err == nil && parsed.Before(retrievedAt) {
						status = "retired"
					}
					stateEvidence = []LifecycleEvidence{{ModelID: id, Status: status}}
				}
				for _, base := range stateEvidence {
					e := base
					if date := normalizeDate(row[0]); date != "" {
						e.EffectiveAt = date
					}
					e.Replacement = safeText(row[2])
					e.Excerpt = strings.Join(row, " | ")
					states[id] = append(states[id], e)
				}
			}
		}
		for _, records := range states {
			for _, e := range records {
				addEvidence(e)
			}
		}
	case "deepseek":
		if !strings.EqualFold(strings.TrimSpace(strings.TrimSuffix(title, "| DeepSeek API Docs")), "Change Log") || !regexp.MustCompile(`(?i)Date:\s*20\d{2}-\d{2}-\d{2}`).MatchString(text) {
			return parsedPage{}, errors.New("DeepSeek page structure changed")
		}
		for _, sentence := range splitSentences(text) {
			lower := strings.ToLower(sentence)
			if !containsAny(lower, "deprecated", "retired", "discontinued", "will be discontinued", "end of life", "sunset") {
				continue
			}
			ids := lifecycleSubjects(sentence, "deepseek-", "deprecated", "retired", "discontinued", "end of life", "sunset")
			if len(ids) == 0 {
				continue
			}
			status := "announced_deprecated"
			if strings.Contains(lower, "point to") || strings.Contains(lower, "routed to") || strings.Contains(lower, "redirect") {
				status = "retired_with_compatibility_route"
			} else if date := findDate(sentence); date != "" {
				if parsed, err := parseAnyDate(date); err == nil && parsed.Before(retrievedAt) {
					status = "retired"
				}
			}
			replacement := ""
			if index := firstIndex(lower, "point to", "routed to", "redirected to"); index >= 0 {
				for _, id := range filterModelIDs(modelTokenRE.FindAllString(sentence, -1), "deepseek-") {
					if strings.Index(strings.ToLower(sentence), strings.ToLower(id)) > index {
						replacement = id
						break
					}
				}
			}
			for _, id := range ids {
				addEvidence(LifecycleEvidence{ModelID: id, Status: status, EffectiveAt: findDate(sentence), Replacement: replacement, Excerpt: sentence})
			}
		}
	case "alibaba":
		if !strings.Contains(title, "模型下线机制说明") || !strings.Contains(text, "下线模型列表") || !dateCNRe.MatchString(text) || !containsAny(text, "将下线", "已下线") {
			return parsedPage{}, errors.New("Alibaba page structure changed")
		}
		for _, row := range extractTableRows(string(body)) {
			joined := strings.Join(row, " ")
			if !containsAny(joined, "将下线", "已下线", "下线") {
				continue
			}
			date := findDate(joined)
			for _, id := range extractAlibabaModelIDs(row) {
				status := "announced_deprecated"
				if strings.Contains(joined, "已下线") {
					status = "retired"
				}
				addEvidence(LifecycleEvidence{ModelID: id, Status: status, EffectiveAt: date, Excerpt: joined})
			}
		}
	case "xai":
		if sourceURL == spec.rootURL {
			if !strings.Contains(strings.ToLower(title), "release notes") || len(headings) < 2 || !hasMonthHeading(headings) || findDate(text) == "" {
				return parsedPage{}, errors.New("xAI release notes page structure changed")
			}
		} else if !hasHeadingContaining(headings, "migration") {
			return parsedPage{}, errors.New("xAI migration page structure changed")
		}
		sentences := splitSentences(extractXAIVisibleText(string(body)))
		lifecycle := make(map[string][]LifecycleEvidence)
		type routeRecord struct {
			replacement string
			excerpt     string
		}
		routes := make(map[string][]routeRecord)
		routeTargets := make(map[string]bool)
		for sentenceIndex, sentence := range sentences {
			lower := strings.ToLower(sentence)
			allIDs := filterModelIDs(modelTokenRE.FindAllString(sentence, -1), "grok-")
			if containsAny(lower, "deprecated", "retired", "end of life", "retirement") {
				ids := xaiLifecycleSubjects(sentence)
				status := "announced_deprecated"
				if date := findDate(sentence); date != "" {
					if parsed, err := parseAnyDate(date); err == nil && parsed.Before(retrievedAt) {
						status = "retired"
					}
				}
				for _, id := range ids {
					evidence := LifecycleEvidence{ModelID: id, Status: status, EffectiveAt: findDate(sentence), Excerpt: sentence}
					lifecycle[id] = append(lifecycle[id], evidence)
				}
			}
			if routeIndex := firstIndex(lower, "routed to", "served by", "redirected to", "in favor of"); routeIndex >= 0 {
				var sourceIDs, replacementIDs []string
				for _, id := range allIDs {
					idIndex := strings.Index(lower, strings.ToLower(id))
					if idIndex < routeIndex {
						sourceIDs = append(sourceIDs, id)
					} else if idIndex > routeIndex {
						replacementIDs = append(replacementIDs, id)
					}
				}
				if len(sourceIDs) == 0 && len(replacementIDs) > 0 && sentenceIndex > 0 {
					previous := sentences[sentenceIndex-1]
					for _, id := range xaiLifecycleSubjects(previous) {
						if len(lifecycle[id]) > 0 {
							sourceIDs = append(sourceIDs, id)
						}
					}
				}
				if len(replacementIDs) > 0 {
					for _, sourceID := range sourceIDs {
						routes[sourceID] = append(routes[sourceID], routeRecord{replacement: replacementIDs[0], excerpt: sentence})
						routeTargets[replacementIDs[0]] = true
					}
				}
			}
		}
		for id, records := range lifecycle {
			// Migration pages often mention a new target in the same section
			// that announces retirement of the old slug. The target is not itself
			// deprecated merely because it appears beside the retirement notice.
			// Preserve it only when the page also identifies it as a retired
			// source with its own compatibility route (a chained migration).
			if routeTargets[id] && len(routes[id]) == 0 {
				continue
			}
			for _, evidence := range records {
				if routeRecords := routes[id]; len(routeRecords) > 0 {
					for _, route := range routeRecords {
						routed := evidence
						if evidence.Status == "retired" {
							routed.Status = "retired_with_compatibility_route"
						}
						routed.Replacement = route.replacement
						routed.Excerpt += " " + route.excerpt
						addEvidence(routed)
					}
					continue
				}
				addEvidence(evidence)
			}
		}
	}
	page.Evidence = normalizeEvidence(page.Evidence)
	return page, nil
}

func parseProductLifecycle(spec sourceSpec, sourceURL string, body []byte, visibleText string, retrievedAt time.Time) ([]LifecycleEvidence, error) {
	title := extractPageTitle(string(body))
	if title == "" {
		return nil, errors.New("product source title missing")
	}
	switch spec.id {
	case "openai-codex-models":
		visibleText = productSourceVisibleText(spec, body, visibleText)
		lowerTitle := strings.ToLower(title)
		if spec.id == "openai-codex-models" && !strings.Contains(lowerTitle, "model") && !strings.Contains(strings.ToLower(visibleText), "codex") {
			return nil, errors.New("Codex model page structure changed")
		}
		if spec.id == "openai-cross-product-lifecycle-v2" && !strings.Contains(strings.ToLower(visibleText), "codex") {
			return nil, errors.New("Codex changelog structure changed")
		}
		return parseExactLifecycleMentions(visibleText, "gpt-", retrievedAt), nil
	case "openai-cross-product-lifecycle-v2":
		visibleText = productSourceVisibleText(spec, body, visibleText)
		if !strings.Contains(strings.ToLower(visibleText), "chatgpt") || !strings.Contains(strings.ToLower(visibleText), "codex") {
			return nil, errors.New("OpenAI cross-product lifecycle source structure changed")
		}
		var evidence []LifecycleEvidence
		for _, entry := range openAIChangelogEntry.FindAllStringSubmatch(string(body), -1) {
			if len(entry) != 3 {
				continue
			}
			products := openAIChangelogProducts.FindStringSubmatch(entry[1])
			if len(products) != 2 || !strings.Contains(strings.ToLower(products[1]), "codex") {
				continue
			}
			heading := openAIChangelogHeading.FindStringSubmatch(entry[2])
			if len(heading) != 2 {
				continue
			}
			text := extractVisibleText(heading[1])
			entryText := extractVisibleText(entry[2])
			if date := openAIChangelogFullDate.FindStringSubmatch(entryText); len(date) == 2 {
				text = strings.TrimSpace(openAIChangelogShortDate.ReplaceAllString(text, "")) + " effective on " + date[1]
			}
			lower := strings.ToLower(text)
			chatGPTProductExplicit := containsAny(lower, "chatgpt web", "chatgpt work", "chatgpt, chatgpt")
			if !chatGPTProductExplicit || !strings.Contains(lower, "codex") || !hasLifecycleLanguage(lower) {
				continue
			}
			evidence = append(evidence, parseExactLifecycleMentions(text, "gpt-", retrievedAt)...)
		}
		return normalizeEvidence(evidence), nil
	case "openai-chatgpt-models":
		visibleText = productSourceVisibleText(spec, body, visibleText)
		if !strings.Contains(strings.ToLower(visibleText), "other models in chatgpt") || !strings.Contains(strings.ToLower(visibleText), "choose a thinking level") {
			return nil, errors.New("ChatGPT model guide structure changed")
		}
		return nil, nil
	case "openai-chatgpt-gpt6-announcement":
		if !containsAny(strings.ToLower(visibleText), "chatgpt", "chat tab") || !strings.Contains(strings.ToLower(visibleText), "gpt") {
			return nil, errors.New("OpenAI GPT-6 ChatGPT launch page structure changed")
		}
		return nil, nil
	case "anthropic-claude-release-notes":
		if !strings.Contains(strings.ToLower(title), "release notes") && !strings.Contains(strings.ToLower(visibleText), "claude code") {
			return nil, errors.New("Claude release-notes page structure changed")
		}
		return parseClaudeProductLifecycle(visibleText, retrievedAt), nil
	case "anthropic-claude-code-models":
		if !strings.Contains(strings.ToLower(visibleText), "supported models") || !strings.Contains(strings.ToLower(visibleText), "claude code") {
			return nil, errors.New("Claude Code model configuration page structure changed")
		}
		return nil, nil
	case "anthropic-claude-web-models":
		if _, ok := extractHTMLHeadingSection(string(body), "Chatting with Claude", "Claude Code"); !ok {
			return nil, errors.New("Claude consumer model section structure changed")
		}
		return nil, nil
	case "kimi-code-models":
		if !strings.Contains(strings.ToLower(visibleText), "kimi code") && !strings.Contains(strings.ToLower(title), "kimi") {
			return nil, errors.New("Kimi Code model page structure changed")
		}
		return parseExactLifecycleMentions(visibleText, "kimi-", retrievedAt), nil
	case "kimi-web-models":
		if _, ok := extractHTMLHeadingSection(string(body), "Choose a model", "About Kimi K3"); !ok {
			return nil, errors.New("Kimi web model selector section structure changed")
		}
		return nil, nil
	case "kimi-code-whats-new":
		if !strings.Contains(strings.ToLower(visibleText), "kimi code") && !strings.Contains(strings.ToLower(title), "kimi") {
			return nil, errors.New("Kimi Code changelog structure changed")
		}
		return parseExactLifecycleMentions(visibleText, "kimi-", retrievedAt), nil
	case "xai-grok-web-models":
		return nil, nil
	default:
		return nil, errors.New("unknown product lifecycle source")
	}
}

func parseProductAvailableModels(spec sourceSpec, sourceURL, body, visibleText string) ([]string, error) {
	lower := strings.ToLower(visibleText)
	var section string
	switch spec.id {
	case "openai-codex-models":
		section = productSourceVisibleText(spec, []byte(body), visibleText)
		if !containsAny(strings.ToLower(section), "codex", "gpt") {
			return nil, errors.New("Codex model article is missing")
		}
		ids := filterModelIDs(modelTokenRE.FindAllString(section, -1), "gpt-")
		if len(ids) == 0 {
			return nil, errors.New("Codex current-model list is empty")
		}
		return ids, nil
	case "openai-chatgpt-models":
		section = productSourceVisibleText(spec, []byte(body), visibleText)
		lowerSection := strings.ToLower(section)
		end := strings.Index(lowerSection, "choose a thinking level")
		if !strings.Contains(lowerSection, "other models in chatgpt") || end < 0 {
			return nil, errors.New("ChatGPT signed-in model section is missing")
		}
		// This article's early section lists ChatGPT model choices. Later sections
		// separately document Work, Codex, and API availability and must not be
		// treated as web-selector evidence.
		section = section[:end]
		section = strings.NewReplacer("\u2010", "-", "\u2011", "-", "\u2012", "-", "\u2013", "-", "\u2014", "-", "\u2212", "-").Replace(section)
		ids := filterModelIDs(modelTokenRE.FindAllString(section, -1), "gpt-")
		if len(ids) == 0 {
			return nil, errors.New("ChatGPT current-model list is empty")
		}
		for i := range ids {
			ids[i] = strings.ToLower(ids[i])
		}
		return uniqueStrings(ids), nil
	case "openai-chatgpt-gpt6-announcement":
		lowerText := strings.ToLower(visibleText)
		if !containsAny(lowerText, "chatgpt", "chat tab") || !strings.Contains(lowerText, "gpt") {
			return nil, errors.New("OpenAI page does not establish a ChatGPT model launch")
		}
		modelText := strings.NewReplacer("\u2010", "-", "\u2011", "-", "\u2012", "-", "\u2013", "-", "\u2014", "-", "\u2212", "-").Replace(visibleText)
		ids := filterModelIDs(modelTokenRE.FindAllString(modelText, -1), "gpt-")
		foundGPT6 := false
		for index := range ids {
			ids[index] = strings.ToLower(ids[index])
			if ids[index] == "gpt-6" {
				foundGPT6 = true
			}
		}
		if !foundGPT6 {
			return nil, errors.New("OpenAI GPT-6 ChatGPT launch page has no exact GPT-6 family name")
		}
		return []string{"gpt-6"}, nil
	case "anthropic-claude-code-models":
		start := strings.Index(lower, "supported models")
		end := strings.Index(lower, "change model for current session only")
		if start < 0 || end <= start {
			return nil, errors.New("Claude Code supported-model section is missing")
		}
		section = visibleText[start:end]
		ids := filterModelIDs(modelTokenRE.FindAllString(section, -1), "claude-")
		if len(ids) == 0 {
			return nil, errors.New("Claude Code supported-model list is empty")
		}
		return ids, nil
	case "anthropic-claude-web-models":
		section, ok := extractHTMLHeadingSection(body, "Chatting with Claude", "Claude Code")
		if !ok || !tableHasHeaders(section, "Model", "Context window") {
			return nil, errors.New("Claude consumer model table is missing")
		}
		ids := make([]string, 0)
		for _, row := range extractTableRows(section) {
			if len(row) < 2 || strings.EqualFold(strings.TrimSpace(row[0]), "Model") {
				continue
			}
			if id := claudeConsumerModelAliases[strings.ToLower(strings.TrimSpace(row[0]))]; id != "" {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			return nil, errors.New("Claude consumer model names have no reviewed ID aliases")
		}
		return uniqueStrings(ids), nil
	case "kimi-code-models":
		for _, row := range extractTableRows(body) {
			if len(row) < 2 || !strings.EqualFold(strings.TrimSpace(row[0]), "Model ID") {
				continue
			}
			ids := make([]string, 0, len(row)-1)
			for _, cell := range row[1:] {
				id := strings.TrimSpace(cell)
				if !validModelID(id) {
					return nil, errors.New("Kimi Code model table contains an invalid model ID")
				}
				ids = append(ids, id)
			}
			if len(ids) == 0 {
				return nil, errors.New("Kimi Code current-model list is empty")
			}
			return uniqueStrings(ids), nil
		}
		return nil, errors.New("Kimi Code Model ID table is missing")
	case "kimi-web-models":
		section, ok := extractHTMLHeadingSection(body, "Choose a model", "About Kimi K3")
		if !ok || !tableHasHeaders(section, "Model", "Thinking strength", "Best for") {
			return nil, errors.New("Kimi web model selector table is missing")
		}
		ids := make([]string, 0)
		for _, row := range extractTableRows(section) {
			if len(row) == 0 || strings.EqualFold(strings.TrimSpace(row[0]), "Model") {
				continue
			}
			if id := kimiWebModelAliases[strings.ToLower(strings.TrimSpace(row[0]))]; id != "" {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			return nil, errors.New("Kimi web model names have no reviewed ID aliases")
		}
		return uniqueStrings(ids), nil
	case "xai-grok-web-models":
		if strings.TrimSpace(extractPageTitle(body)) == "" {
			return nil, errors.New("xAI news page title is missing")
		}
		// The seeded official announcement and its linked articles contribute
		// only exact IDs or a reviewed display-name alias when the same text line
		// explicitly says the model is on grok.com.
		text := extractXAIVisibleText(body)
		ids := make([]string, 0)
		for _, line := range textLines(text) {
			lowerLine := strings.ToLower(line)
			if !xaiConsumerWebAvailabilityClaim(lowerLine) {
				continue
			}
			ids = append(ids, filterModelIDs(modelTokenRE.FindAllString(line, -1), "grok-")...)
			for display, id := range xaiGrokWebModelAliases {
				if strings.Contains(lowerLine, display) {
					ids = append(ids, id)
				}
			}
		}
		if sourceURL == spec.rootURL && len(ids) == 0 {
			return nil, errors.New("seeded xAI Grok web announcement no longer contains a recognized model claim")
		}
		return uniqueStrings(ids), nil
	default:
		return nil, errors.New("unknown official product model catalog")
	}
}

var (
	claudeConsumerModelAliases = map[string]string{
		"claude fable 5.1":  "claude-fable-5-1",
		"claude fable 5":    "claude-fable-5",
		"claude opus 5.5":   "claude-opus-5-5",
		"claude opus 5":     "claude-opus-5",
		"claude opus 4.8":   "claude-opus-4-8",
		"claude opus 4.7":   "claude-opus-4-7",
		"claude opus 4.6":   "claude-opus-4-6",
		"claude sonnet 5.5": "claude-sonnet-5-5",
		"claude sonnet 5":   "claude-sonnet-5",
		"claude sonnet 4.6": "claude-sonnet-4-6",
		"claude haiku 5.5":  "claude-haiku-5-5",
	}
	kimiWebModelAliases = map[string]string{
		"k3": "k3",
	}
	xaiGrokWebModelAliases = map[string]string{
		"grok 4.5": "grok-4.5",
	}
)

func xaiConsumerWebAvailabilityClaim(lowerLine string) bool {
	return strings.Contains(lowerLine, "grok.com") && containsAny(lowerLine,
		"now on grok.com", "is now on grok.com", "live today on grok.com", "live on grok.com",
		"available on grok.com", "available to all users on grok.com")
}

func extractHTMLHeadingSection(source, startHeading, endHeading string) (string, bool) {
	matches := headingRE.FindAllStringSubmatchIndex(source, -1)
	start := -1
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		heading := cleanFragment(source[match[2]:match[3]])
		if start < 0 {
			if strings.EqualFold(heading, startHeading) {
				start = match[1]
			}
			continue
		}
		if strings.EqualFold(heading, endHeading) {
			return source[start:match[0]], true
		}
	}
	return "", false
}

func productSourceVisibleText(spec sourceSpec, body []byte, fallback string) string {
	if spec.id != "openai-codex-models" && spec.id != "openai-chatgpt-models" {
		return fallback
	}
	match := mainArticleRE.FindSubmatch(body)
	if len(match) == 2 {
		return extractVisibleText(string(match[1]))
	}
	return fallback
}

func parseExactLifecycleMentions(text, prefix string, retrievedAt time.Time) []LifecycleEvidence {
	var evidence []LifecycleEvidence
	for _, sentence := range splitSentences(text) {
		lower := strings.ToLower(sentence)
		if !hasLifecycleLanguage(lower) {
			continue
		}
		ids := filterModelIDs(modelTokenRE.FindAllString(sentence, -1), prefix)
		if prefix == "kimi-" {
			ids = append(ids, kimiCodeIDsMentioned(sentence)...)
		}
		ids = lifecycleProductSubjects(sentence, uniqueStrings(ids))
		if len(ids) == 0 {
			continue
		}
		for _, id := range uniqueStrings(ids) {
			status, effective := lifecycleStatusInContext(lower, retrievedAt)
			evidence = append(evidence, LifecycleEvidence{ModelID: id, Status: status, EffectiveAt: effective, Excerpt: sentence})
		}
	}
	return normalizeEvidence(evidence)
}

func parseClaudeProductLifecycle(text string, retrievedAt time.Time) []LifecycleEvidence {
	var evidence []LifecycleEvidence
	for _, sentence := range splitSentences(text) {
		lower := strings.ToLower(sentence)
		if !hasLifecycleLanguage(lower) || !containsAny(lower, "claude", "claude code") {
			continue
		}
		status, effective := lifecycleStatusInContext(lower, retrievedAt)
		ids := filterModelIDs(modelTokenRE.FindAllString(sentence, -1), "claude-")
		if len(ids) == 0 {
			// The official release note names the Claude products but uses display
			// family names, while the official Anthropic API catalog supplies the
			// exact stable IDs. This narrow crosswalk intentionally covers only
			// those two exact families; it does not infer by fuzzy prefix matching.
			ids = append(ids, claudeDisplayLifecycleSubjects(sentence)...)
		} else {
			ids = lifecycleProductSubjects(sentence, uniqueStrings(ids))
		}
		for _, id := range uniqueStrings(ids) {
			evidence = append(evidence, LifecycleEvidence{ModelID: id, Status: status, EffectiveAt: effective, Excerpt: sentence})
		}
	}
	return normalizeEvidence(evidence)
}

func kimiCodeIDsMentioned(sentence string) []string {
	pattern := regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_-])(kimi-for-coding-highspeed|kimi-for-coding|k3-256k|k3)(?:$|[^A-Za-z0-9_-])`)
	ids := make([]string, 0)
	for _, match := range pattern.FindAllStringSubmatch(sentence, -1) {
		if len(match) == 2 {
			ids = append(ids, strings.ToLower(match[1]))
		}
	}
	return uniqueStrings(ids)
}

// lifecycleProductSubjects narrows product lifecycle evidence to the model IDs
// that the sentence grammatically identifies as lifecycle subjects. Product
// notices often mention a successor alongside the retiring model; treating all
// IDs in the sentence as equivalent can incorrectly retire the successor.
type modelMention struct {
	id  string
	at  int
	end int
}

func lifecycleProductSubjects(sentence string, ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	lower := strings.ToLower(sentence)
	mentions := make([]modelMention, 0, len(ids))
	for _, id := range uniqueStrings(ids) {
		at := strings.Index(lower, strings.ToLower(id))
		if at >= 0 {
			mentions = append(mentions, modelMention{id: id, at: at, end: at + len(id)})
		}
	}
	selected := lifecycleProductMentions(sentence, mentions)
	idsOut := make([]string, 0, len(selected))
	for _, mention := range selected {
		idsOut = append(idsOut, mention.id)
	}
	return uniqueStrings(idsOut)
}

func lifecycleProductMentions(sentence string, mentions []modelMention) []modelMention {
	lower := strings.ToLower(sentence)
	if len(mentions) == 0 {
		return nil
	}
	anchor := firstIndex(lower, "retired", "retires", "retirement", "removed from", "no longer available", "discontinued", "deprecated", "end of life")
	if anchor < 0 {
		return nil
	}
	replacementTargets := make(map[int]bool)
	for _, marker := range []string{"replaced by", "replaced with", "superseded by", "succeeded by", "replacement is", "replacement ", "successor is", "successor "} {
		if at := strings.Index(lower, marker); at >= 0 {
			if index := nearestMentionAfter(lower, mentions, at+len(marker)); index >= 0 {
				replacementTargets[mentions[index].at] = true
			}
		}
	}
	for _, marker := range []string{" replaces ", " replacing ", " supersedes ", " superseding ", " instead of "} {
		if at := strings.Index(lower, marker); at >= 0 {
			if index := nearestMentionBefore(lower, mentions, at); index >= 0 {
				replacementTargets[mentions[index].at] = true
			}
		}
	}
	filtered := make([]modelMention, 0, len(mentions))
	for _, mention := range mentions {
		if !replacementTargets[mention.at] {
			filtered = append(filtered, mention)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	before := make([]modelMention, 0, len(filtered))
	for _, mention := range filtered {
		if mention.at < anchor && anchor-mention.at <= 120 {
			before = append(before, mention)
		}
	}
	if len(before) > 0 {
		sort.Slice(before, func(i, j int) bool { return before[i].at < before[j].at })
		last := before[len(before)-1]
		if anchor-last.at > 120 {
			return nil
		}
		subjects := []modelMention{last}
		for i := len(before) - 2; i >= 0; i-- {
			previous := before[i]
			between := lower[previous.end:last.at]
			if !onlyModelListSeparators(between) {
				break
			}
			subjects = append(subjects, previous)
			last = previous
		}
		return subjects
	}
	// Only accept IDs after the lifecycle verb when the sentence explicitly
	// introduces a subject list or a retirement-of heading. Otherwise a
	// successor mentioned after the retired model could be mistaken for the
	// subject of the notice.
	if strings.Contains(lower, "retirement of") || strings.Contains(lower, "retirement for") || strings.Contains(lower, "following model") || strings.Contains(lower, "following models") || strings.Contains(lower, "retired models:") || strings.Contains(lower, "deprecated models:") || strings.Contains(lower, "models removed:") || strings.Contains(lower, " instead of ") {
		var after []modelMention
		for _, mention := range filtered {
			if mention.at >= anchor && mention.at-anchor <= 120 {
				after = append(after, mention)
			}
		}
		if len(after) > 0 {
			sort.Slice(after, func(i, j int) bool { return after[i].at < after[j].at })
			return contiguousModelMentions(lower, after)
		}
	}
	return nil
}

func nearestMentionAfter(text string, mentions []modelMention, markerEnd int) int {
	best := -1
	for i, mention := range mentions {
		if mention.at < markerEnd {
			continue
		}
		between := text[markerEnd:mention.at]
		if len(between) > 100 || strings.ContainsAny(between, ".;,:?!") {
			continue
		}
		if best < 0 || mention.at < mentions[best].at {
			best = i
		}
	}
	return best
}

func nearestMentionBefore(text string, mentions []modelMention, markerAt int) int {
	best := -1
	for i, mention := range mentions {
		if mention.end > markerAt {
			continue
		}
		between := text[mention.end:markerAt]
		if len(between) > 100 || strings.ContainsAny(between, ".;,:?!") {
			continue
		}
		if best < 0 || mention.at > mentions[best].at {
			best = i
		}
	}
	return best
}

func onlyModelListSeparators(text string) bool {
	text = regexp.MustCompile(`(?i)\b(?:and|or)\b`).ReplaceAllString(text, "")
	text = strings.NewReplacer(",", "", ";", "", "&", "", "、", "", "，", "", "；", "").Replace(text)
	return strings.TrimSpace(text) == ""
}

func contiguousModelMentions(text string, mentions []modelMention) []modelMention {
	if len(mentions) == 0 {
		return nil
	}
	subjects := []modelMention{mentions[0]}
	last := mentions[0]
	for i := 1; i < len(mentions); i++ {
		current := mentions[i]
		between := text[last.end:current.at]
		if !onlyModelListSeparators(between) {
			break
		}
		subjects = append(subjects, current)
		last = current
	}
	return subjects
}

func claudeDisplayLifecycleSubjects(sentence string) []string {
	var mentions []modelMention
	opus41 := regexp.MustCompile(`(?i)\bopus\s+4\.1\b`)
	for _, span := range opus41.FindAllStringIndex(sentence, -1) {
		mentions = append(mentions, modelMention{id: "claude-opus-4-1-20250805", at: span[0], end: span[1]})
	}
	withoutOpus41 := opus41.ReplaceAllStringFunc(sentence, func(value string) string { return strings.Repeat(" ", len(value)) })
	opus4 := regexp.MustCompile(`(?i)\bopus\s+4\b`)
	for _, span := range opus4.FindAllStringIndex(withoutOpus41, -1) {
		// A word boundary after "4" also matches the start of a decimal
		// version such as Opus 4.5. Do not crosswalk those distinct models to
		// the exact Opus 4 ID.
		if span[1]+1 < len(withoutOpus41) && withoutOpus41[span[1]] == '.' && withoutOpus41[span[1]+1] >= '0' && withoutOpus41[span[1]+1] <= '9' {
			continue
		}
		mentions = append(mentions, modelMention{id: "claude-opus-4-20250514", at: span[0], end: span[1]})
	}
	if len(mentions) == 0 {
		return nil
	}
	selected := lifecycleProductMentions(sentence, mentions)
	ids := make([]string, 0, len(selected))
	for _, mention := range selected {
		ids = append(ids, mention.id)
	}
	return uniqueStrings(ids)
}

func hasLifecycleLanguage(lower string) bool {
	return containsAny(lower, "retired", "retires", "retirement", "removed from", "no longer available", "discontinued", "deprecated", "end of life")
}

func lifecycleEffectiveDate(lower string, actionEnd int) string {
	if actionEnd < 0 || actionEnd > len(lower) {
		return ""
	}
	type dateSpan struct{ start, end int }
	var spans []dateSpan
	for _, re := range []*regexp.Regexp{dateISORe, dateUSRe, dateCNRe} {
		for _, span := range re.FindAllStringIndex(lower, -1) {
			spans = append(spans, dateSpan{start: span[0], end: span[1]})
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for _, span := range spans {
		if span.start < actionEnd || span.start-actionEnd > 80 {
			continue
		}
		between := strings.TrimSpace(lower[actionEnd:span.start])
		if strings.ContainsAny(between, ".;!?\n") {
			continue
		}
		if between != "" && !regexp.MustCompile(`(?i)\b(?:on|by|effective(?:\s+on)?|from|starting|as of|at|for|scheduled for|planned for|date(?:d)?(?:\s+of)?|to take effect on)\s*$`).MatchString(between) {
			continue
		}
		if date := normalizeDate(lower[span.start:span.end]); date != "" {
			return date
		}
	}
	return ""
}

func lifecycleStatusInContext(lower string, retrievedAt time.Time) (string, string) {
	if containsAny(lower, "not sooner than", "not earlier than", "no sooner than") {
		return "legacy", ""
	}
	if regexp.MustCompile(`\bnot\s+(?:be\s+)?(?:retired|removed|deprecated|discontinued)\b`).MatchString(lower) {
		return "legacy", ""
	}
	futureRetirementRe := regexp.MustCompile(`\b(?:will|scheduled to|planned to|expected to|set to)\b.{0,60}\b(?:retire|retires|retired|be\s+retired|be\s+removed|be\s+discontinued|end of life)\b`)
	futureRetirementMatch := futureRetirementRe.FindStringIndex(lower)
	futureDeprecationMatch := regexp.MustCompile(`\b(?:will|scheduled to|planned to|expected to|set to)\b.{0,60}\b(?:deprecate|deprecated)\b`).FindStringIndex(lower)
	if futureDeprecationMatch != nil && futureRetirementMatch == nil {
		return "announced_deprecated", lifecycleEffectiveDate(lower, futureDeprecationMatch[1])
	}
	retirementActionEnd := -1
	if futureRetirementMatch != nil {
		retirementActionEnd = futureRetirementMatch[1]
	} else {
		for _, action := range []string{"retired", "retires", "retirement", "removed from", "no longer available", "discontinued", "end of life"} {
			if at := strings.Index(lower, action); at >= 0 {
				end := at + len(action)
				if retirementActionEnd < 0 || end < retirementActionEnd {
					retirementActionEnd = end
				}
			}
		}
	}
	effective := lifecycleEffectiveDate(lower, retirementActionEnd)
	var effectiveDay time.Time
	if effective != "" {
		if parsed, err := parseAnyDate(effective); err == nil {
			effectiveDay = time.Date(parsed.Year(), parsed.Month(), parsed.Day(), 0, 0, 0, 0, time.UTC)
			today := retrievedAt.UTC()
			currentDay := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
			if effectiveDay.After(currentDay) {
				return "announced_deprecated", effective
			}
		}
	}
	if futureRetirementMatch != nil {
		if !effectiveDay.IsZero() {
			// A dated planned retirement has taken effect once its date is today
			// or earlier. A date attached only to "deprecated" is not enough.
			return "retired", effective
		}
		return "announced_deprecated", effective
	}
	if strings.Contains(lower, "retires") {
		if !effectiveDay.IsZero() {
			return "retired", effective
		}
		return "announced_deprecated", effective
	}
	hardRetired := containsAny(lower, "retired", "removed from", "were removed", "was removed", "has been removed", "no longer available", "discontinued", "end of life")
	if hardRetired {
		return "retired", effective
	}
	if strings.Contains(lower, "deprecated") {
		return "deprecated", effective
	}
	return "announced_deprecated", effective
}

func extractVisibleText(source string) string {
	source = scriptRE.ReplaceAllString(source, " ")
	source = regexp.MustCompile(`(?i)</(h[1-6]|p|tr|td|th|li|section|article|br|div|summary)>`).ReplaceAllString(source, "\n")
	source = tagRE.ReplaceAllString(source, " ")
	source = html.UnescapeString(source)
	return strings.TrimSpace(spaceRE.ReplaceAllString(source, " "))
}

func extractXAIVisibleText(source string) string {
	metaText := make([]string, 0, 2)
	for _, tag := range metaTagRE.FindAllString(source, -1) {
		nameMatch := metaNameRE.FindStringSubmatch(tag)
		if len(nameMatch) != 2 {
			continue
		}
		name := strings.ToLower(nameMatch[1])
		if name != "description" && name != "og:description" {
			continue
		}
		if match := metaContentRE.FindStringSubmatch(tag); len(match) == 2 {
			metaText = append(metaText, html.UnescapeString(match[1]))
		}
	}
	source = scriptRE.ReplaceAllString(source, " ")
	source = regexp.MustCompile(`(?i)</(title|h[1-6]|p|tr|td|th|li|section|article|br|div|summary)>`).ReplaceAllString(source, "\n")
	source = tagRE.ReplaceAllString(source, " ")
	lines := strings.Split(html.UnescapeString(source), "\n")
	lines = append(lines, metaText...)
	for i := range lines {
		lines[i] = strings.TrimSpace(spaceRE.ReplaceAllString(lines[i], " "))
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func extractPageTitle(source string) string {
	if match := h1RE.FindStringSubmatch(source); len(match) == 2 {
		if title := cleanFragment(match[1]); title != "" {
			return shortText(title, 200)
		}
	}
	if match := titleRE.FindStringSubmatch(source); len(match) == 2 {
		return shortText(cleanFragment(match[1]), 200)
	}
	return ""
}

func extractHeadings(source string) []string {
	out := make([]string, 0)
	for _, match := range headingRE.FindAllStringSubmatch(source, -1) {
		if len(match) == 2 {
			if heading := cleanFragment(match[1]); heading != "" {
				out = append(out, heading)
			}
		}
	}
	return out
}

func hasMonthHeading(headings []string) bool {
	for _, heading := range headings {
		if monthDayRe.MatchString(heading) || regexp.MustCompile(`(?i)\b(January|February|March|April|May|June|July|August|September|October|November|December)\b`).MatchString(heading) {
			return true
		}
	}
	return false
}

func hasHeadingContaining(headings []string, token string) bool {
	for _, heading := range headings {
		if strings.Contains(strings.ToLower(heading), strings.ToLower(token)) {
			return true
		}
	}
	return false
}

func extractTableRows(source string) [][]string {
	rows := make([][]string, 0)
	for _, row := range rowRE.FindAllStringSubmatch(source, -1) {
		cells := make([]string, 0)
		for _, cell := range cellRE.FindAllStringSubmatch(row[1], -1) {
			cells = append(cells, cleanFragment(cell[1]))
		}
		if len(cells) > 0 {
			rows = append(rows, cells)
		}
	}
	return rows
}

func tableHasHeaders(source string, wanted ...string) bool {
	for _, row := range extractTableRows(source) {
		joined := strings.ToLower(strings.Join(row, " | "))
		all := true
		for _, header := range wanted {
			if !strings.Contains(joined, strings.ToLower(header)) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func extractLinks(base, source string) []string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil
	}
	set := make(map[string]bool)
	for _, link := range linkRE.FindAllStringSubmatch(source, -1) {
		if len(link) != 3 {
			continue
		}
		href := html.UnescapeString(strings.TrimSpace(link[1]))
		parsed, err := url.Parse(href)
		if err != nil {
			continue
		}
		resolved := baseURL.ResolveReference(parsed)
		set[resolved.String()] = true
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

// extractXAINewsLinks keeps the archive's DOM order so the bounded crawl sees
// the newest announcements first. Only same-site, single-segment news posts
// can become child fetches.
func extractXAINewsLinks(base, source string) []string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	links := make([]string, 0)
	for _, match := range linkRE.FindAllStringSubmatch(source, -1) {
		if len(match) != 3 {
			continue
		}
		href := html.UnescapeString(strings.TrimSpace(match[1]))
		parsed, err := url.Parse(href)
		if err != nil {
			continue
		}
		resolved := baseURL.ResolveReference(parsed)
		if resolved.Scheme != "https" || resolved.Host != "x.ai" || resolved.User != nil || resolved.Port() != "" || resolved.RawQuery != "" || resolved.ForceQuery || resolved.Fragment != "" || !xaiNewsPath.MatchString(resolved.Path) {
			continue
		}
		value := resolved.String()
		if !seen[value] {
			seen[value] = true
			links = append(links, value)
		}
	}
	return links
}

func cleanFragment(s string) string {
	s = tagRE.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = strings.TrimSpace(spaceRE.ReplaceAllString(s, " "))
	return s
}

func splitModelIDs(cell string) []string {
	ids := make([]string, 0)
	for _, chunk := range strings.FieldsFunc(cell, func(r rune) bool { return r == '|' || r == ',' || r == ';' || r == '\n' }) {
		chunk = strings.TrimSpace(chunk)
		if validModelID(chunk) && modelTokenRE.MatchString(chunk) {
			ids = append(ids, chunk)
		}
	}
	return uniqueStrings(ids)
}

func validLifecycleModelCell(s string) bool { return len(splitModelIDs(s)) > 0 }

func filterModelIDs(ids []string, prefix string) []string {
	out := make([]string, 0)
	for _, id := range ids {
		id = strings.Trim(strings.TrimSpace(id), "`*_()[]{}.,;:")
		if strings.HasPrefix(strings.ToLower(id), prefix) && validModelID(id) {
			out = append(out, id)
		}
	}
	return uniqueStrings(out)
}

func lifecycleSubjects(sentence, prefix string, markers ...string) []string {
	all := filterModelIDs(modelTokenRE.FindAllString(sentence, -1), prefix)
	lower := strings.ToLower(sentence)
	anchor := firstIndex(lower, markers...)
	if anchor < 0 {
		return all
	}
	subjects := make([]string, 0, len(all))
	for _, id := range all {
		at := strings.Index(lower, strings.ToLower(id))
		if at >= 0 && at < anchor {
			subjects = append(subjects, id)
		}
	}
	if len(subjects) == 0 {
		// Some notices lead with the lifecycle term ("Retirement of model-x").
		for _, id := range all {
			at := strings.Index(lower, strings.ToLower(id))
			if at >= anchor && at-anchor < 80 {
				subjects = append(subjects, id)
				break
			}
		}
	}
	return uniqueStrings(subjects)
}

func xaiLifecycleSubjects(sentence string) []string {
	ids := filterModelIDs(modelTokenRE.FindAllString(sentence, -1), "grok-")
	if len(ids) == 0 {
		return nil
	}
	lower := strings.ToLower(sentence)
	anchor := firstIndex(lower, "deprecated", "retired", "end of life", "retirement")
	if anchor < 0 {
		return nil
	}
	var before []string
	for _, id := range ids {
		if at := strings.Index(lower, strings.ToLower(id)); at >= 0 && at < anchor {
			before = append(before, id)
		}
	}
	if len(before) > 0 {
		return uniqueStrings(before)
	}
	// xAI sometimes states a retirement first and then gives an explicit list.
	// Accept only that unambiguous list wording; a model named later in a pricing
	// or migration sentence is a replacement target, not a lifecycle subject.
	listStart := firstIndex(lower, "following models will be retired", "following model will be retired", "these models will be retired")
	if listStart >= 0 {
		end := len(sentence)
		if routeAt := firstIndex(lower, "routed to", "redirected to", "served by", "in favor of", "billed at"); routeAt > listStart && routeAt < end {
			end = routeAt
		}
		listText := sentence[listStart:end]
		return filterModelIDs(modelTokenRE.FindAllString(listText, -1), "grok-")
	}
	// Also accept a direct construction such as “retirement of grok-model”.
	retirementOf := strings.Index(lower, "retirement of ")
	if retirementOf >= 0 {
		for _, id := range ids {
			at := strings.Index(lower, strings.ToLower(id))
			if at >= retirementOf+len("retirement of ") && at-retirementOf < 48 {
				return []string{id}
			}
		}
	}
	return nil
}

func extractAlibabaModelIDs(parts []string) []string {
	joined := strings.Join(parts, " ")
	allowed := []string{"qwen", "deepseek", "glm", "kimi", "wanx", "paraformer", "cosyvoice", "sambert", "tongyi", "qwq", "qvq", "qwen-vl", "qwen-audio", "gte"}
	ids := make([]string, 0)
	for _, token := range modelTokenRE.FindAllString(joined, -1) {
		low := strings.ToLower(token)
		for _, prefix := range allowed {
			if strings.HasPrefix(low, prefix) && validModelID(token) {
				ids = append(ids, token)
				break
			}
		}
	}
	return uniqueStrings(ids)
}

func normalizeEvidence(evidence []LifecycleEvidence) []LifecycleEvidence {
	byKey := make(map[string]LifecycleEvidence)
	for _, item := range evidence {
		item.ModelID = strings.TrimSpace(item.ModelID)
		if !validModelID(item.ModelID) || !validLifecycleStatus(item.Status) {
			continue
		}
		key := strings.Join([]string{item.SourceID, item.Scope, item.Provider, item.ModelID, item.Status, item.AnnouncedAt, item.EffectiveAt, item.Replacement, item.SourceURL}, "\x00")
		if _, exists := byKey[key]; !exists {
			byKey[key] = item
		}
	}
	out := make([]LifecycleEvidence, 0, len(byKey))
	for _, item := range byKey {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceID != out[j].SourceID {
			return out[i].SourceID < out[j].SourceID
		}
		if out[i].ModelID != out[j].ModelID {
			return out[i].ModelID < out[j].ModelID
		}
		if out[i].Status != out[j].Status {
			return out[i].Status < out[j].Status
		}
		if out[i].SourceURL != out[j].SourceURL {
			return out[i].SourceURL < out[j].SourceURL
		}
		if out[i].EffectiveAt != out[j].EffectiveAt {
			return out[i].EffectiveAt < out[j].EffectiveAt
		}
		if out[i].AnnouncedAt != out[j].AnnouncedAt {
			return out[i].AnnouncedAt < out[j].AnnouncedAt
		}
		if out[i].Replacement != out[j].Replacement {
			return out[i].Replacement < out[j].Replacement
		}
		return out[i].ContentSHA256 < out[j].ContentSHA256
	})
	return out
}

func validLifecycleStatus(status string) bool {
	switch status {
	case "announced_deprecated", "deprecated", "retired", "retired_with_compatibility_route", "legacy":
		return true
	default:
		return false
	}
}

func containsAny(value string, choices ...string) bool {
	for _, choice := range choices {
		if strings.Contains(strings.ToLower(value), strings.ToLower(choice)) {
			return true
		}
	}
	return false
}

func looksLikeDate(s string) bool { return findDate(s) != "" }

func normalizeDate(s string) string {
	if match := dateISORe.FindString(s); match != "" {
		return match
	}
	if match := dateUSRe.FindStringSubmatch(s); len(match) == 4 {
		if parsed, err := time.Parse("January 2, 2006", strings.Title(strings.ToLower(match[1])+" "+match[2]+", "+match[3])); err == nil {
			return parsed.Format("2006-01-02")
		}
	}
	if match := dateCNRe.FindStringSubmatch(s); len(match) == 4 {
		parsed, err := time.Parse("2006-1-2", fmt.Sprintf("%s-%s-%s", match[1], match[2], match[3]))
		if err == nil {
			return parsed.Format("2006-01-02")
		}
	}
	return ""
}

func findDate(s string) string {
	if date := dateISORe.FindString(s); date != "" {
		return date
	}
	if date := normalizeDate(s); date != "" {
		return date
	}
	if match := monthDayRe.FindStringSubmatch(s); len(match) == 3 {
		return match[1] + " " + match[2]
	}
	return ""
}

func parseAnyDate(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02", "January 2, 2006", "January 2 2006"} {
		if parsed, err := time.Parse(layout, s); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, errors.New("date is not a full date")
}

func splitSentences(text string) []string {
	text = strings.ReplaceAll(text, "\u200b", " ")
	parts := regexp.MustCompile(`(?i)[.!?]\s+|\n+`).Split(text, -1)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func textLines(text string) []string {
	return regexp.MustCompile(`\n+`).Split(text, -1)
}

func shortText(s string, max int) string {
	s = strings.TrimSpace(spaceRE.ReplaceAllString(s, " "))
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func safeText(s string) string {
	s = strings.TrimSpace(spaceRE.ReplaceAllString(s, " "))
	if strings.EqualFold(s, "n/a") || strings.EqualFold(s, "none") || s == "—" {
		return ""
	}
	return shortText(s, 240)
}

func safeHeader(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 || strings.ContainsAny(s, "\r\n") {
		return ""
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstIndex(value string, choices ...string) int {
	best := -1
	for _, choice := range choices {
		if index := strings.Index(value, choice); index >= 0 && (best < 0 || index < best) {
			best = index
		}
	}
	return best
}

func isRedirect(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

func snapshotDigest(pages []CachedPage) (string, error) {
	parts := make([]string, 0, len(pages))
	for _, page := range pages {
		if page.URL == "" || page.ContentSHA256 == "" || page.Title == "" || page.FetchedAt.IsZero() {
			return "", errors.New("invalid page snapshot")
		}
		available := append([]string{}, page.AvailableModelIDs...)
		sort.Strings(available)
		pagination := ""
		if page.CatalogTotal != 0 || page.CatalogPageNo != 0 || page.CatalogPageSize != 0 {
			pagination = fmt.Sprintf("\x00%d\x00%d\x00%d", page.CatalogTotal, page.CatalogPageNo, page.CatalogPageSize)
		}
		parts = append(parts, page.URL+"\x00"+page.ContentSHA256+"\x00"+strings.Join(available, "\x00")+pagination)
	}
	sort.Strings(parts)
	hash := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(hash[:]), nil
}

func failureCode(err error) string {
	var failure fetchFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	return "source_parse_error"
}
