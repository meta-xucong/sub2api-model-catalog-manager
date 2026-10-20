package officialcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxModelStudioAPIKey = 4096
	modelStudioPageSize  = 200
)

func validateModelStudioAPIKey(apiKey string) error {
	if apiKey == "" {
		return errors.New("credential_not_configured")
	}
	if len(apiKey) > maxModelStudioAPIKey || strings.TrimSpace(apiKey) != apiKey || !strings.HasPrefix(apiKey, "sk-ws-") || strings.ContainsAny(apiKey, "\r\n\x00") {
		return errors.New("credential_format_invalid")
	}
	return nil
}

func fetchAlibabaModelStudioCatalog(ctx context.Context, spec sourceSpec, apiKey string, doer HTTPDoer, budget *requestBudget, now func() time.Time) (CatalogSnapshot, error) {
	if ctx == nil || doer == nil || budget == nil || spec.adapter != "alibaba_model_studio" {
		return CatalogSnapshot{}, fetchFailure{code: "source_fetch_unavailable"}
	}
	if err := validateModelStudioAPIKey(apiKey); err != nil {
		return CatalogSnapshot{}, fetchFailure{code: err.Error()}
	}
	baseURL, err := url.Parse(spec.rootURL)
	if err != nil || baseURL.Scheme != "https" || baseURL.Host != "ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com" || baseURL.Path != "/api/v1/models" || baseURL.Query().Get("page_no") != "1" || baseURL.Query().Get("page_size") != "200" || len(baseURL.Query()) != 2 {
		return CatalogSnapshot{}, fetchFailure{code: "source_url_rejected"}
	}
	if now == nil {
		now = time.Now
	}
	fetchedAt := now().UTC()
	models := make([]string, 0)
	pages := make([]CachedPage, 0, 1)
	seen := make(map[string]bool)
	total, pageSize := -1, -1
	for pageNo := 1; ; pageNo++ {
		requestURL := *baseURL
		query := url.Values{}
		query.Set("page_no", strconv.Itoa(pageNo))
		query.Set("page_size", strconv.Itoa(modelStudioPageSize))
		requestURL.RawQuery = query.Encode()
		var body []byte
		var statusCode int
		for retry := 0; ; {
			if !budget.reserve() {
				return CatalogSnapshot{}, fetchFailure{code: "request_budget_exhausted"}
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
			if err != nil {
				return CatalogSnapshot{}, fetchFailure{code: "source_request_invalid"}
			}
			request.Header.Set("Authorization", "Bearer "+apiKey)
			request.Header.Set("Accept", "application/json")
			response, err := doer.Do(request)
			if err != nil {
				return CatalogSnapshot{}, fetchFailure{code: "network_transport_error"}
			}
			if response == nil {
				return CatalogSnapshot{}, fetchFailure{code: "http_error"}
			}
			if response.StatusCode == http.StatusTooManyRequests {
				retryAfter := response.Header.Get("Retry-After")
				if response.Body != nil {
					_ = response.Body.Close()
				}
				if retry >= maxRateLimitRetries {
					return CatalogSnapshot{}, fetchFailure{code: "http_status_429"}
				}
				delay, retryable := rateLimitRetryDelay(retryAfter, retry+1, time.Now())
				if !retryable {
					return CatalogSnapshot{}, fetchFailure{code: "http_status_429"}
				}
				if !budget.wait(ctx, delay) {
					return CatalogSnapshot{}, rateLimitWaitFailure(ctx)
				}
				retry++
				continue
			}
			if response.Body == nil {
				return CatalogSnapshot{}, fetchFailure{code: "http_error"}
			}
			var readErr error
			body, statusCode, readErr = readLimitedResponse(response)
			_ = response.Body.Close()
			if readErr != nil {
				return CatalogSnapshot{}, fetchFailure{code: "response_too_large_or_empty"}
			}
			break
		}
		if statusCode != http.StatusOK {
			zero(body)
			return CatalogSnapshot{}, fetchFailure{code: fmt.Sprintf("http_status_%d", statusCode)}
		}
		var envelope map[string]json.RawMessage
		if json.Unmarshal(body, &envelope) != nil {
			zero(body)
			return CatalogSnapshot{}, fetchFailure{code: "source_parse_error"}
		}
		var success bool
		var output map[string]json.RawMessage
		if json.Unmarshal(envelope["success"], &success) != nil || !success || json.Unmarshal(envelope["output"], &output) != nil {
			zero(body)
			return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
		}
		var currentTotal, currentPageNo, currentPageSize int
		if json.Unmarshal(output["total"], &currentTotal) != nil || json.Unmarshal(output["page_no"], &currentPageNo) != nil || json.Unmarshal(output["page_size"], &currentPageSize) != nil {
			zero(body)
			return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
		}
		var items []map[string]json.RawMessage
		if json.Unmarshal(output["models"], &items) != nil || items == nil {
			zero(body)
			return CatalogSnapshot{}, fetchFailure{code: "source_model_list_invalid"}
		}
		if currentTotal <= 0 || currentTotal > MaxModelsPerAccount || currentPageNo != pageNo || currentPageSize <= 0 || currentPageSize > modelStudioPageSize || (total >= 0 && currentTotal != total) || (pageSize >= 0 && currentPageSize != pageSize) {
			zero(body)
			return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
		}
		if total < 0 {
			total, pageSize = currentTotal, currentPageSize
		}
		expected := pageSize
		remaining := total - (pageNo-1)*pageSize
		if remaining < expected {
			expected = remaining
		}
		if remaining <= 0 || len(items) != expected || len(items) == 0 {
			zero(body)
			return CatalogSnapshot{}, fetchFailure{code: "source_model_list_invalid"}
		}
		ids := make([]string, 0, len(items))
		for _, item := range items {
			var modelID string
			if json.Unmarshal(item["model"], &modelID) != nil || modelID == "" || strings.TrimSpace(modelID) != modelID || !validModelID(modelID) || seen[strings.ToLower(modelID)] {
				zero(body)
				return CatalogSnapshot{}, fetchFailure{code: "source_model_list_invalid"}
			}
			seen[strings.ToLower(modelID)] = true
			ids = append(ids, modelID)
			models = append(models, modelID)
		}
		sort.Strings(ids)
		responseHash := sha256.Sum256(body)
		pages = append(pages, CachedPage{
			URL: requestURL.String(), Title: "Alibaba Bailian Model Studio model catalog", ContentSHA256: hex.EncodeToString(responseHash[:]),
			FetchedAt: fetchedAt, CatalogTotal: total, CatalogPageNo: pageNo, CatalogPageSize: pageSize, AvailableModelIDs: ids,
		})
		zero(body)
		if len(models) == total {
			break
		}
		if pageNo >= MaxHTTPGets || len(models) > total {
			return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
		}
	}
	if len(models) != total {
		return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
	}
	sort.Strings(models)
	snapshot := CatalogSnapshot{
		SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Pages: pages,
		Evidence: []LifecycleEvidence{}, FetchedAt: fetchedAt, CheckedAt: fetchedAt, Complete: true,
	}
	snapshot.ContentSHA256, err = snapshotDigest(snapshot.Pages)
	if err != nil {
		return CatalogSnapshot{}, fetchFailure{code: "snapshot_validation_failed"}
	}
	return snapshot, nil
}

func readLimitedResponse(response *http.Response) ([]byte, int, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(body) == 0 || len(body) > MaxResponseBytes {
		zero(body)
		return nil, response.StatusCode, errors.New("response exceeds limit or is empty")
	}
	return body, response.StatusCode, nil
}

func validateModelStudioPagination(spec sourceSpec, snapshot CatalogSnapshot) error {
	if spec.adapter != "alibaba_model_studio" {
		return nil
	}
	if len(snapshot.Pages) == 0 {
		return errors.New("model catalog pagination is missing")
	}
	total, pageSize := snapshot.Pages[0].CatalogTotal, snapshot.Pages[0].CatalogPageSize
	if total <= 0 || total > MaxModelsPerAccount || pageSize <= 0 || pageSize > modelStudioPageSize {
		return errors.New("model catalog pagination metadata is invalid")
	}
	expectedPages := (total + pageSize - 1) / pageSize
	if len(snapshot.Pages) != expectedPages {
		return errors.New("model catalog page count does not match total")
	}
	seen := make(map[string]bool, total)
	count := 0
	for index, page := range snapshot.Pages {
		pageNo := index + 1
		if page.CatalogTotal != total || page.CatalogPageSize != pageSize || page.CatalogPageNo != pageNo {
			return errors.New("model catalog pagination metadata changed")
		}
		expected := pageSize
		remaining := total - (pageNo-1)*pageSize
		if remaining < expected {
			expected = remaining
		}
		if len(page.AvailableModelIDs) != expected {
			return errors.New("model catalog page is incomplete")
		}
		parsedURL, err := url.Parse(page.URL)
		if err != nil || parsedURL.Path != "/api/v1/models" || parsedURL.Query().Get("page_no") != strconv.Itoa(pageNo) || parsedURL.Query().Get("page_size") != strconv.Itoa(modelStudioPageSize) {
			return errors.New("model catalog page URL does not match pagination metadata")
		}
		for _, id := range page.AvailableModelIDs {
			folded := strings.ToLower(id)
			if seen[folded] {
				return errors.New("model catalog contains duplicate IDs across pages")
			}
			seen[folded] = true
			count++
		}
	}
	if count != total {
		return errors.New("model catalog item count does not match total")
	}
	return nil
}
