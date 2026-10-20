package officialcatalog

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	arkRegion        = "cn-beijing"
	arkService       = "ark"
	arkPageSize      = 100
	maxArkCredential = 16 << 10
)

type arkCredentials struct {
	accessKeyID string
	secretKey   []byte
}

type arkPageRequest struct {
	PageNumber int `json:"PageNumber"`
	PageSize   int `json:"PageSize"`
	Filter     struct {
		States                  []string `json:"States"`
		IncludeDeprecatedModels bool     `json:"IncludeDeprecatedModels"`
	} `json:"Filter"`
}

type arkPageResponse struct {
	Result struct {
		TotalCount *int `json:"TotalCount"`
		PageNumber int  `json:"PageNumber"`
		PageSize   int  `json:"PageSize"`
		Items      []struct {
			FoundationModelName string `json:"FoundationModelName"`
			State               string `json:"State"`
			IsDeprecated        bool   `json:"IsDeprecated"`
		} `json:"Items"`
	} `json:"Result"`
}

func loadArkCredentials(path string) (arkCredentials, error) {
	var credentials arkCredentials
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxArkCredential {
		return credentials, errors.New("credential_file_unavailable")
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 || len(body) > maxArkCredential {
		zero(body)
		return credentials, errors.New("credential_file_unavailable")
	}
	defer zero(body)
	access, secret, ok := parseArkCredentialFile(body)
	if !ok {
		return credentials, errors.New("credential_file_invalid")
	}
	credentials.accessKeyID = access
	credentials.secretKey = secret
	return credentials, nil
}

func parseArkCredentialFile(body []byte) (string, []byte, bool) {
	body = bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	lines := bytes.Split(body, []byte("\n"))
	values := map[string][]byte{}
	defer func() {
		for _, value := range values {
			zero(value)
		}
	}()
	for i := 0; i < len(lines); i++ {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		label, value, hasValue := splitArkCredentialLine(line)
		if !hasValue {
			label = string(line)
			if i+1 >= len(lines) {
				return "", nil, false
			}
			i++
			value = bytes.TrimSpace(lines[i])
		}
		kind := arkCredentialLabel(label)
		if kind == "" || len(value) == 0 || bytes.ContainsAny(value, "\r\x00") || len(values[kind]) != 0 {
			return "", nil, false
		}
		values[kind] = append([]byte(nil), value...)
	}
	access, accessOK := values["access"]
	secret, secretOK := values["secret"]
	if !accessOK || !secretOK || len(access) > 512 || len(secret) > 1024 {
		return "", nil, false
	}
	return string(access), append([]byte(nil), secret...), true
}

func splitArkCredentialLine(line []byte) (label string, value []byte, ok bool) {
	for _, delimiter := range [][]byte{[]byte(":"), []byte("："), []byte("=")} {
		if index := bytes.Index(line, delimiter); index > 0 {
			return string(bytes.TrimSpace(line[:index])), bytes.TrimSpace(line[index+len(delimiter):]), true
		}
	}
	return "", nil, false
}

func arkCredentialLabel(label string) string {
	var normalized strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(label)) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r >= '\u4e00' && r <= '\u9fff' {
			normalized.WriteRune(r)
		}
	}
	switch value := normalized.String(); {
	case value == "ak" || value == "akid" || strings.Contains(value, "accesskeyid") || strings.Contains(value, "访问密钥id"):
		return "access"
	case value == "sk" || strings.Contains(value, "secretaccesskey") || strings.Contains(value, "secretkey") || strings.Contains(value, "secret") || strings.Contains(value, "密钥"):
		return "secret"
	default:
		return ""
	}
}

func fetchArkCatalog(ctx context.Context, spec sourceSpec, credentials arkCredentials, doer HTTPDoer, now func() time.Time) (CatalogSnapshot, error) {
	if ctx == nil || doer == nil || spec.adapter != "volcengine_ark" {
		return CatalogSnapshot{}, fetchFailure{code: "source_fetch_unavailable"}
	}
	if credentials.accessKeyID == "" || len(credentials.secretKey) == 0 {
		return CatalogSnapshot{}, fetchFailure{code: "credential_file_invalid"}
	}
	if now == nil {
		now = time.Now
	}
	started := now().UTC()
	var allIDs []string
	seen := map[string]bool{}
	var total int
	var responseDigest bytes.Buffer
	for pageNumber := 1; ; pageNumber++ {
		if pageNumber > MaxModelsPerAccount/arkPageSize+1 {
			return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
		}
		var body arkPageRequest
		body.PageNumber = pageNumber
		body.PageSize = arkPageSize
		body.Filter.States = []string{"Available"}
		body.Filter.IncludeDeprecatedModels = false
		encoded, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return CatalogSnapshot{}, fetchFailure{code: "source_request_invalid"}
		}
		response, requestErr := arkListModelActivations(ctx, spec.rootURL, encoded, credentials, doer, started)
		zero(encoded)
		if requestErr != nil {
			return CatalogSnapshot{}, requestErr
		}
		if pageNumber == 1 {
			if response.page.Result.TotalCount == nil {
				zero(response.body)
				return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
			}
			total = *response.page.Result.TotalCount
			if total < 0 || total > MaxModelsPerAccount {
				zero(response.body)
				return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
			}
		} else if response.page.Result.TotalCount == nil || *response.page.Result.TotalCount != total {
			zero(response.body)
			return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
		}
		result := response.page.Result
		wantCount := arkPageSize
		if remaining := total - len(allIDs); remaining < wantCount {
			wantCount = remaining
		}
		if result.PageNumber != pageNumber || result.PageSize != arkPageSize || len(result.Items) != wantCount {
			zero(response.body)
			return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
		}
		for _, item := range result.Items {
			id := item.FoundationModelName
			if item.State != "Available" || item.IsDeprecated || strings.TrimSpace(id) != id || !validModelID(id) || seen[strings.ToLower(id)] {
				zero(response.body)
				return CatalogSnapshot{}, fetchFailure{code: "source_model_list_invalid"}
			}
			seen[strings.ToLower(id)] = true
			allIDs = append(allIDs, id)
		}
		responseDigest.Write(response.body)
		responseDigest.Write([]byte{0})
		zero(response.body)
		if len(allIDs) == total {
			break
		}
	}
	if len(allIDs) != total {
		return CatalogSnapshot{}, fetchFailure{code: "source_pagination_invalid"}
	}
	sort.Strings(allIDs)
	contentHash := sha256.Sum256(responseDigest.Bytes())
	page := CachedPage{
		URL: spec.rootURL, Title: "Volcengine Ark account model activations", ContentSHA256: hex.EncodeToString(contentHash[:]),
		FetchedAt: started, AvailableModelIDs: allIDs,
	}
	snapshot := CatalogSnapshot{
		SourceID: spec.id, Provider: spec.provider, Scope: spec.scope, Pages: []CachedPage{page},
		Evidence: []LifecycleEvidence{}, FetchedAt: started, CheckedAt: started, Complete: true,
	}
	digest, err := snapshotDigest(snapshot.Pages)
	if err != nil {
		return CatalogSnapshot{}, fetchFailure{code: "snapshot_validation_failed"}
	}
	snapshot.ContentSHA256 = digest
	return snapshot, nil
}

type arkResponseBody struct {
	page arkPageResponse
	body []byte
}

func arkListModelActivations(ctx context.Context, endpoint string, body []byte, credentials arkCredentials, doer HTTPDoer, now time.Time) (arkResponseBody, error) {
	requestURL, err := url.Parse(endpoint)
	if err != nil || requestURL.RawQuery != "Action=ListModelActivations&Version=2024-01-01" {
		return arkResponseBody{}, fetchFailure{code: "source_url_rejected"}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		return arkResponseBody{}, fetchFailure{code: "source_request_invalid"}
	}
	if err := signArkRequest(request, body, credentials, now); err != nil {
		return arkResponseBody{}, fetchFailure{code: "source_request_invalid"}
	}
	response, err := doer.Do(request)
	if err != nil {
		return arkResponseBody{}, fetchFailure{code: "network_transport_error"}
	}
	if response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return arkResponseBody{}, fetchFailure{code: "http_error"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return arkResponseBody{}, fetchFailure{code: fmt.Sprintf("http_status_%d", response.StatusCode)}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaxResponseBytes {
		zero(data)
		return arkResponseBody{}, fetchFailure{code: "response_too_large_or_empty"}
	}
	var decoded arkPageResponse
	if json.Unmarshal(data, &decoded) != nil || decoded.Result.TotalCount == nil || decoded.Result.Items == nil || decoded.Result.PageNumber <= 0 || decoded.Result.PageSize <= 0 {
		zero(data)
		return arkResponseBody{}, fetchFailure{code: "source_parse_error"}
	}
	return arkResponseBody{page: decoded, body: data}, nil
}

func signArkRequest(request *http.Request, body []byte, credentials arkCredentials, now time.Time) error {
	if request == nil || request.URL == nil || credentials.accessKeyID == "" || len(credentials.secretKey) == 0 || request.URL.Host != "ark.cn-beijing.volcengineapi.com" {
		return errors.New("invalid signing input")
	}
	if now.IsZero() {
		now = time.Now()
	}
	xDate := now.UTC().Format("20060102T150405Z")
	date := xDate[:8]
	bodyHash := sha256.Sum256(body)
	bodyHashHex := hex.EncodeToString(bodyHash[:])
	contentType := "application/json"
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("X-Date", xDate)
	request.Header.Set("X-Content-Sha256", bodyHashHex)
	request.Host = request.URL.Host
	query := request.URL.Query()
	queryString := strings.ReplaceAll(query.Encode(), "+", "%20")
	canonicalHeaders := "content-type:" + contentType + "\n" + "host:" + request.URL.Host + "\n" + "x-content-sha256:" + bodyHashHex + "\n" + "x-date:" + xDate + "\n"
	signedHeaders := "content-type;host;x-content-sha256;x-date"
	canonicalRequest := strings.Join([]string{request.Method, "/", queryString, canonicalHeaders, signedHeaders, bodyHashHex}, "\n")
	canonicalHash := sha256.Sum256([]byte(canonicalRequest))
	credentialScope := date + "/" + arkRegion + "/" + arkService + "/request"
	stringToSign := "HMAC-SHA256\n" + xDate + "\n" + credentialScope + "\n" + hex.EncodeToString(canonicalHash[:])
	kDate := arkHMAC(credentials.secretKey, date)
	kRegion := arkHMAC(kDate, arkRegion)
	kService := arkHMAC(kRegion, arkService)
	kSigning := arkHMAC(kService, "request")
	signature := hex.EncodeToString(arkHMAC(kSigning, stringToSign))
	request.Header.Set("Authorization", fmt.Sprintf("HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", credentials.accessKeyID, credentialScope, signedHeaders, signature))
	zero(kDate)
	zero(kRegion)
	zero(kService)
	zero(kSigning)
	return nil
}

func arkHMAC(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
