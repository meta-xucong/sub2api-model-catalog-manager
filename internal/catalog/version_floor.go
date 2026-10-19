package catalog

import (
	"net/url"
	"sort"

	"sub2api-model-catalog-manager/internal/modelversion"
)

// CascadeUnavailableVersions applies the owner hard rule to exact model IDs:
// once an authoritative negative proves a version unavailable, lower versions
// in the same recognized family are unavailable too. Unknown IDs, other
// families, and non-authoritative/incomplete evidence are left unchanged.
func CascadeUnavailableVersions(items []ProductModelAvailability) {
	floors := make(map[string]ProductModelAvailability)
	for _, item := range items {
		family, recognized := modelversion.Family(item.ModelID)
		if item.Status != "unavailable" || item.MatchKind == "lower_than_unavailable_version" || !recognized || !canEstablishVersionFloor(item) {
			continue
		}
		key := item.Provider + "\x00" + family
		current, ok := floors[key]
		if !ok || modelversion.HigherVersion(item.ModelID, current.ModelID) {
			floors[key] = item
		}
	}
	for i := range items {
		item := &items[i]
		family, recognized := modelversion.Family(item.ModelID)
		if !recognized {
			continue
		}
		floor, ok := floors[item.Provider+"\x00"+family]
		if !ok || !modelversion.LowerVersion(item.ModelID, floor.ModelID) {
			continue
		}
		// The owner hard rule takes precedence over a lower ID's direct negative
		// classification too. Reclassifying it as a cascade is necessary because
		// this rule explicitly authorizes removing unmanaged lower-version mappings.
		item.Status = "unavailable"
		item.MatchKind = "lower_than_unavailable_version"
		item.VersionFloorModelID = floor.ModelID
		item.SourceIDs = append([]string(nil), floor.SourceIDs...)
		item.SourceURLs = append([]string(nil), floor.SourceURLs...)
		item.ContentSHA256 = append([]string(nil), floor.ContentSHA256...)
		item.RetrievedAt = floor.RetrievedAt
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Provider != items[j].Provider {
			return items[i].Provider < items[j].Provider
		}
		return items[i].ModelID < items[j].ModelID
	})
}

func canEstablishVersionFloor(item ProductModelAvailability) bool {
	if validateProductModelAvailability(item) != nil {
		return false
	}
	switch item.MatchKind {
	case "accepted_union_version_floor", "accepted_union_retirement", "all_account_probes_failed":
		return authorizesUnmanagedProductRemoval(item)
	case "accepted_union_absence":
		return validVersionFloorSource(item)
	case "official_account_absence":
		return validVersionFloorSource(item)
	case "official_api_catalog_absence":
		return validVersionFloorSource(item)
	default:
		return false
	}
}

func validVersionFloorSource(item ProductModelAvailability) bool {
	if len(item.SourceIDs) != 1 || len(item.SourceURLs) != 1 || len(item.ContentSHA256) != 1 {
		return false
	}
	switch item.SourceIDs[0] {
	case "openai-cross-product-lifecycle-v2":
		return item.Provider == "openai" && item.SourceURLs[0] == "https://learn.chatgpt.com/docs/changelog"
	case "openai-codex-models":
		return item.Provider == "openai" && item.SourceURLs[0] == "https://developers.openai.com/codex/models"
	case "xai-grok-web-models":
		return item.Provider == "xai" && item.SourceURLs[0] == "https://x.ai/news/grok-4-5-everywhere"
	case "404token-account-probe-v1":
		return item.SourceURLs[0] == "https://404token.xyz/api/v1/admin/accounts/{account_id}/test"
	case "volcengine-ark-account-models":
		return item.Provider == "volcengine" && item.SourceURLs[0] == "https://ark.cn-beijing.volcengineapi.com/?Action=ListModelActivations&Version=2024-01-01"
	case "alibaba-model-studio-models":
		if item.Provider != "alibaba" {
			return false
		}
		u, err := url.Parse(item.SourceURLs[0])
		if err != nil || u.Scheme != "https" || u.Host != "ws-soph8gi8iynvs7lh.cn-beijing.maas.aliyuncs.com" || u.Path != "/api/v1/models" {
			return false
		}
		query := u.Query()
		return len(query) == 2 && query.Get("page_no") == "1" && query.Get("page_size") == "200"
	default:
		return false
	}
}
