package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sub2api-model-catalog-manager/internal/catalog"
)

const summaryTestRunID = "0123456789abcdef0123456789abcdef"

func TestAppliedScreenSummaryUsesVerifiedAfterMappingsAndReportsRouteDifferences(t *testing.T) {
	dir := t.TempDir()
	created := time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC)
	doc := Document{
		RunID: summaryTestRunID, CreatedAt: created, Mode: "discover", AccountScope: "all",
		AccountScanStatus: "complete", AccountInventoryCount: 2, TargetFingerprint: "verified-build",
		Discovery: []DiscoveryAccount{
			{ID: 2, Status: "candidate_reported", SourceProfileStatus: "approved", CatalogCompleteness: "unknown", CurrentMappingStatus: "explicit_nonempty", CurrentMappings: []Mapping{{PublicID: "shared-model", UpstreamID: "route-b", Disposition: "observed_current"}}},
			{ID: 1, Status: "candidate_reported", SourceProfileStatus: "approved", CatalogCompleteness: "unknown", CurrentMappingStatus: "explicit_nonempty", CurrentMappings: []Mapping{{PublicID: "old-model", UpstreamID: "old-route", Disposition: "observed_current"}}, Changes: []MappingChange{{Action: "update", PublicID: "shared-model", Before: "old-route", After: "route-a", Reason: "exact reviewed rule"}}},
		},
	}
	plan := &catalog.ApprovalPlan{Accounts: []catalog.Plan{
		{AccountID: 1, Before: map[string]string{"old-model": "old-route"}, After: map[string]string{"shared-model": "route-a"}},
		{AccountID: 2, Before: map[string]string{"shared-model": "route-b"}, After: map[string]string{"shared-model": "route-b"}},
	}}
	outcome := ScreenSummaryOutcome{Status: ScreenSummaryApplied, AppliedIDs: []int64{1}, NoopIDs: []int64{2}, Consumed: true, ReportPath: filepath.Join(dir, "discover.json"), PlanPath: filepath.Join(dir, "plan.json")}
	path, err := WriteScreenSummary(dir, doc, plan, outcome)
	if err != nil {
		t.Fatal(err)
	}
	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)
	for _, want := range []string{
		"已应用", "write_readback_verified", "apply_preflight_verified_noop",
		"`shared-model` → `route-a`", "`shared-model` → `route-b`",
		"`shared-model`", "账号 #1", "账号 #2", "Applied=1 #1", "No-op=1 #2",
		"不同公开模型名：1", "线路映射有差异", "目录中出现模型 ID 不等于该模型生成可用",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "route-a` → `route-a") {
		t.Fatal("summary used stale discovery mapping instead of the applied after-state")
	}
}

func TestPreviewScreenSummarySeparatesCurrentMappingsFromProposedChanges(t *testing.T) {
	dir := t.TempDir()
	doc := Document{
		RunID: summaryTestRunID, CreatedAt: time.Date(2026, 10, 14, 9, 31, 0, 0, time.UTC),
		AccountInventoryCount: 1, AccountScanStatus: "complete",
		Discovery: []DiscoveryAccount{{
			ID: 7, Status: "candidate_reported", SourceProfileStatus: "approved", CatalogCompleteness: "unknown",
			CurrentMappingStatus: "explicit_nonempty", CurrentMappings: []Mapping{{PublicID: "current", UpstreamID: "observed"}},
			Changes: []MappingChange{{Action: "add", PublicID: "proposed", After: "target", Reason: "reviewed"}},
		}},
	}
	plan := &catalog.ApprovalPlan{Accounts: []catalog.Plan{{AccountID: 7, Before: map[string]string{"current": "observed"}, After: map[string]string{"current": "observed", "proposed": "target"}}}}
	path, err := WriteScreenSummary(dir, doc, plan, ScreenSummaryOutcome{Status: ScreenSummaryPreview})
	if err != nil {
		t.Fatal(err)
	}
	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)
	if !strings.Contains(got, "PREVIEW ONLY / 未应用映射") || !strings.Contains(got, "`current` → `observed`") || !strings.Contains(got, "`add` `proposed`: `` → `target`") {
		t.Fatalf("preview summary does not separate current mapping and proposal:\n%s", got)
	}
	if strings.Contains(got, "`proposed` → `target`") {
		t.Fatal("preview summary presented a proposed mapping as current")
	}
}

func TestNoPlanAndPartialSummariesDoNotInferUnreadableAccountIsEmpty(t *testing.T) {
	dir := t.TempDir()
	doc := Document{
		RunID: summaryTestRunID, CreatedAt: time.Date(2026, 10, 14, 9, 32, 0, 0, time.UTC),
		AccountInventoryCount: 3, AccountScanStatus: "partial",
		Discovery: []DiscoveryAccount{
			{ID: 8, Status: "skipped_unrestricted_mapping", CurrentMappingStatus: "no_explicit_mapping", CurrentMappings: []Mapping{}},
			{ID: 9, Status: "account_read_failed", CurrentMappingStatus: "account_read_failed", CurrentMappings: []Mapping{}},
			{ID: 10, Status: "skipped_unrestricted_mapping", CurrentMappingStatus: "explicit_empty", CurrentMappings: []Mapping{}},
		},
	}
	path, err := WriteScreenSummary(dir, doc, nil, ScreenSummaryOutcome{Status: ScreenSummaryPartial})
	if err != nil {
		t.Fatal(err)
	}
	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)
	if !strings.Contains(got, "PARTIAL / 全账号结果不完整") || !strings.Contains(got, "未读取，不能推断为空") || !strings.Contains(got, "no_explicit_mapping") || !strings.Contains(got, "explicit_empty") {
		t.Fatalf("partial summary does not distinguish unreadable and unrestricted mappings:\n%s", got)
	}
	if strings.Contains(got, "账号 #9`\n\n- 来源状态") && !strings.Contains(got, "account_read_failed") {
		t.Fatal("unreadable account was misreported as successfully empty")
	}
}

func TestBlockedAfterDiscoveryHasDistinctNoApplyStatus(t *testing.T) {
	dir := t.TempDir()
	doc := Document{
		RunID: summaryTestRunID, CreatedAt: time.Date(2026, 10, 14, 9, 33, 0, 0, time.UTC),
		AccountInventoryCount: 1, AccountScanStatus: "complete",
		Discovery: []DiscoveryAccount{{ID: 1, Status: "candidate_reported", CurrentMappingStatus: "explicit_nonempty", CurrentMappings: []Mapping{{PublicID: "keep", UpstreamID: "same"}}, Changes: []MappingChange{{Action: "remove", PublicID: "retired"}}}},
	}
	plan := &catalog.ApprovalPlan{Accounts: []catalog.Plan{{AccountID: 1, Before: map[string]string{"keep": "same", "retired": "retired"}, After: map[string]string{"keep": "same"}}}}
	path, err := WriteScreenSummary(dir, doc, plan, ScreenSummaryOutcome{Status: ScreenSummaryBlockedAfterDiscovery})
	if err != nil {
		t.Fatal(err)
	}
	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)
	if !strings.Contains(got, "BLOCKED AFTER DISCOVERY / 未应用映射") || !strings.Contains(got, "`keep` → `same`") || strings.Contains(got, "`retired` → `retired`") {
		t.Fatalf("blocked summary confused current and proposed state:\n%s", got)
	}
}

func TestScreenSummaryUsesSafeLiteralCodeSpansAndDoesNotOverwriteExistingFile(t *testing.T) {
	dir := t.TempDir()
	unsafeModelID := "model|with`pipe\nline``[link](file:///tmp/pwn)<img src=x>"
	doc := Document{
		RunID: summaryTestRunID, CreatedAt: time.Date(2026, 10, 14, 9, 34, 0, 0, time.UTC),
		AccountInventoryCount: 1, AccountScanStatus: "complete",
		Discovery: []DiscoveryAccount{{ID: 3, Status: "candidate_reported", CurrentMappingStatus: "explicit_nonempty", CurrentMappings: []Mapping{{PublicID: unsafeModelID, UpstreamID: `up\stream`}}}},
	}
	firstPath, err := WriteScreenSummary(dir, doc, nil, ScreenSummaryOutcome{Status: ScreenSummaryNoPlan})
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(firstBytes)
	wantID := "```model|with`pipe\\nline``[link](file:///tmp/pwn)<img src=x>```"
	if !strings.Contains(got, wantID) || !strings.Contains(got, "`up\\stream`") {
		t.Fatalf("model IDs were not preserved inside safe literal code spans:\n%s", got)
	}
	if strings.Contains(got, "\\`pipe") || strings.Contains(got, "model\\|with") {
		t.Fatal("summary serializer altered model ID characters")
	}
	for _, forbidden := range []string{"test-admin-key", "Authorization", "header_override", "https://secret.example", "owner@example.com"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("summary leaked a forbidden credential/connection field %q", forbidden)
		}
	}
	if _, err := WriteScreenSummary(dir, doc, nil, ScreenSummaryOutcome{Status: ScreenSummaryNoPlan}); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("existing summary path was overwritten or not rejected: %v", err)
	}
}

func TestScreenSummaryReportsAccountStatusCategoryCounts(t *testing.T) {
	doc := Document{
		RunID: summaryTestRunID, CreatedAt: time.Date(2026, 10, 14, 9, 34, 0, 0, time.UTC),
		AccountInventoryCount: 7, AccountScanStatus: "partial",
		Discovery: []DiscoveryAccount{
			{ID: 1, Status: "candidate_reported", SourceProfileStatus: "approved"},
			{ID: 2, Status: "skipped_inactive", SourceProfileStatus: "not_checked"},
			{ID: 3, Status: "skipped", SourceProfileStatus: "not_allowlisted_for_target"},
			{ID: 4, Status: "sync_failed", SourceProfileStatus: "approved"},
			{ID: 5, Status: "skipped_shadow", SourceProfileStatus: "not_checked"},
			{ID: 6, Status: "account_read_failed", SourceProfileStatus: "not_checked"},
			{ID: 7, Status: "skipped_unrestricted_mapping", SourceProfileStatus: "not_checked"},
		},
	}
	got, err := renderScreenSummary(doc, nil, ScreenSummaryOutcome{Status: ScreenSummaryPartial})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"inventory=7，详情已读=6，计划账号=0",
		"活跃=5，非活跃=1，未匹配审核来源=1，来源未检查=3，目录失败/未知=1，其他跳过/阻断=3，详情读取失败=1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary omitted account status count %q:\n%s", want, got)
		}
	}
}
