package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"sub2api-model-catalog-manager/internal/catalog"
)

const (
	ScreenSummaryApplied               = "applied"
	ScreenSummaryPreview               = "preview"
	ScreenSummaryNoPlan                = "no_plan"
	ScreenSummaryBlockedAfterDiscovery = "blocked_after_discovery"
	ScreenSummaryPartial               = "partial"
)

var screenSummaryRunIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// ScreenSummaryOutcome contains only safe run metadata. It deliberately does
// not import app.ApplyResult, keeping report formatting independent of the
// workflow implementation.
type ScreenSummaryOutcome struct {
	Status     string
	AppliedIDs []int64
	NoopIDs    []int64
	Consumed   bool
	PlanSHA256 string
	ReportPath string
	PlanPath   string
}

// WriteScreenSummary writes a local, human-readable mapping snapshot. For an
// applied plan, changed accounts use the plan's after-state (already read back
// by ApplyPrepared); no-op accounts use the after-state verified at preflight.
// Accounts not in the plan retain the mapping observed during discovery.
func WriteScreenSummary(dir string, doc Document, plan *catalog.ApprovalPlan, outcome ScreenSummaryOutcome) (string, error) {
	if strings.TrimSpace(dir) == "" || !screenSummaryRunIDPattern.MatchString(doc.RunID) || doc.CreatedAt.IsZero() {
		return "", errors.New("screen summary identity or output directory is invalid")
	}
	switch outcome.Status {
	case ScreenSummaryApplied:
		if plan == nil {
			return "", errors.New("applied screen summary requires an approval plan")
		}
	case ScreenSummaryPreview, ScreenSummaryBlockedAfterDiscovery:
		if plan == nil {
			return "", errors.New("preview or blocked screen summary requires an approval plan")
		}
	case ScreenSummaryNoPlan, ScreenSummaryPartial:
	default:
		return "", errors.New("screen summary status is invalid")
	}

	body, err := renderScreenSummary(doc, plan, outcome)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", errors.New("screen summary directory could not be created")
	}
	name := "screen-summary-" + doc.CreatedAt.UTC().Format("20060102T150405Z") + "-" + doc.RunID + ".md"
	path := filepath.Join(dir, name)
	tmp, err := os.CreateTemp(dir, ".screen-summary-*.tmp")
	if err != nil {
		return "", errors.New("temporary screen summary could not be created")
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return "", errors.New("screen summary file mode could not be set")
	}
	if _, err := tmp.Write([]byte(body)); err != nil {
		_ = tmp.Close()
		return "", errors.New("screen summary write failed")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", errors.New("screen summary flush failed")
	}
	if err := tmp.Close(); err != nil {
		return "", errors.New("screen summary close failed")
	}
	if _, err := os.Stat(path); err == nil {
		return "", errors.New("screen summary filename collision")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("screen summary destination could not be checked")
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return "", errors.New("screen summary atomic publish failed")
	}
	return path, nil
}

func renderScreenSummary(doc Document, plan *catalog.ApprovalPlan, outcome ScreenSummaryOutcome) (string, error) {
	planByID := make(map[int64]catalog.Plan)
	if plan != nil {
		for _, account := range plan.Accounts {
			if account.AccountID <= 0 {
				return "", errors.New("screen summary plan contains an invalid account ID")
			}
			if _, exists := planByID[account.AccountID]; exists {
				return "", errors.New("screen summary plan contains a duplicate account")
			}
			planByID[account.AccountID] = account
		}
	}

	rows := append([]DiscoveryAccount(nil), doc.Discovery...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	seenAccounts := make(map[int64]bool, len(rows))
	for _, row := range rows {
		if row.ID <= 0 || seenAccounts[row.ID] {
			return "", errors.New("screen summary discovery contains an invalid or duplicate account ID")
		}
		seenAccounts[row.ID] = true
	}

	finalMappings := make(map[int64]map[string]string, len(rows))
	evidence := make(map[int64]string, len(rows))
	uniquePublic := map[string]struct{}{}
	totalMappings := 0
	targetsByPublic := map[string]map[string]map[int64]struct{}{}
	unreviewed := map[string]struct{}{}
	changeCounts := map[string]int{"add": 0, "update": 0, "remove": 0}
	accountCounts := screenAccountCounts{}
	plannedIDs := make([]int64, 0, len(planByID))
	for id, p := range planByID {
		plannedIDs = append(plannedIDs, id)
		for _, change := range p.Changes {
			changeCounts[change.Action]++
		}
	}
	sort.Slice(plannedIDs, func(i, j int) bool { return plannedIDs[i] < plannedIDs[j] })

	for _, row := range rows {
		accountCounts.observe(row)
		mapping := make(map[string]string, len(row.CurrentMappings))
		for _, item := range row.CurrentMappings {
			if item.PublicID == "" {
				return "", errors.New("screen summary discovery contains an empty public model ID")
			}
			if _, exists := mapping[item.PublicID]; exists {
				return "", errors.New("screen summary discovery contains duplicate public model IDs")
			}
			mapping[item.PublicID] = item.UpstreamID
		}
		evidence[row.ID] = "observed_at_discovery"
		if outcome.Status == ScreenSummaryApplied {
			if p, ok := planByID[row.ID]; ok {
				mapping = cloneScreenMapping(p.After)
				if equalScreenMappings(p.Before, p.After) {
					evidence[row.ID] = "apply_preflight_verified_noop"
				} else {
					evidence[row.ID] = "write_readback_verified"
				}
			}
		}
		finalMappings[row.ID] = mapping
		totalMappings += len(mapping)
		for publicID := range mapping {
			uniquePublic[publicID] = struct{}{}
			targets := targetsByPublic[publicID]
			if targets == nil {
				targets = map[string]map[int64]struct{}{}
				targetsByPublic[publicID] = targets
			}
			upstreamID := mapping[publicID]
			accounts := targets[upstreamID]
			if accounts == nil {
				accounts = map[int64]struct{}{}
				targets[upstreamID] = accounts
			}
			accounts[row.ID] = struct{}{}
		}
		for _, model := range row.UnreviewedModels {
			unreviewed[model] = struct{}{}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# 404token 全账号模型筛分摘要\n\n")
	fmt.Fprintf(&b, "- 结果：**%s**\n", screenStatusLabel(outcome.Status))
	fmt.Fprintf(&b, "- 运行 ID：%s\n", markdownCode(doc.RunID))
	fmt.Fprintf(&b, "- 生成时间（UTC）：%s\n", markdownCode(doc.CreatedAt.UTC().Format(time.RFC3339)))
	fmt.Fprintf(&b, "- 模式：%s；目标 build：%s\n", markdownCode(doc.Mode), markdownCode(doc.TargetFingerprint))
	fmt.Fprintf(&b, "- 账号盘点：%s，inventory=%d，详情已读=%d，计划账号=%d\n", markdownCode(doc.AccountScanStatus), doc.AccountInventoryCount, accountCounts.DetailsRead, len(planByID))
	fmt.Fprintf(&b, "- 账号状态汇总：活跃=%d，非活跃=%d，未匹配审核来源=%d，来源未检查=%d，目录失败/未知=%d，其他跳过/阻断=%d，详情读取失败=%d\n", accountCounts.Active, accountCounts.Inactive, accountCounts.UnreviewedSource, accountCounts.SourceNotChecked, accountCounts.CatalogFailures, accountCounts.OtherSkipped, accountCounts.DetailReadFailed)
	fmt.Fprintf(&b, "- 映射变更：新增=%d，更新=%d，删除=%d；Applied=%d %s；No-op=%d %s；consumed=%t\n", changeCounts["add"], changeCounts["update"], changeCounts["remove"], len(outcome.AppliedIDs), formatScreenIDs(sortedScreenIDs(outcome.AppliedIDs)), len(outcome.NoopIDs), formatScreenIDs(sortedScreenIDs(outcome.NoopIDs)), outcome.Consumed)
	fmt.Fprintf(&b, "- 本轮可读取的账号—模型映射条目：%d\n", totalMappings)
	fmt.Fprintf(&b, "- 当前观察到的不同公开模型名：%d（不等于模型生成可用数或统一网关最终可见数）\n", len(uniquePublic))
	fmt.Fprintf(&b, "- 未决/未审核模型名：%d\n", len(unreviewed))
	if outcome.PlanSHA256 != "" {
		fmt.Fprintf(&b, "- 计划 SHA-256：%s\n", markdownCode(outcome.PlanSHA256))
	}
	if outcome.ReportPath != "" {
		fmt.Fprintf(&b, "- 原始发现报告：%s\n", markdownCode(outcome.ReportPath))
	}
	if outcome.PlanPath != "" {
		fmt.Fprintf(&b, "- 审批计划：%s\n", markdownCode(outcome.PlanPath))
	}

	fmt.Fprintf(&b, "\n## 结果口径\n\n")
	switch outcome.Status {
	case ScreenSummaryApplied:
		fmt.Fprintf(&b, "本轮批准计划已成功应用。变更账号的映射经过写后读取核验；no-op 账号在 Apply 预检中确认与计划目标一致，但没有额外的结束时读取。未列入计划的账号映射来自发现阶段读取，未由本轮 Apply 修改。\n")
	case ScreenSummaryPreview:
		fmt.Fprintf(&b, "**PREVIEW ONLY：本轮没有应用映射。** 下方映射是发现阶段读到的当前值；拟议变更另列。\n")
	case ScreenSummaryBlockedAfterDiscovery:
		fmt.Fprintf(&b, "**BLOCKED AFTER DISCOVERY：批准规则在发现阶段后发生变化，自动应用已安全阻止；本轮没有应用映射。** 下方映射是发现阶段读到的当前值；拟议变更另列。\n")
	case ScreenSummaryNoPlan:
		fmt.Fprintf(&b, "本轮没有生成可应用计划；映射来自发现阶段读取。请查看逐账号跳过原因。\n")
	case ScreenSummaryPartial:
		fmt.Fprintf(&b, "**PARTIAL：至少一个账号详情未能读取或全账号盘点不完整。** 本报告只列已读取的映射；不得将缺失账号视为无映射。\n")
	}
	fmt.Fprintf(&b, "原生 `sync-upstream` 可能更新 Sub2API 的上游目录元数据并产生目录查询成本；本流程不发送模型生成请求。目录中出现模型 ID 不等于该模型生成可用。\n")

	fmt.Fprintf(&b, "\n## 逐账号映射\n\n")
	if len(rows) == 0 {
		fmt.Fprintf(&b, "本轮没有可列出的账号详情。\n")
	}
	for _, row := range rows {
		mapping := finalMappings[row.ID]
		fmt.Fprintf(&b, "### 账号 #%d — %s\n\n", row.ID, markdownCode(row.Status))
		fmt.Fprintf(&b, "- 来源状态：%s；目录完整性：%s；映射读取状态：%s；映射条数：%d\n", markdownCode(row.SourceProfileStatus), markdownCode(row.CatalogCompleteness), markdownCode(row.CurrentMappingStatus), len(mapping))
		if reason := strings.TrimSpace(row.Reason); reason != "" {
			fmt.Fprintf(&b, "- 说明：%s\n", markdownCode(reason))
		}
		if row.Status == "account_read_failed" {
			fmt.Fprintf(&b, "- 映射：`未读取，不能推断为空`\n")
		} else if len(mapping) == 0 {
			fmt.Fprintf(&b, "- 映射：`无条目`（结合映射状态理解；可能是显式空或 unrestricted）\n")
		} else {
			publicIDs := make([]string, 0, len(mapping))
			for publicID := range mapping {
				publicIDs = append(publicIDs, publicID)
			}
			sort.Strings(publicIDs)
			fmt.Fprintf(&b, "- 映射证据：%s\n", markdownCode(evidence[row.ID]))
			for _, publicID := range publicIDs {
				fmt.Fprintf(&b, "  - %s → %s\n", markdownCode(publicID), markdownCode(mapping[publicID]))
			}
		}
		if len(row.Changes) > 0 {
			fmt.Fprintf(&b, "- 本轮规则动作：\n")
			changes := append([]MappingChange(nil), row.Changes...)
			sort.Slice(changes, func(i, j int) bool {
				if changes[i].PublicID != changes[j].PublicID {
					return changes[i].PublicID < changes[j].PublicID
				}
				return changes[i].Action < changes[j].Action
			})
			for _, change := range changes {
				fmt.Fprintf(&b, "  - %s %s: %s → %s（%s）\n", markdownCode(change.Action), markdownCode(change.PublicID), markdownCode(change.Before), markdownCode(change.After), markdownCode(change.Reason))
			}
		}
		if len(row.Conflicts) > 0 {
			fmt.Fprintf(&b, "- 冲突：%s\n", markdownList(row.Conflicts))
		}
		if len(row.Warnings) > 0 {
			fmt.Fprintf(&b, "- 目录警告：%s\n", markdownList(row.Warnings))
		}
		if len(row.UnreviewedModels) > 0 {
			models := append([]string(nil), row.UnreviewedModels...)
			sort.Strings(models)
			fmt.Fprintf(&b, "- 未决模型名：%s\n", markdownList(models))
		}
		b.WriteByte('\n')
	}

	fmt.Fprintf(&b, "## 跨账号同名模型目标差异\n\n")
	differing := make([]string, 0)
	for publicID, targets := range targetsByPublic {
		if len(targets) > 1 {
			differing = append(differing, publicID)
		}
	}
	sort.Strings(differing)
	if len(differing) == 0 {
		fmt.Fprintf(&b, "本轮读取到的映射中未发现同名公开模型指向不同上游 ID。\n")
	} else {
		fmt.Fprintf(&b, "以下公开模型存在**线路映射有差异**：\n")
		for _, publicID := range differing {
			fmt.Fprintf(&b, "- %s\n", markdownCode(publicID))
			upstreams := make([]string, 0, len(targetsByPublic[publicID]))
			for upstreamID := range targetsByPublic[publicID] {
				upstreams = append(upstreams, upstreamID)
			}
			sort.Strings(upstreams)
			for _, upstreamID := range upstreams {
				ids := make([]int64, 0, len(targetsByPublic[publicID][upstreamID]))
				for accountID := range targetsByPublic[publicID][upstreamID] {
					ids = append(ids, accountID)
				}
				sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
				fmt.Fprintf(&b, "  - 上游 %s：账号 %s\n", markdownCode(upstreamID), formatScreenIDs(ids))
			}
		}
	}

	uniqueIDs := make([]string, 0, len(uniquePublic))
	for id := range uniquePublic {
		uniqueIDs = append(uniqueIDs, id)
	}
	sort.Strings(uniqueIDs)
	fmt.Fprintf(&b, "\n## 不同公开模型名清单\n\n")
	if len(uniqueIDs) == 0 {
		fmt.Fprintf(&b, "本轮已读取映射中没有公开模型条目。\n")
	} else {
		for _, id := range uniqueIDs {
			fmt.Fprintf(&b, "- %s\n", markdownCode(id))
		}
	}
	return b.String(), nil
}

func screenStatusLabel(status string) string {
	switch status {
	case ScreenSummaryApplied:
		return "已应用（变更账号写后核验；no-op 账号预检核验）"
	case ScreenSummaryPreview:
		return "PREVIEW ONLY / 未应用映射"
	case ScreenSummaryNoPlan:
		return "无可应用计划"
	case ScreenSummaryBlockedAfterDiscovery:
		return "BLOCKED AFTER DISCOVERY / 未应用映射"
	case ScreenSummaryPartial:
		return "PARTIAL / 全账号结果不完整"
	default:
		return "未知状态"
	}
}

func cloneScreenMapping(input map[string]string) map[string]string {
	copy := make(map[string]string, len(input))
	for key, value := range input {
		copy[key] = value
	}
	return copy
}

func equalScreenMappings(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if other, ok := b[key]; !ok || other != value {
			return false
		}
	}
	return true
}

func formatScreenIDs(ids []int64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("#%d", id)
	}
	return strings.Join(parts, ", ")
}

func sortedScreenIDs(ids []int64) []int64 {
	copy := append([]int64(nil), ids...)
	sort.Slice(copy, func(i, j int) bool { return copy[i] < copy[j] })
	return copy
}

type screenAccountCounts struct {
	DetailsRead      int
	Active           int
	Inactive         int
	UnreviewedSource int
	SourceNotChecked int
	CatalogFailures  int
	OtherSkipped     int
	DetailReadFailed int
}

func (c *screenAccountCounts) observe(row DiscoveryAccount) {
	if row.Status == "account_read_failed" {
		c.DetailReadFailed++
		return
	}
	c.DetailsRead++
	if row.Status == "skipped_inactive" {
		c.Inactive++
	} else {
		// Discover marks every detail-read account whose native status is not
		// active as skipped_inactive before evaluating other eligibility gates.
		c.Active++
	}
	if row.SourceProfileStatus == "not_allowlisted_for_target" {
		c.UnreviewedSource++
	}
	if row.SourceProfileStatus == "not_checked" {
		c.SourceNotChecked++
	}
	switch row.Status {
	case "sync_failed", "catalog_unknown", "catalog_invalid":
		c.CatalogFailures++
	}
	if (strings.HasPrefix(row.Status, "skipped") && row.Status != "skipped_inactive") || row.Status == "blocked" {
		c.OtherSkipped++
	}
}

func markdownList(values []string) string {
	items := append([]string(nil), values...)
	sort.Strings(items)
	for i := range items {
		items[i] = markdownCode(items[i])
	}
	return strings.Join(items, ", ")
}

func markdownCode(value string) string {
	var normalized strings.Builder
	for _, r := range value {
		switch r {
		case '\r':
			normalized.WriteString(`\r`)
		case '\n':
			normalized.WriteString(`\n`)
		case '\t':
			normalized.WriteString(`\t`)
		default:
			if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
				fmt.Fprintf(&normalized, `\u{%X}`, r)
			} else {
				normalized.WriteRune(r)
			}
		}
	}
	content := normalized.String()
	longestRun, currentRun := 0, 0
	for _, r := range content {
		if r == '`' {
			currentRun++
			if currentRun > longestRun {
				longestRun = currentRun
			}
		} else {
			currentRun = 0
		}
	}
	fence := strings.Repeat("`", longestRun+1)
	if content != "" && strings.Trim(content, " ") != "" && (strings.HasPrefix(content, " ") || strings.HasSuffix(content, " ")) {
		content = " " + content + " "
	}
	return fence + content + fence
}
