package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"sub2api-model-catalog-manager/internal/adminapi"
	"sub2api-model-catalog-manager/internal/app"
	"sub2api-model-catalog-manager/internal/catalog"
	"sub2api-model-catalog-manager/internal/config"
	"sub2api-model-catalog-manager/internal/inventorysummary"
	"sub2api-model-catalog-manager/internal/mergereview"
	"sub2api-model-catalog-manager/internal/officialcatalog"
	"sub2api-model-catalog-manager/internal/report"
	"sub2api-model-catalog-manager/internal/securecred"
	"sub2api-model-catalog-manager/internal/state"
)

const maxPlanBytes = 4 << 20

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	base := officialcatalog.StartupSyncOptions{
		NewDoer: func() officialcatalog.HTTPDoer { return officialcatalog.NewHTTPClient() },
		Now:     time.Now,
	}
	return runWithStartup(args, base, func(options officialcatalog.StartupSyncOptions) officialcatalog.StartupSyncResult {
		return officialcatalog.SyncStartup(context.Background(), options)
	})
}

type startupSyncFunc func(officialcatalog.StartupSyncOptions) officialcatalog.StartupSyncResult
type startupPass func() officialcatalog.StartupSyncResult

func runWithStartup(args []string, base officialcatalog.StartupSyncOptions, syncStartup startupSyncFunc) error {
	args, offline, err := extractOfflineFlag(args)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New("usage: model-catalog-manager <inspect|adopt|discover|apply|run|official-review|inventory-summary|merge-review> [options]")
	}
	if args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "usage: model-catalog-manager [--offline-official-lifecycle] <inspect|adopt|discover|apply|run|official-review|inventory-summary|merge-review> [options]")
		return nil
	}
	pass := func() officialcatalog.StartupSyncResult {
		if syncStartup == nil {
			return officialcatalog.StartupSyncResult{}
		}
		options := base
		options.Offline = offline
		result := syncStartup(options)
		fmt.Fprintln(os.Stderr, "official lifecycle startup sync:", result.Summary())
		return result
	}
	var commandErr error
	switch args[0] {
	case "inspect":
		commandErr = runInspectWithStartup(args[1:], pass)
	case "adopt":
		commandErr = runAdoptWithStartup(args[1:], pass)
	case "discover":
		commandErr = runDiscoverWithStartup(args[1:], pass)
	case "apply":
		commandErr = runApplyWithStartup(args[1:], pass)
	case "run":
		commandErr = runAutomaticWithStartup(args[1:], pass)
	case "official-review":
		commandErr = runOfficialReviewWithStartup(args[1:], pass)
	case "inventory-summary":
		commandErr = runInventorySummaryWithStartup(args[1:], pass)
	case "merge-review":
		commandErr = runMergeReviewWithStartup(args[1:], pass)
	default:
		commandErr = errors.New("unknown command; use inspect, adopt, discover, apply, run, official-review, inventory-summary, or merge-review")
	}
	if errors.Is(commandErr, flag.ErrHelp) {
		return nil
	}
	return commandErr
}

func extractOfflineFlag(args []string) ([]string, bool, error) {
	position := -1
	for i, arg := range args {
		if strings.HasPrefix(arg, "--offline-official-lifecycle=") {
			return nil, false, errors.New("--offline-official-lifecycle does not accept a value")
		}
		if arg != "--offline-official-lifecycle" {
			continue
		}
		if position >= 0 {
			return nil, false, errors.New("--offline-official-lifecycle may be specified only once")
		}
		position = i
	}
	if position < 0 {
		return args, false, nil
	}
	if position > 1 {
		return nil, false, errors.New("--offline-official-lifecycle is allowed only before or immediately after the subcommand")
	}
	remaining := make([]string, 0, len(args)-1)
	remaining = append(remaining, args[:position]...)
	remaining = append(remaining, args[position+1:]...)
	return remaining, true, nil
}

func runMergeReview(args []string) error {
	return runMergeReviewWithStartup(args, nil)
}

func runMergeReviewWithStartup(args []string, startup startupPass) error {
	fs := flag.NewFlagSet("merge-review", flag.ContinueOnError)
	configPath := fs.String("config", "", "local configuration for rules and state paths; no credentials are read")
	inspectPath := fs.String("inspect", "", "complete all-account inspect JSON report")
	discoverPath := fs.String("discover", "", "complete all-account discover JSON report")
	outDir := fs.String("out-dir", "", "private local directory for the review report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *inspectPath == "" || *discoverPath == "" || *outDir == "" || fs.NArg() != 0 {
		return errors.New("merge-review requires --config, --inspect, --discover, and --out-dir")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	inspect, err := mergereview.ReadReport(*inspectPath)
	if err != nil {
		return errors.New("merge-review inspect input is invalid or unavailable")
	}
	discover, err := mergereview.ReadReport(*discoverPath)
	if err != nil {
		return errors.New("merge-review discover input is invalid or unavailable")
	}
	rules, rulesHash, err := catalog.LoadRulesWithHash(cfg.RulesFile)
	if err != nil {
		return err
	}
	local, err := state.Load(filepath.Join(cfg.StateDir, "state.json"))
	if err != nil {
		return err
	}
	value, err := mergereview.Build(inspect, discover, rules, rulesHash, local, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := prepareOutputDirectory(*outDir); err != nil {
		return err
	}
	if startup != nil {
		startup()
	}
	path, err := mergereview.Write(*outDir, value)
	if err != nil {
		return err
	}
	fmt.Printf("merge review complete: accounts=%d live=%d date_candidates=%d alias_rules=%d family_rules=%d no_rule_candidates=%d partial_rule_candidates=%d report=%s\n",
		value.AccountCount, value.Summary.AccountsWithLiveCatalog, value.Summary.DateFamilyCandidates,
		value.RuleCounts.Aliases, value.RuleCounts.VersionFamilies, value.Summary.CandidatesWithNoRule,
		value.Summary.CandidatesWithPartialRule, path)
	return nil
}

func runInventorySummary(args []string) error {
	return runInventorySummaryWithStartup(args, nil)
}

func runInventorySummaryWithStartup(args []string, startup startupPass) error {
	fs := flag.NewFlagSet("inventory-summary", flag.ContinueOnError)
	inspectPath := fs.String("inspect", "", "complete all-account inspect JSON report")
	discoverPath := fs.String("discover", "", "complete all-account discover JSON report")
	outDir := fs.String("out-dir", "", "local directory for the summary report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inspectPath == "" || *discoverPath == "" || *outDir == "" || fs.NArg() != 0 {
		return errors.New("inventory-summary requires --inspect <inspect.json>, --discover <discover.json>, and --out-dir <directory>")
	}
	inspect, err := readInventory(*inspectPath)
	if err != nil {
		return errors.New("inventory-summary inspect input is invalid or unavailable")
	}
	discover, err := readInventory(*discoverPath)
	if err != nil {
		return errors.New("inventory-summary discover input is invalid or unavailable")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return errors.New("inventory-summary report ID could not be created")
	}
	report, err := inventorysummary.Build(inspect, discover, time.Now().UTC(), hex.EncodeToString(id[:]))
	if err != nil {
		return err
	}
	if err := prepareOutputDirectory(*outDir); err != nil {
		return err
	}
	if startup != nil {
		startup()
	}
	path, err := inventorysummary.Write(*outDir, report)
	if err != nil {
		return err
	}
	fmt.Printf("inventory summary complete: accounts=%d public_id_routes=%d upstream_id_reuse=%d discovered_id_reuse=%d conflicts=%d catalog_coverage=%s report=%s\n",
		report.Counts.Accounts, len(report.PublicIDRoutes), len(report.UpstreamIDReuse), len(report.DiscoveredIDReuse), len(report.IntraAccountMappingConflicts), report.CatalogCoverage, path)
	return nil
}

func readInventory(path string) (officialcatalog.Inventory, error) {
	var inventory officialcatalog.Inventory
	f, err := os.Open(path)
	if err != nil {
		return inventory, errors.New("input file unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > officialcatalog.MaxInputReportBytes {
		return inventory, errors.New("input must be a small regular JSON file")
	}
	return officialcatalog.ParseInventory(f)
}

func runOfficialReviewWithStartup(args []string, startup startupPass) error {
	fs := flag.NewFlagSet("official-review", flag.ContinueOnError)
	inputPath := fs.String("input", "", "prior inspect or discover JSON report")
	outDir := fs.String("out-dir", "", "local directory for the read-only review report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" || *outDir == "" || fs.NArg() != 0 {
		return errors.New("official-review requires --input <inspect-or-discover.json> and --out-dir <directory>")
	}
	inventory, err := readInventory(*inputPath)
	if err != nil {
		return errors.New("official-review input report is invalid or unavailable")
	}
	var synced officialcatalog.StartupSyncResult
	if err := prepareOutputDirectory(*outDir); err != nil {
		return err
	}
	if startup != nil {
		synced = startup()
	}
	review, err := officialcatalog.BuildReviewFromStartup(inventory, synced, time.Now)
	if err != nil {
		return err
	}
	path, err := officialcatalog.Write(*outDir, review)
	if err != nil {
		return err
	}
	fmt.Printf("official review complete: observations=%d candidates=%d report=%s\n", len(review.Observations), len(review.NameShape), path)
	return nil
}

func runInspect(args []string) error {
	return runInspectWithStartup(args, nil)
}

func runInspectWithStartup(args []string, startup startupPass) error {
	return runInspectPreparedWithStartup(args, securecred.Read, makeClient, startup)
}

func runInspectPreparedWithStartup(args []string, readCredential app.CredentialReader, newClient app.ClientFactory, startup startupPass) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to local JSON configuration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || fs.NArg() != 0 {
		return errors.New("inspect requires --config <path>")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	inspector := app.Inspector{ReadCredential: readCredential, NewClient: newClient}
	if err := inspector.Preflight(cfg); err != nil {
		return err
	}
	if err := prepareOutputDirectory(cfg.ReportDir); err != nil {
		return err
	}
	if startup != nil {
		startup()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	doc, err := inspector.Inspect(ctx, cfg)
	if err != nil {
		return err
	}
	path, err := report.Write(cfg.ReportDir, doc)
	if err != nil {
		return err
	}
	fmt.Printf("inspection complete: accounts=%d report=%s\n", len(doc.Accounts), path)
	return nil
}

func runAdopt(args []string) error {
	return runAdoptWithStartup(args, nil)
}

func runAdoptWithStartup(args []string, startup startupPass) error {
	return runAdoptPreparedWithStartup(args, securecred.Read, makeClient, startup)
}

func runAdoptPreparedWithStartup(args []string, readCredential app.CredentialReader, newClient app.ClientFactory, startup startupPass) error {
	fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to local JSON configuration")
	accountID := fs.Int64("account-id", 0, "allowlisted account ID")
	keysFile := fs.String("keys-file", "", "JSON string array of exact model_mapping keys")
	expectedHash := fs.String("expected-mapping-hash", "", "SHA256 of the complete current mapping")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *keysFile == "" || *expectedHash == "" || *accountID <= 0 || fs.NArg() != 0 {
		return errors.New("adopt requires --config, --account-id, --keys-file, and --expected-mapping-hash")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	adopter := app.Adopter{ReadCredential: readCredential, NewClient: newClient}
	prepared, err := adopter.Preflight(cfg, *accountID, *keysFile, *expectedHash)
	if err != nil {
		return err
	}
	if err := prepareOutputDirectory(cfg.StateDir); err != nil {
		return err
	}
	if startup != nil {
		startup()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := adopter.AdoptPrepared(ctx, cfg, *accountID, *expectedHash, prepared); err != nil {
		return err
	}
	fmt.Printf("adoption complete: account=%d; local ownership state only; Sub2API was not written\n", *accountID)
	return nil
}

func runDiscover(args []string) error {
	return runDiscoverWithStartup(args, nil)
}

func runDiscoverWith(args []string, readCredential app.CredentialReader, newClient app.ClientFactory) error {
	return runDiscoverPreparedWithStartup(args, readCredential, newClient, nil)
}

func runDiscoverWithStartup(args []string, startup startupPass) error {
	return runDiscoverPreparedWithStartup(args, securecred.Read, makeClient, startup)
}

func runDiscoverPreparedWithStartup(args []string, readCredential app.CredentialReader, newClient app.ClientFactory, startup startupPass) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to local JSON configuration")
	manualSync := fs.Bool("manual-sync-authorized", false, "owner-authorized manual all-account sync; preview only")
	manualOnly := fs.Bool("manual-only", false, "discover only today's native manual_only/skipped accounts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || fs.NArg() != 0 {
		return errors.New("discover requires --config <path>")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *manualSync && (!cfg.AllAccounts() || cfg.ApplyModeValue() != "preview") {
		return errors.New("--manual-sync-authorized requires account_scope=all and apply_mode=preview")
	}
	if *manualOnly && (!cfg.AllAccounts() || *manualSync) {
		return errors.New("--manual-only requires account_scope=all and cannot be combined with --manual-sync-authorized")
	}
	timeout := 90 * time.Second
	if *manualSync {
		timeout = 45 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	discoverer := app.Discoverer{ReadCredential: readCredential, NewClient: newClient, ManualSyncAuthorized: *manualSync, ManualOnlyOnly: *manualOnly}
	prepared, err := discoverer.Preflight(cfg)
	if err != nil {
		return err
	}
	if err := prepareOutputDirectory(cfg.StateDir); err != nil {
		return err
	}
	if err := prepareOutputDirectory(cfg.ReportDir); err != nil {
		return err
	}
	if startup != nil {
		discoverer.LifecycleStartup = startup()
	}
	result, err := discoverer.DiscoverPrepared(ctx, cfg, prepared)
	if err != nil {
		return err
	}
	reportPath, err := report.Write(cfg.ReportDir, result.Report)
	if err != nil {
		return err
	}
	if result.Plan == nil {
		fmt.Printf("discovery complete: no applicable plan; manual_native_sync_override=%t account_scan_status=%s accounts=%d report=%s\n", result.Report.ManualNativeSyncOverride, result.Report.AccountScanStatus, len(result.Report.Discovery), reportPath)
		return nil
	}
	fmt.Printf("discovery complete: manual_native_sync_override=%t accounts=%d report=%s plan=%s plan_sha256=%s\n", result.Report.ManualNativeSyncOverride, len(result.Plan.Accounts), reportPath, result.PlanPath, result.PlanSHA256)
	return nil
}

func runApply(args []string) error {
	return runApplyWithStartup(args, nil)
}

func runApplyWithStartup(args []string, startup startupPass) error {
	return runApplyPreparedWithStartup(args, securecred.Read, makeClient, startup)
}

func runApplyPreparedWithStartup(args []string, readCredential app.CredentialReader, newClient app.ClientFactory, startup startupPass) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to local JSON configuration")
	planPath := fs.String("plan", "", "local JSON plan file")
	confirmSHA := fs.String("confirm-plan-sha256", "", "exact SHA256 of the reviewed raw plan file")
	manualOnly := fs.Bool("manual-only", false, "apply only a plan sourced from today's native manual_only/skipped accounts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *planPath == "" || *confirmSHA == "" || fs.NArg() != 0 {
		return errors.New("apply requires --config <path> --plan <path> --confirm-plan-sha256 <sha256>")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	plan, digest, err := loadPlan(*planPath)
	if err != nil {
		return err
	}
	if digest != *confirmSHA {
		return errors.New("apply blocked: --confirm-plan-sha256 does not match the plan file raw bytes")
	}
	applier := app.Applier{ReadCredential: readCredential, NewClient: newClient, ManualOnlyOnly: *manualOnly}
	prepared, err := applier.Preflight(cfg, plan, digest, *confirmSHA, false)
	if err != nil {
		return err
	}
	if err := prepareOutputDirectory(cfg.StateDir); err != nil {
		return err
	}
	if err := prepareOutputDirectory(cfg.BackupDir); err != nil {
		return err
	}
	if startup != nil {
		applier.LifecycleStartup = startup()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	result, err := applier.ApplyPrepared(ctx, cfg, plan, digest, *confirmSHA, false, prepared)
	if err != nil {
		return fmt.Errorf("apply stopped (%s): %w", result.String(), err)
	}
	fmt.Printf("apply complete: %s\n", result.String())
	return nil
}

func runAutomatic(args []string) error {
	return runAutomaticWithStartup(args, nil)
}

func runAutomaticWith(args []string, readCredential app.CredentialReader, newClient app.ClientFactory) error {
	return runAutomaticPreparedWithStartup(args, readCredential, newClient, nil)
}

func runAutomaticWithStartup(args []string, startup startupPass) error {
	return runAutomaticPreparedWithStartup(args, securecred.Read, makeClient, startup)
}

type fullScreenResult struct {
	SchemaVersion     int    `json:"schema_version"`
	Status            string `json:"status"`
	ReasonCode        string `json:"reason_code"`
	PlannedCount      int    `json:"planned_count"`
	AppliedCount      int    `json:"applied_count"`
	NoopCount         int    `json:"noop_count"`
	FailedCount       int    `json:"failed_count"`
	NotAttemptedCount int    `json:"not_attempted_count"`
	SummaryBasename   string `json:"summary_basename"`
}

var screenSummaryBasenamePattern = regexp.MustCompile(`^screen-summary-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}\.md$`)

func runAutomaticPreparedWithStartup(args []string, readCredential app.CredentialReader, newClient app.ClientFactory, startup startupPass) error {
	fullScreen, invalidFullScreenValue := fullScreenFlagState(args)
	if invalidFullScreenValue {
		terminal := fullScreenResult{SchemaVersion: 1, Status: "failed", ReasonCode: "configuration_invalid"}
		if err := json.NewEncoder(os.Stdout).Encode(terminal); err != nil {
			return errors.New("full-screen result could not be written")
		}
		return errors.New("run received an invalid --full-screen boolean value")
	}
	if !fullScreen {
		return runAutomaticCore(args, readCredential, newClient, startup, nil)
	}
	terminal := fullScreenResult{SchemaVersion: 1, Status: "failed", ReasonCode: "configuration_invalid"}
	err := runAutomaticCore(args, readCredential, newClient, startup, &terminal)
	if !validFullScreenReason(terminal.ReasonCode) {
		terminal.ReasonCode = "configuration_invalid"
		terminal.Status = "failed"
	}
	if terminal.Status == "" {
		terminal.Status = "failed"
	}
	if terminal.SummaryBasename != "" && !screenSummaryBasenamePattern.MatchString(terminal.SummaryBasename) {
		terminal.SummaryBasename = ""
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(terminal); encodeErr != nil {
		return errors.New("full-screen result could not be written")
	}
	return err
}

func requestsFullScreen(args []string) bool {
	enabled, _ := fullScreenFlagState(args)
	return enabled
}

func fullScreenFlagState(args []string) (enabled, invalid bool) {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "--full-screen" || arg == "-full-screen" {
			enabled = true
			continue
		}
		for _, prefix := range []string{"--full-screen=", "-full-screen="} {
			if strings.HasPrefix(arg, prefix) {
				value, err := strconv.ParseBool(strings.TrimPrefix(arg, prefix))
				if err != nil {
					return enabled, true
				}
				enabled = value
				break
			}
		}
	}
	return enabled, false
}

func validFullScreenReason(code string) bool {
	switch code {
	case "completed", "no_applicable_plan", "account_scan_partial", "native_refresh_running", "native_refresh_status_unavailable", "native_refresh_status_unknown", "manager_lock_requires_review", "configuration_invalid", "credential_unavailable", "discovery_failed", "approved_rules_blocked", "apply_partial", "apply_failed":
		return true
	default:
		return false
	}
}

func isManagerLockReviewError(err error) bool {
	return err != nil && err.Error() == "another run may be active or a prior lock needs manual review"
}

func fullScreenApplyFailure(err error, result app.ApplyResult) (string, string) {
	status, reason := "failed", "apply_failed"
	var gate interface{ ReasonCode() string }
	switch {
	case errors.As(err, &gate):
		reason = gate.ReasonCode()
		if len(result.AppliedIDs) > 0 {
			status = "partial"
		} else {
			status = "blocked"
		}
	case isManagerLockReviewError(err):
		if len(result.AppliedIDs) > 0 {
			status, reason = "partial", "apply_partial"
		} else {
			status, reason = "blocked", "manager_lock_requires_review"
		}
	case len(result.AppliedIDs) > 0:
		status, reason = "partial", "apply_partial"
	case strings.Contains(err.Error(), "administrator credential could not be read"):
		reason = "credential_unavailable"
	}
	return status, reason
}

func (r *fullScreenResult) set(status, reason string, plan *catalog.ApprovalPlan, applied app.ApplyResult, summaryPath string) {
	if r == nil {
		return
	}
	r.Status = status
	r.ReasonCode = reason
	r.PlannedCount = 0
	if plan != nil {
		r.PlannedCount = len(plan.Accounts)
	}
	r.AppliedCount = len(applied.AppliedIDs)
	r.NoopCount = len(applied.NoopIDs)
	r.FailedCount = 0
	if applied.FailedID > 0 {
		r.FailedCount = 1
	}
	r.NotAttemptedCount = r.PlannedCount - r.AppliedCount - r.NoopCount - r.FailedCount
	if r.NotAttemptedCount < 0 {
		r.NotAttemptedCount = 0
	}
	r.SummaryBasename = ""
	if summaryPath != "" {
		name := filepath.Base(summaryPath)
		if screenSummaryBasenamePattern.MatchString(name) {
			r.SummaryBasename = name
		}
	}
}

func runAutomaticCore(args []string, readCredential app.CredentialReader, newClient app.ClientFactory, startup startupPass, terminal *fullScreenResult) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to local JSON configuration")
	manualOnly := fs.Bool("manual-only", false, "refresh only accounts marked manual_only/skipped in today's completed 04:00 native run")
	fullScreen := fs.Bool("full-screen", false, "screen all eligible accounts using freshly synced upstream model catalogs")
	previewOnly := fs.Bool("preview-only", false, "with --full-screen, generate reports/plans without applying model mappings")
	if err := fs.Parse(args); err != nil {
		return err
	}
	humanOutput := io.Writer(os.Stdout)
	if *fullScreen {
		humanOutput = os.Stderr
		if terminal != nil {
			terminal.set("failed", "configuration_invalid", nil, app.ApplyResult{}, "")
		}
	}
	if *configPath == "" || fs.NArg() != 0 {
		return errors.New("run requires --config <path>")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if cfg.RequireManualOnlyMode && !*manualOnly {
		return errors.New("run blocked: this config requires --manual-only")
	}
	if *manualOnly && *fullScreen {
		return errors.New("run cannot combine --manual-only and --full-screen")
	}
	if *previewOnly && !*fullScreen {
		return errors.New("run --preview-only requires --full-screen")
	}
	if *fullScreen {
		if !cfg.AllowFullScreenMode || !cfg.AllAccounts() || cfg.RequireManualOnlyMode {
			return errors.New("run --full-screen requires its explicit all-account configuration gate")
		}
		if !*previewOnly {
			_, rulesHash, hashErr := catalog.LoadRulesWithHash(cfg.RulesFile)
			if hashErr != nil {
				return hashErr
			}
			if cfg.ApplyModeValue() != "approved_rules" || cfg.ApprovedRulesSHA256 == "" || cfg.ApprovedRulesSHA256 != rulesHash {
				if terminal != nil {
					terminal.set("blocked", "approved_rules_blocked", nil, app.ApplyResult{}, "")
				}
				return errors.New("run --full-screen blocked before credentials/API access: automatic apply requires an exact approved rules hash")
			}
		}
	} else if cfg.AllowFullScreenMode {
		return errors.New("this config is reserved for --full-screen")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	if *manualOnly && !cfg.AllAccounts() {
		return errors.New("run --manual-only requires account_scope=all")
	}
	discoverer := app.Discoverer{ReadCredential: readCredential, NewClient: newClient, WaitForRefresh: !*fullScreen, ManualOnlyOnly: *manualOnly, FullScreen: *fullScreen}
	prepared, err := discoverer.Preflight(cfg)
	if err != nil {
		return err
	}
	if terminal != nil {
		terminal.set("failed", "discovery_failed", nil, app.ApplyResult{}, "")
	}
	if err := prepareOutputDirectory(cfg.StateDir); err != nil {
		return err
	}
	if err := prepareOutputDirectory(cfg.ReportDir); err != nil {
		return err
	}
	if err := prepareOutputDirectory(cfg.BackupDir); err != nil {
		return err
	}
	lifecycleStartup := officialcatalog.StartupSyncResult{}
	if startup != nil {
		lifecycleStartup = startup()
		discoverer.LifecycleStartup = lifecycleStartup
	}
	result, err := discoverer.DiscoverPrepared(ctx, cfg, prepared)
	if err != nil {
		if terminal != nil {
			var gate interface{ ReasonCode() string }
			switch {
			case errors.As(err, &gate):
				terminal.set("blocked", gate.ReasonCode(), nil, app.ApplyResult{}, "")
			case isManagerLockReviewError(err):
				terminal.set("blocked", "manager_lock_requires_review", nil, app.ApplyResult{}, "")
			case strings.Contains(err.Error(), "administrator credential could not be read"):
				terminal.set("failed", "credential_unavailable", nil, app.ApplyResult{}, "")
			}
		}
		return err
	}
	if terminal != nil {
		terminal.set("failed", "discovery_failed", result.Plan, app.ApplyResult{}, "")
	}
	reportPath, err := report.Write(cfg.ReportDir, result.Report)
	if err != nil {
		return err
	}
	if result.Plan == nil {
		if !*fullScreen {
			fmt.Fprintf(humanOutput, "run complete: manual_only=%t full_screen=false preview_only=%t; no applicable plan; account_scan_status=%s accounts=%d report=%s\n", *manualOnly, *previewOnly, result.Report.AccountScanStatus, len(result.Report.Discovery), reportPath)
			return nil
		}
		status := report.ScreenSummaryNoPlan
		if result.Report.AccountScanStatus == "partial" {
			status = report.ScreenSummaryPartial
		}
		summaryPath, summaryJSON, summaryErr := writeScreenSummary(cfg.ReportDir, result.Report, nil, report.ScreenSummaryOutcome{Status: status, ReportPath: reportPath})
		if summaryErr != nil {
			return summaryErr
		}
		if result.Report.AccountScanStatus == "partial" {
			terminal.set("partial", "account_scan_partial", nil, app.ApplyResult{}, summaryPath)
		} else {
			terminal.set("no_plan", "no_applicable_plan", nil, app.ApplyResult{}, summaryPath)
		}
		fmt.Fprintf(humanOutput, "run complete: status=%s manual_only=%t full_screen=%t preview_only=%t; no applicable plan; account_scan_status=%s accounts=%d report=%s summary=%s\n", status, *manualOnly, *fullScreen, *previewOnly, result.Report.AccountScanStatus, len(result.Report.Discovery), reportPath, summaryPath)
		fmt.Fprintf(humanOutput, "summary_path_json=%s\n", summaryJSON)
		if result.Report.AccountScanStatus == "partial" {
			return errors.New("full-screen account scan was incomplete")
		}
		return nil
	}
	if *previewOnly {
		summaryPath, summaryJSON, summaryErr := writeScreenSummary(cfg.ReportDir, result.Report, result.Plan, report.ScreenSummaryOutcome{Status: report.ScreenSummaryPreview, PlanSHA256: result.PlanSHA256, ReportPath: reportPath, PlanPath: result.PlanPath})
		if summaryErr != nil {
			return summaryErr
		}
		terminal.set("failed", "configuration_invalid", result.Plan, app.ApplyResult{}, summaryPath)
		fmt.Fprintf(humanOutput, "run complete: status=%s full_screen=true preview_only=true; no model mappings applied; account_scan_status=%s accounts=%d report=%s plan=%s plan_sha256=%s summary=%s\n", report.ScreenSummaryPreview, result.Report.AccountScanStatus, len(result.Report.Discovery), reportPath, result.PlanPath, result.PlanSHA256, summaryPath)
		fmt.Fprintf(humanOutput, "summary_path_json=%s\n", summaryJSON)
		return errors.New("full-screen preview-only mode did not apply mappings")
	}
	_, rulesHash, err := catalog.LoadRulesWithHash(cfg.RulesFile)
	if err != nil {
		return err
	}
	if cfg.ApplyModeValue() != "approved_rules" || cfg.ApprovedRulesSHA256 == "" || cfg.ApprovedRulesSHA256 != rulesHash {
		if !*fullScreen {
			fmt.Fprintf(humanOutput, "run complete: manual_only=%t preview only; approved rules hash is absent or mismatched; report=%s plan=%s plan_sha256=%s\n", *manualOnly, reportPath, result.PlanPath, result.PlanSHA256)
			return nil
		}
		summaryPath, summaryJSON, summaryErr := writeScreenSummary(cfg.ReportDir, result.Report, result.Plan, report.ScreenSummaryOutcome{Status: report.ScreenSummaryBlockedAfterDiscovery, PlanSHA256: result.PlanSHA256, ReportPath: reportPath, PlanPath: result.PlanPath})
		if summaryErr != nil {
			return summaryErr
		}
		terminal.set("blocked", "approved_rules_blocked", result.Plan, app.ApplyResult{}, summaryPath)
		fmt.Fprintf(humanOutput, "run complete: status=%s; approved rules changed after discovery or no longer match; mapping apply was blocked; report=%s plan=%s plan_sha256=%s summary=%s\n", report.ScreenSummaryBlockedAfterDiscovery, reportPath, result.PlanPath, result.PlanSHA256, summaryPath)
		fmt.Fprintf(humanOutput, "summary_path_json=%s\n", summaryJSON)
		return errors.New("approved rules changed after full-screen discovery; mapping apply was blocked")
	}
	if terminal != nil {
		terminal.set("failed", "apply_failed", result.Plan, app.ApplyResult{}, "")
	}
	applier := app.Applier{ReadCredential: readCredential, NewClient: newClient, ManualOnlyOnly: *manualOnly, FullScreen: *fullScreen, LifecycleStartup: lifecycleStartup}
	applyPrepared, err := applier.Preflight(cfg, *result.Plan, result.PlanSHA256, "", true)
	if err != nil {
		if terminal != nil {
			status, reason := fullScreenApplyFailure(err, app.ApplyResult{})
			terminal.set(status, reason, result.Plan, app.ApplyResult{}, "")
		}
		return err
	}
	applyResult, err := applier.ApplyPrepared(ctx, cfg, *result.Plan, result.PlanSHA256, "", true, applyPrepared)
	if err != nil {
		if *fullScreen {
			if terminal != nil {
				status, reason := fullScreenApplyFailure(err, applyResult)
				terminal.set(status, reason, result.Plan, applyResult, "")
			}
			return fullScreenApplyError(applyResult, reportPath, result.PlanPath, err)
		}
		return fmt.Errorf("run stopped (%s): %w", applyResult.String(), err)
	}
	if !*fullScreen {
		fmt.Fprintf(humanOutput, "run complete: manual_only=%t full_screen=false %s report=%s plan=%s\n", *manualOnly, applyResult.String(), reportPath, result.PlanPath)
		return nil
	}
	summaryPath, summaryJSON, summaryErr := writeScreenSummary(cfg.ReportDir, result.Report, result.Plan, report.ScreenSummaryOutcome{Status: report.ScreenSummaryApplied, AppliedIDs: applyResult.AppliedIDs, NoopIDs: applyResult.NoopIDs, Consumed: applyResult.Consumed, PlanSHA256: result.PlanSHA256, ReportPath: reportPath, PlanPath: result.PlanPath})
	if summaryErr != nil {
		if terminal != nil {
			status, reason := "failed", "apply_failed"
			if len(applyResult.AppliedIDs) > 0 {
				status, reason = "partial", "apply_partial"
			}
			terminal.set(status, reason, result.Plan, applyResult, "")
		}
		return fmt.Errorf("mapping apply completed (%s applied_ids=%v no_op_ids=%v), but the local summary could not be written; do not blindly rerun: %w", applyResult.String(), sortedAccountIDs(applyResult.AppliedIDs), sortedAccountIDs(applyResult.NoopIDs), summaryErr)
	}
	terminal.set("succeeded", "completed", result.Plan, applyResult, summaryPath)
	fmt.Fprintf(humanOutput, "run complete: status=%s manual_only=%t full_screen=%t %s report=%s plan=%s summary=%s\n", report.ScreenSummaryApplied, *manualOnly, *fullScreen, applyResult.String(), reportPath, result.PlanPath, summaryPath)
	fmt.Fprintf(humanOutput, "summary_path_json=%s\n", summaryJSON)
	return nil
}

func fullScreenApplyError(result app.ApplyResult, reportPath, planPath string, cause error) error {
	return fmt.Errorf("run stopped (%s applied_ids=%v no_op_ids=%v report=%s plan=%s): apply may have partially succeeded; do not blindly rerun before checking the verified IDs and backups: %w", result.String(), sortedAccountIDs(result.AppliedIDs), sortedAccountIDs(result.NoopIDs), reportPath, planPath, cause)
}

func writeScreenSummary(dir string, doc report.Document, plan *catalog.ApprovalPlan, outcome report.ScreenSummaryOutcome) (string, string, error) {
	path, err := report.WriteScreenSummary(dir, doc, plan, outcome)
	if err != nil {
		return "", "", err
	}
	encodedPath, err := json.Marshal(path)
	if err != nil {
		return "", "", errors.New("screen summary path could not be encoded")
	}
	return path, string(encodedPath), nil
}

func sortedAccountIDs(ids []int64) []int64 {
	copy := append([]int64(nil), ids...)
	sort.Slice(copy, func(i, j int) bool { return copy[i] < copy[j] })
	return copy
}

func makeClient(base string) (app.AdminAPI, error) { return adminapi.New(base) }

func prepareOutputDirectory(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("local output directory is unavailable")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return errors.New("local output directory could not be prepared")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return errors.New("local output path is not a directory")
	}
	return nil
}

func loadPlan(path string) (catalog.ApprovalPlan, string, error) {
	var plan catalog.ApprovalPlan
	f, err := os.Open(path)
	if err != nil {
		return plan, "", errors.New("plan file is unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPlanBytes {
		return plan, "", errors.New("plan file must be a small regular JSON file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPlanBytes+1))
	if err != nil || len(data) > maxPlanBytes {
		return plan, "", errors.New("plan file exceeds size limit")
	}
	defer zero(data)
	h := sha256.Sum256(data)
	digest := hex.EncodeToString(h[:])
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&plan); err != nil {
		return plan, "", errors.New("plan file is invalid")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return plan, "", errors.New("plan file has trailing data")
	}
	if err := plan.ValidateShape(time.Now().UTC()); err != nil {
		return plan, "", errors.New("plan file failed structural or expiry validation")
	}
	return plan, digest, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
