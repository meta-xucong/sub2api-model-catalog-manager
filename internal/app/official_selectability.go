package app

import (
	"errors"
	"path/filepath"
	"sort"
	"time"

	"sub2api-model-catalog-manager/internal/catalog"
	"sub2api-model-catalog-manager/internal/config"
	"sub2api-model-catalog-manager/internal/officialselectability"
	"sub2api-model-catalog-manager/internal/state"
)

func loadRulesWithOfficialSnapshot(cfg config.Config, now time.Time) (catalog.Rules, string, string, error) {
	rules, rulesHash, err := catalog.LoadRulesWithHash(cfg.RulesFile)
	if err != nil {
		return catalog.Rules{}, "", "", err
	}
	if err := officialselectability.ValidateRuleBindings(rules, cfg.OfficialSelectabilitySources); err != nil {
		return catalog.Rules{}, "", "", err
	}
	if len(cfg.OfficialSelectabilitySources) == 0 {
		return rules, rulesHash, "", nil
	}
	snapshots, fileHash, err := officialselectability.LoadWithDigest(cfg.OfficialSelectabilityFile(), cfg.OfficialSelectabilitySources, now.UTC())
	if err != nil {
		return catalog.Rules{}, "", "", err
	}
	configured := make(map[string]bool, len(cfg.OfficialSelectabilitySources))
	for _, source := range cfg.OfficialSelectabilitySources {
		configured[source.Scope] = true
	}
	merged := make([]catalog.OfficialSelectability, 0, len(rules.OfficialSelectability)+len(snapshots))
	for _, snapshot := range rules.OfficialSelectability {
		if !configured[snapshot.Scope] {
			merged = append(merged, snapshot)
		}
	}
	merged = append(merged, snapshots...)
	sort.Slice(merged, func(i, j int) bool { return merged[i].Scope < merged[j].Scope })
	rules.OfficialSelectability = merged
	if err := rules.Validate(); err != nil {
		return catalog.Rules{}, "", "", errors.New("official selectability snapshot conflicts with the approved rules")
	}
	return rules, rulesHash, fileHash, nil
}

// loadRulesForRun selects the evidence boundary for a screening run. The
// full-screen 404token workflow treats its freshly synchronized upstream list
// as the availability source and never loads or fetches provider snapshots.
func loadRulesForRun(cfg config.Config, fullScreen bool, now time.Time) (catalog.Rules, string, string, error) {
	if fullScreen {
		rules, rulesHash, err := catalog.LoadRulesWithHash(cfg.RulesFile)
		return rules, rulesHash, "", err
	}
	return loadRulesWithOfficialSnapshot(cfg, now)
}

func acquireOfficialSelectabilityLock(cfg config.Config) (*state.Lock, error) {
	if len(cfg.OfficialSelectabilitySources) == 0 {
		return nil, nil
	}
	return state.AcquireLock(filepath.Join(cfg.StateDir, "official-selectability.lock"))
}
