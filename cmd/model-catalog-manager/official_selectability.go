package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"sub2api-model-catalog-manager/internal/catalog"
	"sub2api-model-catalog-manager/internal/config"
	"sub2api-model-catalog-manager/internal/officialselectability"
	"sub2api-model-catalog-manager/internal/state"
)

func syncOfficialSelectabilitySources(ctx context.Context, cfg config.Config, readSecret officialselectability.SecretReader, doer officialselectability.Doer, now func() time.Time) error {
	rules, _, err := catalog.LoadRulesWithHash(cfg.RulesFile)
	if err != nil {
		return errors.New("official selectability refresh blocked: approved rules are unavailable")
	}
	if err := officialselectability.ValidateRuleBindings(rules, cfg.OfficialSelectabilitySources); err != nil {
		return errors.New("official selectability refresh blocked: configured sources and approved product scopes do not match")
	}
	if len(cfg.OfficialSelectabilitySources) == 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	lock, err := state.AcquireLock(filepath.Join(cfg.StateDir, "official-selectability.lock"))
	if err != nil {
		return errors.New("official selectability refresh blocked: another run holds the evidence lock")
	}
	defer lock.Release()
	return officialselectability.Refresh(ctx, cfg.OfficialSelectabilityFile(), cfg.OfficialSelectabilitySources, readSecret, doer, now)
}
