package logs

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/totp"
)

// BootPurgeDelay is how long after StartRetention the first purge runs
// (v1.3.38.3). It used to run immediately at boot, which held the
// single SQLite connection for ~1.5 s on a 500k-row DB while the rest
// of the boot (backup reconcile, caddy reconcile) queued behind it and
// the listener was not up yet. Two minutes after start the panel has
// been serving for a while and the purge competes like any other
// background job; the 6 h cadence is unchanged.
var BootPurgeDelay = 2 * time.Minute

// StartRetention launches a goroutine that purges log_entries every
// 6 hours (first run BootPurgeDelay after start) and VACUUMs the DB on
// the first of each month. Returns a cancel func the caller invokes at
// shutdown.
func StartRetention(ctx context.Context, d *sql.DB) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go retentionLoop(ctx, d)
	return cancel
}
func retentionLoop(ctx context.Context, d *sql.DB) {
	// First run deferred so boot-to-listen never waits on a purge; an
	// operator that changed retention still sees the effect within
	// minutes rather than six hours.
	first := time.NewTimer(BootPurgeDelay)
	select {
	case <-ctx.Done():
		first.Stop()
		return
	case <-first.C:
	}
	runPurge(ctx, d)
	maybeVacuum(ctx, d)
	purgeTicker := time.NewTicker(6 * time.Hour)
	defer purgeTicker.Stop()
	vacuumTicker := time.NewTicker(24 * time.Hour)
	defer vacuumTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-purgeTicker.C:
			runPurge(ctx, d)
		case <-vacuumTicker.C:
			maybeVacuum(ctx, d)
		}
	}
}

// RunPurgeOnce is exported so POST /api/logs/purge can invoke the same
// path as the scheduled cron.
func RunPurgeOnce(ctx context.Context, d *sql.DB) (int, error) {
	return runPurge(ctx, d), nil
}

func runPurge(ctx context.Context, d *sql.DB) int {
	// v1.3.40.0: per-source days, raw strip on access rows past
	// RawHours (watermark so each run visits only what aged since
	// the previous one), and a bounded cap check that only runs
	// COUNT(*) when the id range says the table may be over the cap.
	policy := LoadRetentionPolicy(ctx, d)
	var watermark time.Time
	if v := db.GetSettingValue(ctx, d, SettingRawWatermark, ""); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			watermark = t.UTC()
		}
	}
	res, err := db.PurgeWithPolicy(ctx, d, policy.purgePolicy(watermark), db.PurgeBatchSize, db.PurgeBatchPause)
	if err != nil {
		slog.Error("retention purge failed", "error", err)
		return res.Removed
	}
	if res.RawWatermark.After(watermark) {
		_ = db.UpsertSetting(ctx, d, SettingRawWatermark, res.RawWatermark.UTC().Format(time.RFC3339))
	}
	n := res.Removed
	if n > 0 || res.RawStripped > 0 {
		slog.Info("retention purge done", "removed", n, "raw_stripped", res.RawStripped,
			"cap_bound", res.CapBound, "cap_counted", res.CapCounted,
			"source_days", policy.SourceDays, "default_days", policy.DefaultDays,
			"max_entries", policy.MaxEntries, "raw_hours", policy.RawHours)
	}
	// Phase 9b: also drop login_attempts older than 24h so the
	// rate-limit table does not grow forever. The window is fixed
	// (not a setting) because the rate-limit logic only ever looks
	// back 5 minutes.
	if res, err := d.ExecContext(ctx,
		`DELETE FROM login_attempts WHERE timestamp < datetime('now','-24 hours')`); err == nil {
		if removed, _ := res.RowsAffected(); removed > 0 {
			slog.Info("login_attempts purge done", "removed", removed)
		}
	}
	// Phase 2FA: same story for totp_attempts. The TOTP rate-limit
	// only looks back 15 minutes so 24h of retention is already a
	// buffer; the helper is in internal/totp to keep the DELETE and
	// its cutoff co-located with the rate-limit logic.
	if removed, err := totp.PurgeTOTPAttempts(ctx, d); err == nil && removed > 0 {
		slog.Info("totp_attempts purge done", "removed", removed)
	}
	return n
}

// maybeVacuum runs VACUUM when the current day of month is 1 and the
// hour has just crossed 04 UTC. Called every 24h (tolerant of ±1h).
func maybeVacuum(ctx context.Context, d *sql.DB) {
	now := time.Now().UTC()
	if now.Day() != 1 || now.Hour() != 4 {
		return
	}
	if err := db.Vacuum(ctx, d); err != nil {
		slog.Error("vacuum failed", "error", err)
		return
	}
	slog.Info("vacuum completed")
}

func settingInt(ctx context.Context, d *sql.DB, key string, fallback int) int {
	s := db.GetSettingValue(ctx, d, key, "")
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}
