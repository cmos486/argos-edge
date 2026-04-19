package logs

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

// StartRetention launches a goroutine that purges log_entries every
// 6 hours and VACUUMs the DB on the first of each month. Returns a
// cancel func the caller invokes at shutdown.
func StartRetention(ctx context.Context, d *sql.DB) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go retentionLoop(ctx, d)
	return cancel
}

func retentionLoop(ctx context.Context, d *sql.DB) {
	// Run once at boot so an operator that changed retention sees the
	// effect without waiting six hours.
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
	retention := settingInt(ctx, d, "logs.retention_days", 30)
	cap := settingInt(ctx, d, "logs.max_entries", 500000)
	n, err := db.PurgeOld(ctx, d, retention, cap)
	if err != nil {
		slog.Error("retention purge failed", "error", err)
		return 0
	}
	if n > 0 {
		slog.Info("retention purge done", "removed", n,
			"retention_days", retention, "max_entries", cap)
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
