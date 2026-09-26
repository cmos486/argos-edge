package logs

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

// Hourly rollup job (v1.3.42.0). Runs inside the retention goroutine so
// it never overlaps the purge: the boot backfill follows the boot
// purge, the hourly fill runs at HH:02, and the 6 h tick runs purge,
// rollup retention and the drift check in that order.

const (
	// SettingRollupDays is how many days of closed hours log_hourly keeps.
	SettingRollupDays = "logs.rollup_days"
	// DefaultRollupDays makes 30 d dashboards possible without touching
	// log_entries retention.
	DefaultRollupDays = 90
	// State keys, read-only in Settings and in /api/logs/pipeline.
	SettingRollupLastHour  = "logs.rollup.last_hour"
	SettingRollupLastRunAt = "logs.rollup.last_run_at"
	SettingRollupDrift     = "logs.rollup.drift"
	SettingRollupDriftAt   = "logs.rollup.drift_checked_at"
)

// RollupPause sits between hours of a fill run so a backfill of a week
// never holds the writer for more than one hour's work at a time.
var RollupPause = 100 * time.Millisecond

// RollupFillDelay is how long after the hour boundary the hourly fill
// runs (HH:02), leaving the ingestor's flush ticker time to land the
// last rows of the closed hour.
var RollupFillDelay = 2 * time.Minute

// rollupFillMissing fills every closed hour the rollup lacks. It starts
// at MAX(hour) (re-filling the newest hour, so rows that landed after
// its first fill, e.g. after a restart, are counted) or at the oldest
// log_entries hour when the rollup is empty, and stops before the hour
// in progress. Idempotent; reason names the caller in the log line.
func rollupFillMissing(ctx context.Context, d *sql.DB, reason string) {
	now := time.Now().UTC()
	lastClosed := now.Truncate(time.Hour) // hours < lastClosed are closed
	start, ok, err := db.RollupMaxHour(ctx, d)
	if err != nil {
		slog.Error("rollup: max hour", "error", err)
		return
	}
	if !ok {
		start, ok, err = db.LogEntriesMinHour(ctx, d)
		if err != nil {
			slog.Error("rollup: min log hour", "error", err)
			return
		}
		if !ok {
			return // nothing to roll up yet
		}
	}
	if !start.Before(lastClosed) {
		return
	}
	runStart := time.Now()
	hours, groups, paths := 0, int64(0), int64(0)
	var slowest db.RollupFillResult
	for h := start; h.Before(lastClosed); h = h.Add(time.Hour) {
		if ctx.Err() != nil {
			return
		}
		res, err := db.FillRollupHour(ctx, d, h)
		if err != nil {
			slog.Error("rollup: fill hour failed", "hour", h.Format(time.RFC3339), "error", err, "reason", reason)
			return
		}
		hours++
		groups += res.Rows
		paths += res.PathRows
		if res.Elapsed > slowest.Elapsed {
			slowest = res
		}
		if res.Elapsed > 3*time.Second {
			slog.Warn("rollup: slow hour", "hour", h.Format(time.RFC3339), "elapsed", res.Elapsed.Round(time.Millisecond).String())
		}
		_ = db.UpsertSetting(ctx, d, SettingRollupLastHour, h.Format(time.RFC3339))
		_ = db.UpsertSetting(ctx, d, SettingRollupLastRunAt, time.Now().UTC().Format(time.RFC3339))
		if hours > 1 || h.Add(time.Hour).Before(lastClosed) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(RollupPause):
			}
		}
	}
	slog.Info("rollup: fill done", "reason", reason, "hours", hours, "groups", groups, "paths", paths,
		"total", time.Since(runStart).Round(time.Millisecond).String(),
		"slowest_hour", slowest.Hour.Format(time.RFC3339), "slowest", slowest.Elapsed.Round(time.Millisecond).String(),
		"from", start.Format(time.RFC3339), "to", lastClosed.Add(-time.Hour).Format(time.RFC3339))
}

// rollupDriftCheck compares the newest closed hour at least two hours
// old with the raw rows (tolerance 0), persists the verdict for the
// pipeline endpoint and logs a drift with both sides.
func rollupDriftCheck(ctx context.Context, d *sql.DB) {
	maxHour, ok, err := db.RollupMaxHour(ctx, d)
	if err != nil || !ok {
		return
	}
	hour := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	if maxHour.Before(hour) {
		hour = maxHour
	}
	res, err := db.RollupDrift(ctx, d, hour)
	if err != nil {
		slog.Error("rollup: drift check failed", "error", err)
		return
	}
	verdict := "0"
	if !res.Agrees() {
		verdict = fmt.Sprintf("hour %s: raw rows %d vs rollup %d, raw bytes %d vs rollup %d, classes raw %v rollup %v",
			hour.Format(time.RFC3339), res.RawRows, res.RollupRequests, res.RawBytes, res.RollupBytes, res.RawByClass, res.RollupByClass)
		slog.Warn("rollup drift", "hour", hour.Format(time.RFC3339), "raw_rows", res.RawRows, "rollup_requests", res.RollupRequests,
			"raw_bytes", res.RawBytes, "rollup_bytes", res.RollupBytes)
	} else {
		slog.Info("rollup drift check", "hour", hour.Format(time.RFC3339), "drift", 0, "rows", res.RawRows)
	}
	_ = db.UpsertSetting(ctx, d, SettingRollupDrift, verdict)
	_ = db.UpsertSetting(ctx, d, SettingRollupDriftAt, time.Now().UTC().Format(time.RFC3339))
}

// rollupPurge drops rollup hours older than logs.rollup_days.
func rollupPurge(ctx context.Context, d *sql.DB) {
	days := settingInt(ctx, d, SettingRollupDays, DefaultRollupDays)
	if days <= 0 {
		days = DefaultRollupDays
	}
	n, err := db.PurgeRollup(ctx, d, time.Now().UTC().Add(-time.Duration(days)*24*time.Hour))
	if err != nil {
		slog.Error("rollup: purge failed", "error", err)
		return
	}
	if n > 0 {
		slog.Info("rollup purge done", "removed_hours_rows", n, "rollup_days", days)
	}
}

// RollupState is what /api/logs/pipeline and Settings show.
func RollupState(ctx context.Context, d *sql.DB) map[string]any {
	return map[string]any{
		"days":             settingInt(ctx, d, SettingRollupDays, DefaultRollupDays),
		"last_hour":        db.GetSettingValue(ctx, d, SettingRollupLastHour, ""),
		"last_run_at":      db.GetSettingValue(ctx, d, SettingRollupLastRunAt, ""),
		"drift":            db.GetSettingValue(ctx, d, SettingRollupDrift, ""),
		"drift_checked_at": db.GetSettingValue(ctx, d, SettingRollupDriftAt, ""),
	}
}

// RunRollupOnce is the operator's hook (tests, smokes): fill missing
// hours, then check drift.
func RunRollupOnce(ctx context.Context, d *sql.DB) {
	rollupFillMissing(ctx, d, "manual")
	rollupDriftCheck(ctx, d)
}

// nextFillAt returns the next HH:02 after now.
func nextFillAt(now time.Time) time.Time {
	next := now.UTC().Truncate(time.Hour).Add(RollupFillDelay)
	if !next.After(now) {
		next = next.Add(time.Hour)
	}
	return next
}
