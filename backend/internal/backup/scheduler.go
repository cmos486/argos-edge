package backup

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// Scheduler runs scheduled backups from backup.schedule and applies
// retention after each run. Settings are read at Start; hot-reload is
// explicitly out of scope (operator restarts the container).
type Scheduler struct {
	Manager *Manager
	DB      *sql.DB
	Emitter *notifications.Emitter

	cron    *cron.Cron
	entryID cron.EntryID
}

// Start parses the configured cron expression and registers the job.
// Returns a cancel func that stops the scheduler.
func (s *Scheduler) Start(ctx context.Context) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	enabled := db.GetSettingValue(ctx, s.DB, "backup.enabled", "true") == "true"
	if !enabled {
		slog.Info("backup scheduler disabled (backup.enabled=false)")
		go func() { <-ctx.Done() }()
		return cancel
	}
	expr := db.GetSettingValue(ctx, s.DB, "backup.schedule", "0 2 * * *")
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	if _, err := parser.Parse(expr); err != nil {
		slog.Warn("backup scheduler: invalid cron, falling back to daily 02:00",
			"expr", expr, "error", err)
		expr = "0 2 * * *"
	}
	s.cron = cron.New(cron.WithParser(parser))
	id, err := s.cron.AddFunc(expr, func() {
		s.runOnce(ctx)
	})
	if err != nil {
		slog.Error("backup scheduler: AddFunc", "error", err)
		cancel()
		return cancel
	}
	s.entryID = id
	s.cron.Start()
	slog.Info("backup scheduler started", "schedule", expr,
		"next", s.cron.Entry(id).Next.Format(time.RFC3339))

	go func() {
		<-ctx.Done()
		stop := s.cron.Stop()
		<-stop.Done()
	}()
	return cancel
}

// NextRuns returns the next N firings of the currently configured
// schedule, for the "Test schedule" UI button. Evaluates the cron
// expression directly -- does not depend on the scheduler being
// running.
func NextRuns(expr string, n int) ([]time.Time, error) {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	sched, err := parser.Parse(expr)
	if err != nil {
		return nil, err
	}
	out := make([]time.Time, 0, n)
	t := time.Now().UTC()
	for i := 0; i < n; i++ {
		t = sched.Next(t)
		out = append(out, t)
	}
	return out, nil
}

// runOnce performs a single scheduled backup, emits notifications
// on success/failure, and applies retention.
func (s *Scheduler) runOnce(ctx context.Context) {
	start := time.Now()
	b, err := s.Manager.Create(ctx, "scheduled", "", nil)
	if err != nil {
		slog.Error("scheduled backup failed", "error", err, "dur", time.Since(start))
		if s.Emitter != nil {
			s.Emitter.Emit(notifications.Event{
				Type:     notifications.EvtBackupFailed,
				Severity: notifications.SeverityError,
				Message:  "scheduled backup failed: " + err.Error(),
				Data:     map[string]any{"kind": "scheduled", "error": err.Error()},
			})
		}
		return
	}
	slog.Info("scheduled backup ok",
		"filename", b.Filename, "size", b.SizeBytes, "dur", time.Since(start))
	if s.Emitter != nil {
		s.Emitter.Emit(notifications.Event{
			Type:     notifications.EvtBackupCompleted,
			Severity: notifications.SeverityInfo,
			Message:  fmt.Sprintf("backup %s (%s) ok", b.Filename, humanSize(b.SizeBytes)),
			Data: map[string]any{
				"filename":   b.Filename,
				"size_bytes": b.SizeBytes,
				"kind":       "scheduled",
			},
		})
	}
	// retention
	retentionDays, _ := strconv.Atoi(db.GetSettingValue(ctx, s.DB, "backup.retention_days", "14"))
	if n, err := s.Manager.Purge(ctx, retentionDays); err != nil {
		slog.Warn("backup retention purge failed", "error", err)
	} else if n > 0 {
		slog.Info("backup retention pruned", "deleted", n, "retention_days", retentionDays)
	}
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n2 := n / unit; n2 >= unit; n2 /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
