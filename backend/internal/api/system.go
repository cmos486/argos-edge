package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/backup"
)

// systemHealth is the shape returned by GET /api/system/health.
type systemHealth struct {
	Memory      memStats       `json:"memory"`
	Goroutines  int            `json:"goroutines"`
	DB          dbStats        `json:"db"`
	Workers     workerStats    `json:"workers"`
	Scheduler   schedulerStats `json:"scheduler"`
	UptimeSecs  int64          `json:"uptime_seconds"`
	PanelMode   string         `json:"panel_mode"`
	PanelDomain string         `json:"panel_domain,omitempty"`
}

type memStats struct {
	AllocMB uint64 `json:"alloc_mb"`
	SysMB   uint64 `json:"sys_mb"`
	NumGC   uint32 `json:"num_gc"`
}

type dbStats struct {
	SizeBytes        int64 `json:"size_bytes"`
	WALSizeBytes     int64 `json:"wal_size_bytes"`
	OpenConnections  int   `json:"open_connections"`
	IdleConnections  int   `json:"idle_connections"`
	InUseConnections int   `json:"in_use_connections"`
}

type workerStats struct {
	NotificationQueueDepth int    `json:"notification_queue_depth"`
	NotificationQueueCap   int    `json:"notification_queue_cap"`
	NotificationDropped    uint64 `json:"notification_dropped_total"`
}

type schedulerStats struct {
	LastBackupAttempt *time.Time `json:"last_backup_attempt,omitempty"`
	LastBackupStatus  string     `json:"last_backup_status"`
	LastBackupKind    string     `json:"last_backup_kind,omitempty"`
}

// SystemHealth GET /api/system/health (admin-only via Authenticate).
// No cache: fields change too quickly and each call is cheap.
func (h *Handlers) SystemHealth(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	res := systemHealth{
		Memory: memStats{
			AllocMB: m.Alloc / (1 << 20),
			SysMB:   m.Sys / (1 << 20),
			NumGC:   m.NumGC,
		},
		Goroutines:  runtime.NumGoroutine(),
		PanelMode:   h.PanelMode,
		PanelDomain: h.PanelDomain,
	}
	if !h.StartedAt.IsZero() {
		res.UptimeSecs = int64(time.Since(h.StartedAt).Seconds())
	}

	// DB stats: Go's sql pool counters + on-disk file sizes.
	if h.DB != nil {
		s := h.DB.Stats()
		res.DB.OpenConnections = s.OpenConnections
		res.DB.IdleConnections = s.Idle
		res.DB.InUseConnections = s.InUse
	}
	// DB path comes from config but is not handily exposed here; try
	// the compose-default path first. If absent (custom mount), fall
	// back to zero.
	const defaultDBPath = "/data/argos.db"
	if fi, err := os.Stat(defaultDBPath); err == nil {
		res.DB.SizeBytes = fi.Size()
	}
	if fi, err := os.Stat(defaultDBPath + "-wal"); err == nil {
		res.DB.WALSizeBytes = fi.Size()
	}

	// Worker queues.
	if h.NotifEmitter != nil {
		res.Workers.NotificationQueueDepth = h.NotifEmitter.QueueDepth()
		res.Workers.NotificationQueueCap = h.NotifEmitter.QueueCap()
		res.Workers.NotificationDropped = h.NotifEmitter.Dropped()
	}

	// Scheduler: last backup from the manager.
	if h.BackupMgr != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		list, err := h.BackupMgr.List(ctx, 1)
		cancel()
		if err == nil && len(list) > 0 {
			t := list[0].CreatedAt
			res.Scheduler.LastBackupAttempt = &t
			res.Scheduler.LastBackupKind = list[0].Kind
			age := time.Since(t)
			switch {
			case age > 48*time.Hour:
				res.Scheduler.LastBackupStatus = "stale"
			default:
				res.Scheduler.LastBackupStatus = "ok"
			}
		} else {
			res.Scheduler.LastBackupStatus = "missing"
		}
	} else {
		res.Scheduler.LastBackupStatus = "missing"
	}
	writeJSON(w, http.StatusOK, res)
}

// backupDirBytes is a small helper: total tar.gz volume on disk.
// Unused today but kept for a future diagnostic.
func backupDirBytes(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}

var _ = backupDirBytes
var _ backup.Backup
