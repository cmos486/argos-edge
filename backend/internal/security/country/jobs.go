package country

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Job mirrors a country_expansion_jobs row 1:1 plus the helper
// nullables for started_at / completed_at decoded from the DB.
type Job struct {
	ID             int64      `json:"id"`
	CountryCode    string     `json:"country_code"`
	State          string     `json:"state"`
	ChunksTotal    int        `json:"chunks_total"`
	ChunksDone     int        `json:"chunks_done"`
	ChunksFailed   int        `json:"chunks_failed"`
	CIDRCommitted  int        `json:"cidr_committed"`
	RequestedCount int        `json:"requested_count"`
	Duration       string     `json:"duration"`
	Reason         string     `json:"reason"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	CreatedBy      string     `json:"created_by"`
}

// Job-state literals. The migration's CHECK constraint pins these.
const (
	StatePending   = "pending"
	StateRunning   = "running"
	StateCompleted = "completed"
	StateFailed    = "failed"
)

// ErrJobNotFound signals "no row with that id". API maps to 404.
var ErrJobNotFound = errors.New("country expansion job not found")

// JobRunner owns the country_expansion_jobs table and the single
// background worker that consumes pending rows. v1.3.31 design:
//
//   - Submit() inserts a row with state=pending, kicks off a
//     goroutine that waits on the global mu and then runs the
//     expansion via Expander.BanWithProgress.
//   - Single worker (one expansion at a time globally). Concurrent
//     country expansions would re-trigger the v1.3.22 LAPI WAL
//     contention finding -- this keeps the LAPI writer-pressure
//     bounded.
//   - Boot-time recovery: pending + running rows the panel was
//     shutdown mid-flight are transitioned to failed with
//     error_message='panel restarted'. The operator can re-submit.
type JobRunner struct {
	db       *sql.DB
	expander *Expander
	logger   *slog.Logger

	// appCtx outlives any single HTTP request; the goroutines
	// spawned by Submit run against it so the expansion survives
	// past the 202 response. main.go passes ctx; the JobRunner's
	// goroutines exit cleanly when ctx is cancelled (SIGTERM).
	appCtx context.Context

	// mu enforces the single-worker invariant. A goroutine acquires
	// it before transitioning pending -> running and releases it
	// after writing the terminal state. Submit returns immediately;
	// queued goroutines block on Lock().
	mu sync.Mutex
}

// NewJobRunner binds the runner to the panel DB + a long-lived
// context (typically main.go's). Boot recovery is NOT auto-run --
// callers invoke RecoverOnBoot() once at startup before serving
// the first HTTP request, so a request that rejoins a stale
// "running" row sees it already transitioned to failed.
func NewJobRunner(ctx context.Context, db *sql.DB, expander *Expander, logger *slog.Logger) *JobRunner {
	return &JobRunner{
		db:       db,
		expander: expander,
		logger:   logger,
		appCtx:   ctx,
	}
}

// RecoverOnBoot transitions any pending/running rows to failed
// with the standard panel-restarted message + completed_at=now.
// Idempotent: re-running on a fresh DB does nothing.
func (r *JobRunner) RecoverOnBoot(ctx context.Context) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE country_expansion_jobs
		SET state = ?,
		    error_message = 'panel restarted',
		    completed_at = CURRENT_TIMESTAMP
		WHERE state IN (?, ?)
	`, StateFailed, StatePending, StateRunning)
	if err != nil {
		return fmt.Errorf("recover boot: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 && r.logger != nil {
		r.logger.Info("country jobs: recovered stale rows",
			"count", n,
			"state", StateFailed)
	}
	return nil
}

// Submit inserts a pending row and kicks off the worker
// goroutine. Returns the new job_id. The goroutine outlives the
// request via r.appCtx; the request-scoped ctx here is only used
// for the initial INSERT.
func (r *JobRunner) Submit(ctx context.Context, countryCode, duration, reason, actor string) (int64, error) {
	if r.expander == nil {
		return 0, errors.New("country expander not wired")
	}
	cc := strings.ToUpper(strings.TrimSpace(countryCode))
	if cc == "" {
		return 0, errors.New("country_code required")
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO country_expansion_jobs
			(country_code, state, duration, reason, created_by)
		VALUES (?, ?, ?, ?, ?)
	`, cc, StatePending, duration, reason, actor)
	if err != nil {
		return 0, fmt.Errorf("insert job: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last id: %w", err)
	}
	go r.runJob(id, cc, duration, reason, actor)
	return id, nil
}

// runJob is the background-worker entry point. Holds the single-
// worker mutex for the entire expansion, so serialised across
// concurrent Submit calls. Each chunk's progress is written
// straight back to the job row via the BanWithProgress callback.
func (r *JobRunner) runJob(jobID int64, cc, duration, reason, actor string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Transition pending -> running. After this point the job is
	// committed to the worker; if the panel restarts before the
	// terminal state lands, RecoverOnBoot transitions it to failed
	// on next start.
	if _, err := r.db.ExecContext(r.appCtx, `
		UPDATE country_expansion_jobs
		SET state = ?, started_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, StateRunning, jobID); err != nil {
		r.warn("transition to running", err, "job_id", jobID)
		return
	}

	// Progress callback writes chunks_done + cidr_committed +
	// chunks_failed live so the polling frontend sees per-chunk
	// updates. UPDATE failure is logged but not fatal -- the
	// expansion continues; only the progress display lags.
	progress := func(chunkIdx, totalChunks, cidrCommitted, chunksFailed int) {
		if _, err := r.db.ExecContext(r.appCtx, `
			UPDATE country_expansion_jobs
			SET chunks_total = ?,
			    chunks_done = ?,
			    chunks_failed = ?,
			    cidr_committed = ?
			WHERE id = ?
		`, totalChunks, chunkIdx, chunksFailed, cidrCommitted, jobID); err != nil {
			r.warn("progress update", err, "job_id", jobID)
		}
	}

	res, err := r.expander.BanWithProgress(r.appCtx, BanRequest{
		CountryCode: cc,
		Duration:    duration,
		Reason:      reason,
		CreatedBy:   actor,
		Progress:    progress,
	})
	if err != nil {
		r.markFailed(jobID, err.Error())
		return
	}
	r.markCompleted(jobID, res)
}

func (r *JobRunner) markCompleted(jobID int64, res *BanResult) {
	if _, err := r.db.ExecContext(r.appCtx, `
		UPDATE country_expansion_jobs
		SET state = ?,
		    cidr_committed = ?,
		    requested_count = ?,
		    chunks_failed = ?,
		    error_message = '',
		    completed_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, StateCompleted, res.CIDRCount, res.RequestedCount, res.FailedChunks, jobID); err != nil {
		r.warn("mark completed", err, "job_id", jobID)
	}
}

func (r *JobRunner) markFailed(jobID int64, errorMessage string) {
	if _, err := r.db.ExecContext(r.appCtx, `
		UPDATE country_expansion_jobs
		SET state = ?,
		    error_message = ?,
		    completed_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, StateFailed, errorMessage, jobID); err != nil {
		r.warn("mark failed", err, "job_id", jobID)
	}
}

// Get returns one job by id. ErrJobNotFound on missing row.
func (r *JobRunner) Get(ctx context.Context, id int64) (*Job, error) {
	row := r.db.QueryRowContext(ctx, jobsSelect+` WHERE id = ?`, id)
	j, err := scanJob(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrJobNotFound
		}
		return nil, err
	}
	return j, nil
}

// ListByCountry returns the most recent jobs for a country code.
// Empty country_code returns the most-recent jobs across all
// countries. Limit caps the result; 0 means default 20.
func (r *JobRunner) ListByCountry(ctx context.Context, countryCode string, limit int) ([]*Job, error) {
	if limit <= 0 {
		limit = 20
	}
	cc := strings.ToUpper(strings.TrimSpace(countryCode))
	var (
		rows *sql.Rows
		err  error
	)
	if cc == "" {
		rows, err = r.db.QueryContext(ctx,
			jobsSelect+` ORDER BY id DESC LIMIT ?`, limit)
	} else {
		rows, err = r.db.QueryContext(ctx,
			jobsSelect+` WHERE country_code = ? ORDER BY id DESC LIMIT ?`,
			cc, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("query jobs: %w", err)
	}
	defer rows.Close()
	out := make([]*Job, 0, limit)
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

const jobsSelect = `
	SELECT id, country_code, state, chunks_total, chunks_done,
	       chunks_failed, cidr_committed, requested_count,
	       duration, reason, error_message,
	       created_at, started_at, completed_at, created_by
	FROM country_expansion_jobs`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanJob(s rowScanner) (*Job, error) {
	var j Job
	var startedAt, completedAt sql.NullTime
	if err := s.Scan(
		&j.ID, &j.CountryCode, &j.State, &j.ChunksTotal, &j.ChunksDone,
		&j.ChunksFailed, &j.CIDRCommitted, &j.RequestedCount,
		&j.Duration, &j.Reason, &j.ErrorMessage,
		&j.CreatedAt, &startedAt, &completedAt, &j.CreatedBy,
	); err != nil {
		return nil, err
	}
	if startedAt.Valid {
		t := startedAt.Time
		j.StartedAt = &t
	}
	if completedAt.Valid {
		t := completedAt.Time
		j.CompletedAt = &t
	}
	return &j, nil
}

func (r *JobRunner) warn(what string, err error, kv ...any) {
	if r.logger == nil {
		return
	}
	args := append([]any{"err", err}, kv...)
	r.logger.Warn("country jobs: "+what, args...)
}
