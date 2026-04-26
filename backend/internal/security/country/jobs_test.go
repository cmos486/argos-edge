package country

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// jobsDB returns a fresh in-memory sqlite with the migration 029
// + 032 schemas applied. Mirrors what the migration runner does
// in production but inline so the test is self-contained.
func jobsDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// modernc/sqlite gotcha: each pool connection to :memory:
	// sees a private database. The JobRunner's goroutine writes
	// UPDATE on a different conn than the request's INSERT, so
	// a multi-conn pool would observe "no such table" in the
	// goroutine. Cap to 1 so all ops share the same in-memory db.
	d.SetMaxOpenConns(1)
	t.Cleanup(func() { d.Close() })
	if _, err := d.Exec(`
		CREATE TABLE country_ban_expansions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			country_code TEXT UNIQUE NOT NULL,
			decision_ids TEXT NOT NULL DEFAULT '[]',
			cidr_count INTEGER NOT NULL DEFAULT 0,
			reason TEXT NOT NULL DEFAULT '',
			duration TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_by TEXT NOT NULL DEFAULT '',
			mmdb_version_at_creation TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE country_expansion_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			country_code TEXT NOT NULL,
			state TEXT NOT NULL CHECK (state IN ('pending','running','completed','failed')),
			chunks_total INTEGER NOT NULL DEFAULT 0,
			chunks_done INTEGER NOT NULL DEFAULT 0,
			chunks_failed INTEGER NOT NULL DEFAULT 0,
			cidr_committed INTEGER NOT NULL DEFAULT 0,
			requested_count INTEGER NOT NULL DEFAULT 0,
			duration TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			error_message TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
			created_by TEXT NOT NULL DEFAULT ''
		);
	`); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSubmit_runsToCompletion(t *testing.T) {
	d := jobsDB(t)
	exp, lapi := newExpanderForJobsTest(t, d, []string{
		"1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewJobRunner(ctx, d, exp, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	id, err := r.Submit(context.Background(), "BR", "4h", "test", "alice")
	if err != nil {
		t.Fatal(err)
	}
	// Wait for the goroutine; up to 2s.
	if !waitForJobState(t, r, id, StateCompleted, 2*time.Second) {
		dump := mustGet(t, r, id)
		t.Fatalf("job did not reach completed: %+v", dump)
	}
	got := mustGet(t, r, id)
	if got.CIDRCommitted != 3 {
		t.Fatalf("cidr_committed: %d, want 3", got.CIDRCommitted)
	}
	if got.ChunksFailed != 0 {
		t.Fatalf("chunks_failed: %d, want 0", got.ChunksFailed)
	}
	if got.StartedAt == nil || got.CompletedAt == nil {
		t.Fatalf("timestamps missing: started=%v completed=%v",
			got.StartedAt, got.CompletedAt)
	}
	if len(lapi.pushed) != 3 {
		t.Fatalf("LAPI received %d, want 3", len(lapi.pushed))
	}
}

func TestSubmit_progressCallbackFires(t *testing.T) {
	d := jobsDB(t)
	// 9 CIDRs with chunkSize=3 -> 3 chunks. The progress
	// callback should drive chunks_done from 0 -> 3 in the row.
	cidrs := []string{
		"1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24",
		"4.0.0.0/24", "5.0.0.0/24", "6.0.0.0/24",
		"7.0.0.0/24", "8.0.0.0/24", "9.0.0.0/24",
	}
	exp, _ := newExpanderForJobsTest(t, d, cidrs)
	exp.ChunkSize = 3
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewJobRunner(ctx, d, exp, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	id, err := r.Submit(context.Background(), "BR", "4h", "", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !waitForJobState(t, r, id, StateCompleted, 2*time.Second) {
		t.Fatal("job did not complete")
	}
	got := mustGet(t, r, id)
	if got.ChunksDone != 3 || got.ChunksTotal != 3 {
		t.Fatalf("chunks_done/total = %d/%d, want 3/3",
			got.ChunksDone, got.ChunksTotal)
	}
	if got.CIDRCommitted != 9 {
		t.Fatalf("cidr_committed: %d, want 9", got.CIDRCommitted)
	}
}

func TestSubmit_LAPIErrorMarksFailed(t *testing.T) {
	d := jobsDB(t)
	exp, lapi := newExpanderForJobsTest(t, d, []string{"1.0.0.0/24"})
	lapi.failAllBatches = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewJobRunner(ctx, d, exp, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	id, err := r.Submit(context.Background(), "BR", "4h", "", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !waitForJobState(t, r, id, StateFailed, 2*time.Second) {
		t.Fatalf("job did not reach failed: %+v", mustGet(t, r, id))
	}
	got := mustGet(t, r, id)
	if got.ErrorMessage == "" {
		t.Fatal("error_message empty on failed job")
	}
}

func TestSubmit_serialisesViaMutex(t *testing.T) {
	d := jobsDB(t)
	// LAPI delays each chunk so two concurrent submissions
	// have a window where the mutex is observable. Without
	// the mutex, both would interleave; with it, the second
	// is queued until the first completes.
	cidrs := []string{"1.0.0.0/24"}
	// Two distinct codes; the source must serve both since the
	// mutex test submits BR and DE back-to-back.
	exp, lapi := newExpanderForJobsTest(t, d, cidrs, "BR", "DE")
	lapi.addDelay = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := NewJobRunner(ctx, d, exp, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	id1, _ := r.Submit(context.Background(), "BR", "4h", "", "alice")
	id2, _ := r.Submit(context.Background(), "DE", "4h", "", "alice")

	// Sample states in the window where id1 is running but
	// addDelay (100ms) hasn't elapsed yet, so id2 is still
	// pending behind the mutex. Window is generous (deadline
	// = full delay) since the goroutine schedule is asynchronous.
	sawSerial := false
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		j1 := mustGet(t, r, id1)
		j2 := mustGet(t, r, id2)
		if j1.State == StateRunning && j2.State == StatePending {
			sawSerial = true
			break
		}
		// Stop sampling once id1 reaches a terminal state -- the
		// race window has closed; nothing to observe.
		if j1.State == StateCompleted || j1.State == StateFailed {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !sawSerial {
		t.Fatal("expected to observe id1=running while id2=pending under mutex")
	}
	// Both should eventually complete.
	if !waitForJobState(t, r, id1, StateCompleted, 2*time.Second) {
		t.Fatal("id1 did not complete")
	}
	if !waitForJobState(t, r, id2, StateCompleted, 2*time.Second) {
		t.Fatal("id2 did not complete")
	}
}

func TestRecoverOnBoot_marksPendingAndRunningFailed(t *testing.T) {
	d := jobsDB(t)
	// Inject stale rows directly. RecoverOnBoot should flip
	// both to failed with the standard message.
	_, _ = d.Exec(`INSERT INTO country_expansion_jobs (country_code, state) VALUES (?, ?), (?, ?), (?, ?)`,
		"BR", StatePending,
		"DE", StateRunning,
		"FR", StateCompleted, // already terminal -- untouched
	)
	ctx := context.Background()
	r := NewJobRunner(ctx, d, nil, nil)
	if err := r.RecoverOnBoot(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ := d.Query(`SELECT country_code, state, error_message FROM country_expansion_jobs ORDER BY id`)
	defer rows.Close()
	var got []struct{ cc, state, msg string }
	for rows.Next() {
		var x struct{ cc, state, msg string }
		_ = rows.Scan(&x.cc, &x.state, &x.msg)
		got = append(got, x)
	}
	if len(got) != 3 {
		t.Fatalf("rows: %d", len(got))
	}
	for _, r := range got {
		if r.cc == "FR" {
			if r.state != StateCompleted {
				t.Fatalf("FR was terminal -- should not be touched: %s", r.state)
			}
			continue
		}
		if r.state != StateFailed {
			t.Fatalf("%s expected failed, got %s", r.cc, r.state)
		}
		if r.msg != "panel restarted" {
			t.Fatalf("%s expected panel-restarted message, got %q", r.cc, r.msg)
		}
	}
}

func TestGet_notFound(t *testing.T) {
	d := jobsDB(t)
	ctx := context.Background()
	r := NewJobRunner(ctx, d, nil, nil)
	if _, err := r.Get(ctx, 999); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("expected ErrJobNotFound, got %v", err)
	}
}

func TestListByCountry_filters(t *testing.T) {
	d := jobsDB(t)
	for _, cc := range []string{"BR", "BR", "DE"} {
		_, _ = d.Exec(`INSERT INTO country_expansion_jobs (country_code, state) VALUES (?, 'completed')`, cc)
	}
	ctx := context.Background()
	r := NewJobRunner(ctx, d, nil, nil)

	all, err := r.ListByCountry(ctx, "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("all: %d, want 3", len(all))
	}

	br, err := r.ListByCountry(ctx, "br", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(br) != 2 {
		t.Fatalf("BR: %d, want 2", len(br))
	}
	for _, j := range br {
		if j.CountryCode != "BR" {
			t.Fatalf("filter leaked: %s", j.CountryCode)
		}
	}
}

// === helpers ==================================================

// newExpanderForJobsTest wraps an Expander around the existing
// fakeLAPI / fakeSource helpers (defined in expander_test.go) so
// the JobRunner tests don't need a parallel set of fakes. Pass
// extra country codes when the test submits multiple jobs;
// default registers BR only.
func newExpanderForJobsTest(t *testing.T, d *sql.DB, cidrs []string, extraCodes ...string) (*Expander, *fakeLAPI) {
	t.Helper()
	codes := append([]string{"BR"}, extraCodes...)
	byCode := make(map[string][]string, len(codes))
	for _, c := range codes {
		byCode[c] = cidrs
	}
	src := &fakeSource{byCode: byCode, version: "test"}
	lapi := &fakeLAPI{}
	return &Expander{DB: d, LAPI: lapi, Source: src}, lapi
}

func waitForJobState(t *testing.T, r *JobRunner, id int64, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		j, err := r.Get(context.Background(), id)
		if err == nil && j.State == want {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func mustGet(t *testing.T, r *JobRunner, id int64) *Job {
	t.Helper()
	j, err := r.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get %d: %v", id, err)
	}
	return j
}
