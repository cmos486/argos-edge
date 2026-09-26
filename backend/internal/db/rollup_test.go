package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

func rowsFor(hour time.Time, host1, host2 int64) []models.LogEntry {
	mk := func(off int, host *int64, status, dur, size int, path string) models.LogEntry {
		return models.LogEntry{Timestamp: hour.Add(time.Duration(off) * time.Second), Source: models.LogCaddyAccess,
			HostID: host, HostDomain: "h", Method: "GET", Path: path, Status: status, DurationMs: dur, SizeBytes: size, Level: "info"}
	}
	rows := []models.LogEntry{
		mk(1, &host1, 200, 10, 100, "/a"), mk(2, &host1, 200, 20, 100, "/a"), mk(3, &host1, 200, 30, 100, "/b"),
		mk(4, &host1, 403, 40, 50, "/x"), mk(5, &host1, 429, 2000, 10, "/y"),
		mk(6, &host2, 200, 60, 1000, "/c"), mk(7, &host2, 500, 700, 0, "/c"),
		mk(8, nil, 200, 5, 1, "/nohost"),
	}
	rows = append(rows, models.LogEntry{Timestamp: hour.Add(9 * time.Second), Source: models.LogCaddyError, Level: "error", Message: "x"})
	return rows
}

func TestFillRollupHourExactAndIdempotent(t *testing.T) {
	d := dbtest.Open(t)
	ctx := context.Background()
	h1 := dbtest.InsertHost(t, d, "one.example.com")
	h2 := dbtest.InsertHost(t, d, "two.example.com")
	hour := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	if err := db.InsertLogBatch(ctx, d, rowsFor(hour, h1, h2)); err != nil {
		t.Fatal(err)
	}
	// a row in the next hour must not be counted
	if err := db.InsertLogBatch(ctx, d, []models.LogEntry{{Timestamp: hour.Add(time.Hour), Source: models.LogCaddyAccess, Status: 200, Path: "/next"}}); err != nil {
		t.Fatal(err)
	}
	res, err := db.FillRollupHour(ctx, d, hour)
	if err != nil {
		t.Fatal(err)
	}
	// groups: (access,h1,2) (access,h1,4) (access,h2,2) (access,h2,5) (access,0,2) (error,0,0) = 6
	if res.Rows != 6 {
		t.Fatalf("groups = %d, want 6", res.Rows)
	}
	if res.PathRows != 6 { // /a /b /x /y for h1, /c for h2, /nohost for 0
		t.Fatalf("path rows = %d, want 6", res.PathRows)
	}
	var req, bytes, forb, rl, errs int64
	if err := d.QueryRow(`SELECT SUM(requests), SUM(bytes_out), SUM(forbidden), SUM(rate_limited), SUM(errors) FROM log_hourly WHERE hour = ?`, hour).
		Scan(&req, &bytes, &forb, &rl, &errs); err != nil {
		t.Fatal(err)
	}
	if req != 9 || bytes != 1361 || forb != 1 || rl != 1 || errs != 1 {
		t.Fatalf("totals requests=%d bytes=%d forbidden=%d rate_limited=%d errors=%d", req, bytes, forb, rl, errs)
	}
	var p50, p95, h0, h7 int64
	if err := d.QueryRow(`SELECT dur_p50_ms, dur_p95_ms, dur_h0, dur_h7 FROM log_hourly WHERE hour = ? AND source = 'caddy_access' AND host_id = ? AND status_class = 2`, hour, h1).
		Scan(&p50, &p95, &h0, &h7); err != nil {
		t.Fatal(err)
	}
	// h1 class 2 durations 10, 20, 30: p50 = 2nd = 20, p95 = 3rd = 30; all <= 50
	if p50 != 20 || p95 != 30 || h0 != 3 || h7 != 0 {
		t.Fatalf("h1/2xx p50=%d p95=%d h0=%d h7=%d", p50, p95, h0, h7)
	}
	// idempotent: a second fill leaves the same rows
	if _, err := db.FillRollupHour(ctx, d, hour); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, d, "log_hourly", "hour = ?", hour); n != 6 {
		t.Fatalf("after refill: %d groups", n)
	}
	drift, err := db.RollupDrift(ctx, d, hour)
	if err != nil {
		t.Fatal(err)
	}
	if !drift.Agrees() {
		t.Fatalf("drift on a fresh fill: %+v", drift)
	}
	// a purge of raw rows after the fill is drift until the hour is refilled
	if _, err := d.Exec(`DELETE FROM log_entries WHERE path = '/x'`); err != nil {
		t.Fatal(err)
	}
	drift, _ = db.RollupDrift(ctx, d, hour)
	if drift.Agrees() {
		t.Fatal("drift not detected after a raw delete")
	}
	if _, err := db.FillRollupHour(ctx, d, hour); err != nil {
		t.Fatal(err)
	}
	// h1 class 4 keeps the 429 row only: forbidden drops to 0, requests to 1
	var forb2, req2 int64
	if err := d.QueryRow(`SELECT forbidden, requests FROM log_hourly WHERE hour = ? AND status_class = 4 AND host_id = ?`, hour, h1).Scan(&forb2, &req2); err != nil {
		t.Fatal(err)
	}
	if forb2 != 0 || req2 != 1 {
		t.Fatalf("after refill h1/4xx forbidden=%d requests=%d, want 0/1", forb2, req2)
	}
	// a group whose rows all vanished is gone after the refill
	if _, err := d.Exec(`DELETE FROM log_entries WHERE source = 'caddy_error'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.FillRollupHour(ctx, d, hour); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, d, "log_hourly", "hour = ? AND source = 'caddy_error'", hour); n != 0 {
		t.Fatal("refill kept a group that no longer exists in the raw rows")
	}
	drift, _ = db.RollupDrift(ctx, d, hour)
	if !drift.Agrees() {
		t.Fatalf("drift after refill: %+v", drift)
	}
}

func TestRollupHoursAndPurge(t *testing.T) {
	d := dbtest.Open(t)
	ctx := context.Background()
	if _, ok, err := db.RollupMaxHour(ctx, d); err != nil || ok {
		t.Fatalf("empty rollup: ok=%v err=%v", ok, err)
	}
	if _, ok, err := db.LogEntriesMinHour(ctx, d); err != nil || ok {
		t.Fatalf("empty log_entries: ok=%v err=%v", ok, err)
	}
	h1 := dbtest.InsertHost(t, d, "one.example.com")
	base := time.Date(2026, 9, 20, 3, 17, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := db.InsertLogBatch(ctx, d, rowsFor(base.Add(time.Duration(i)*time.Hour), h1, h1)); err != nil {
			t.Fatal(err)
		}
	}
	minHour, ok, err := db.LogEntriesMinHour(ctx, d)
	if err != nil || !ok || !minHour.Equal(base.Truncate(time.Hour)) {
		t.Fatalf("min hour = %v ok=%v err=%v", minHour, ok, err)
	}
	for i := 0; i < 3; i++ {
		if _, err := db.FillRollupHour(ctx, d, base.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	maxHour, ok, err := db.RollupMaxHour(ctx, d)
	if err != nil || !ok || !maxHour.Equal(base.Truncate(time.Hour).Add(2*time.Hour)) {
		t.Fatalf("max hour = %v ok=%v err=%v", maxHour, ok, err)
	}
	n, err := db.PurgeRollup(ctx, d, base.Truncate(time.Hour).Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 || dbtest.Count(t, d, "log_hourly", "") == 0 {
		t.Fatalf("purge removed %d, left %d", n, dbtest.Count(t, d, "log_hourly", ""))
	}
	if left := dbtest.Count(t, d, "log_hourly_paths", "hour < ?", base.Truncate(time.Hour).Add(time.Hour)); left != 0 {
		t.Fatalf("paths not purged: %d", left)
	}
}
