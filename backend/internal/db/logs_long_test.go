package db

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// longStatsDB carries the log_entries columns the stats queries touch
// and the six migration-009 indexes by name (the long path pins them
// with INDEXED BY).
func longStatsDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	d.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = d.Close() })
	stmts := []string{
		`CREATE TABLE hosts (id INTEGER PRIMARY KEY, domain TEXT NOT NULL)`,
		`CREATE TABLE log_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TIMESTAMP NOT NULL,
			source TEXT NOT NULL,
			level TEXT NOT NULL DEFAULT '',
			host_id INTEGER,
			host_domain TEXT NOT NULL DEFAULT '',
			rule_id INTEGER,
			remote_ip TEXT NOT NULL DEFAULT '',
			method TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			status INTEGER NOT NULL DEFAULT 0,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			size_bytes INTEGER NOT NULL DEFAULT 0,
			user_agent TEXT NOT NULL DEFAULT '',
			upstream TEXT NOT NULL DEFAULT '',
			message TEXT NOT NULL DEFAULT '',
			raw TEXT NOT NULL DEFAULT '',
			waf_rule_id INTEGER NOT NULL DEFAULT 0,
			waf_rule_message TEXT NOT NULL DEFAULT '',
			waf_severity TEXT NOT NULL DEFAULT '',
			waf_anomaly_score INTEGER NOT NULL DEFAULT 0)`,
		`CREATE INDEX idx_log_entries_timestamp ON log_entries(timestamp DESC)`,
		`CREATE INDEX idx_log_entries_source_ts ON log_entries(source, timestamp DESC)`,
		`CREATE INDEX idx_log_entries_host_ts ON log_entries(host_id, timestamp DESC)`,
		`CREATE INDEX idx_log_entries_rule_ts ON log_entries(rule_id, timestamp DESC)`,
		`CREATE INDEX idx_log_entries_status_ts ON log_entries(status, timestamp DESC)`,
		`CREATE INDEX idx_log_entries_waf_rule_ts ON log_entries(waf_rule_id, timestamp DESC)`,
	}
	for _, st := range stmts {
		if _, err := d.Exec(st); err != nil {
			t.Fatalf("%.40s: %v", st, err)
		}
	}
	return d
}

func insertRow(t *testing.T, d *sql.DB, ts time.Time, source string, hostID any, status, durMs int, path string) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO log_entries (timestamp, source, host_id, status, duration_ms, path) VALUES (?,?,?,?,?,?)`,
		ts.UTC(), source, hostID, status, durMs, path); err != nil {
		t.Fatal(err)
	}
}

func TestStatsFastPathEligibility(t *testing.T) {
	now := time.Now().UTC()
	long := LogFilter{From: now.Add(-7 * 24 * time.Hour), To: now}
	cases := []struct {
		name string
		f    LogFilter
		want bool
	}{
		{"7d, time only", long, true},
		{"unbounded", LogFilter{}, true},
		{"7d access only", LogFilter{From: long.From, To: now, Sources: []models.LogSource{models.LogCaddyAccess}}, true},
		{"7d error source", LogFilter{From: long.From, To: now, Sources: []models.LogSource{models.LogCaddyError}}, false},
		{"1h", LogFilter{From: now.Add(-time.Hour), To: now}, false},
		{"24h exactly", LogFilter{From: now.Add(-24 * time.Hour), To: now}, false},
		{"7d with q", LogFilter{From: long.From, To: now, Query: "x"}, false},
		{"7d with host", LogFilter{From: long.From, To: now, HostIDs: []int64{1}}, false},
		{"7d with status", LogFilter{From: long.From, To: now, StatusExpr: "5xx"}, false},
		{"7d with ip", LogFilter{From: long.From, To: now, RemoteIP: "203.0.113.9"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := statsFastPathEligible(c.f); got != c.want {
				t.Fatalf("want %v, got %v", c.want, got)
			}
		})
	}
}

// TestStatsLongPlans: every pinned query must be answered from a
// covering index with no table scan.
func TestStatsLongPlans(t *testing.T) {
	d := longStatsDB(t)
	from, to := time.Now().Add(-7*24*time.Hour), time.Now()
	cases := []struct {
		name  string
		sql   string
		args  []any
		index string
	}{
		{"class count", statsClassCountSQL, []any{200, 299, from, to}, "idx_log_entries_status_ts"},
		{"source count", statsSourceCountSQL, []any{"caddy_access", from, to}, "idx_log_entries_source_ts"},
		{"total", statsTotalSQL, []any{from, to}, "idx_log_entries_timestamp"},
		{"top hosts", statsTopHostsSQL, []any{from, to}, "idx_log_entries_host_ts"},
		{"class series", statsClassSeriesSQL, []any{500, 599, from, to}, "idx_log_entries_status_ts"},
		{"total series", statsTotalSeriesSQL, []any{from, to}, "idx_log_entries_timestamp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rows, err := d.Query("EXPLAIN QUERY PLAN "+c.sql, c.args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var plan []string
			for rows.Next() {
				var id, parent, notused int
				var detail string
				if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}
			joined := strings.Join(plan, " | ")
			if !strings.Contains(joined, "COVERING INDEX "+c.index) {
				t.Fatalf("plan must use COVERING INDEX %s, got: %s", c.index, joined)
			}
			for _, p := range plan {
				if strings.HasPrefix(p, "SCAN") {
					t.Fatalf("plan must not SCAN, got: %s", joined)
				}
			}
		})
	}
}
