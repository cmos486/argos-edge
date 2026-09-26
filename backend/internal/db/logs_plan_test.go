package db_test

import (
	"strings"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
)

// explain returns the detail column of EXPLAIN QUERY PLAN for q, run
// through the same driver and schema the panel uses. Plans do not
// depend on the bound values, only on their presence.
func explain(t *testing.T, q string, args ...any) []string {
	t.Helper()
	d := dbtest.Open(t)
	rows, err := d.Query(`EXPLAIN QUERY PLAN `+q, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, detail)
	}
	return out
}

// TestStripCursorPlan pins the strip cursor plan (strike 14): the
// index range must use both bounds, otherwise every batch walks
// idx_log_entries_source_ts from the oldest row. The OR form that
// shipped in v1.3.40.2 is kept as the negative case so the assertion
// is known to discriminate.
func TestStripCursorPlan(t *testing.T) {
	cur := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	cutoff := cur.Add(24 * time.Hour)
	orForm := `SELECT id, timestamp FROM log_entries
	  WHERE source = ? AND timestamp < ?
	    AND (timestamp > ? OR (timestamp = ? AND id > ?))
	  ORDER BY timestamp ASC, id ASC LIMIT ?`

	cases := []struct {
		name       string
		q          string
		args       []any
		bothBounds bool
	}{
		{"shipped cursor", db.StripCursorSQL, []any{"caddy_access", cur, cutoff, cur, int64(0), 200}, true},
		{"v1.3.40.2 OR form (negative)", orForm, []any{"caddy_access", cutoff, cur, cur, int64(0), 200}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := strings.Join(explain(t, tc.q, tc.args...), " | ")
			if !strings.Contains(plan, "idx_log_entries_source_ts") {
				t.Fatalf("plan does not use idx_log_entries_source_ts: %s", plan)
			}
			got := strings.Contains(plan, "timestamp>?") && strings.Contains(plan, "timestamp<?")
			if got != tc.bothBounds {
				t.Fatalf("both bounds in range = %v, want %v; plan: %s", got, tc.bothBounds, plan)
			}
		})
	}
}
