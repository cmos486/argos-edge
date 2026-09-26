package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
)

// TestSeedDenseShape runs a small seed on the real schema and checks
// the marker, the source split, the host attribution and that the
// raw column parses as the Caddy access shape the ingestor expects.
func TestSeedDenseShape(t *testing.T) {
	d := dbtest.Open(t)
	ctx := context.Background()
	// 14 hosts like `demo seed`; ranks 15-19 stay unattributed.
	for i := 0; i < 14; i++ {
		dbtest.InsertHost(t, d, fmt.Sprintf("h%d.example.com", i))
	}

	var out bytes.Buffer
	opts := &denseOpts{Yes: true, Rows: 4000, Days: 2, Seed: 7, Stdout: &out}
	if err := seedDense(ctx, d, opts); err != nil {
		t.Fatalf("seedDense: %v", err)
	}
	if got := dbtest.Count(t, d, "log_entries", `upstream = 'demo-dense'`); got != 4000 {
		t.Fatalf("dense rows = %d, want 4000", got)
	}
	access := dbtest.Count(t, d, "log_entries", `upstream = 'demo-dense' AND source = 'caddy_access'`)
	errs := dbtest.Count(t, d, "log_entries", `upstream = 'demo-dense' AND source = 'caddy_error'`)
	if access+errs != 4000 || errs < 80 || errs > 320 {
		t.Fatalf("source split access=%d error=%d, want ~96/4", access, errs)
	}
	withHost := dbtest.Count(t, d, "log_entries", `upstream = 'demo-dense' AND source = 'caddy_access' AND host_id IS NOT NULL`)
	if withHost*100 < access*97 {
		t.Fatalf("host_id set on %d of %d access rows, want >= 97 %%", withHost, access)
	}
	var hours int
	if err := d.QueryRow(`SELECT COUNT(DISTINCT substr(timestamp, 1, 13)) FROM log_entries WHERE upstream = 'demo-dense'`).Scan(&hours); err != nil {
		t.Fatal(err)
	}
	if hours < 40 {
		t.Fatalf("rows span %d hour buckets, want >= 40 of 48", hours)
	}

	var raw string
	if err := d.QueryRow(`SELECT raw FROM log_entries WHERE upstream = 'demo-dense' AND source = 'caddy_access' LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("raw is not JSON: %v", err)
	}
	req, _ := m["request"].(map[string]any)
	if req == nil || req["host"] == "" || req["uri"] == "" || m["status"] == nil || m["duration"] == nil {
		t.Fatalf("raw lacks the Caddy access shape: %s", raw)
	}
	if len(raw) < 1200 || len(raw) > 1800 {
		t.Fatalf("raw is %d bytes, want ~1.4 KB", len(raw))
	}

	// A second run must refuse until clear-dense.
	if err := seedDense(ctx, d, opts); err == nil {
		t.Fatal("second seedDense should refuse while dense rows exist")
	}
	if err := clearDense(ctx, d, &out); err != nil {
		t.Fatalf("clearDense: %v", err)
	}
	if got := dbtest.Count(t, d, "log_entries", `upstream = 'demo-dense'`); got != 0 {
		t.Fatalf("after clear: %d dense rows", got)
	}
}

// TestSeedDenseDeterministic: same seed and rows give the same rows.
func TestSeedDenseDeterministic(t *testing.T) {
	fingerprint := func() string {
		d := dbtest.Open(t)
		dbtest.InsertHost(t, d, "shop.example.com")
		var out bytes.Buffer
		if err := seedDense(context.Background(), d, &denseOpts{Rows: 1500, Days: 1, Seed: 3, Stdout: &out}); err != nil {
			t.Fatal(err)
		}
		var fp string
		// timestamps depend on time.Now, so hash the time-independent columns
		if err := d.QueryRow(`SELECT group_concat(remote_ip || method || path || status || duration_ms || size_bytes || user_agent, '|') FROM (SELECT * FROM log_entries WHERE upstream = 'demo-dense' ORDER BY id)`).Scan(&fp); err != nil {
			t.Fatal(err)
		}
		return fp
	}
	if fingerprint() != fingerprint() {
		t.Fatal("two runs with the same seed differ")
	}
}

func TestBucketCountsSum(t *testing.T) {
	c := bucketCounts(500000, 7)
	if len(c) != 168 {
		t.Fatalf("buckets = %d", len(c))
	}
	sum := 0
	for _, n := range c {
		sum += n
	}
	if sum != 500000 {
		t.Fatalf("sum = %d", sum)
	}
}
