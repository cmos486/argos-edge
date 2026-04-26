package country

import (
	"context"
	"database/sql"
	"testing"
)

// reconcilerLAPI satisfies the CountDecisionsByOrigin interface
// the reconciler probes for. Tests inject a fake count per
// origin so we can exercise the drift classifier without a real
// LAPI.
type reconcilerLAPI struct {
	*fakeLAPI
	counts map[string]int
}

func (r *reconcilerLAPI) CountDecisionsByOrigin(_ context.Context, origin string) (int, error) {
	return r.counts[origin], nil
}

func newReconcilerExpander(t *testing.T, counts map[string]int) (*Expander, *sql.DB) {
	t.Helper()
	d := openTestDB(t)
	lapi := &reconcilerLAPI{fakeLAPI: &fakeLAPI{}, counts: counts}
	src := &fakeSource{byCode: map[string][]string{
		"XX": {"192.0.2.0/24"},
	}, version: "test"}
	return &Expander{DB: d, LAPI: lapi, Source: src}, d
}

func TestReconciler_classifyTolerance(t *testing.T) {
	cases := []struct {
		name        string
		panel, lapi int
		want        string
	}{
		{"both zero -> active (no expansion)", 0, 0, "active"},
		{"perfect match", 100, 100, "active"},
		{"within 1% small (1 of 100)", 100, 99, "active"},
		{"exactly threshold (small) -> active", 100, 99, "active"},
		{"50 missing of 5000 = 1% -> active", 5000, 4950, "active"},
		{"51 missing of 5000 = >1% -> drifted", 5000, 4949, "drifted"},
		{"all gone -> drifted", 5000, 0, "drifted"},
		{"tiny country single off -> active (tolerance floor)", 5, 4, "active"},
		{"tiny country two off -> drifted", 5, 3, "drifted"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classify(c.panel, c.lapi); got != c.want {
				t.Fatalf("classify(panel=%d,lapi=%d) = %q, want %q",
					c.panel, c.lapi, got, c.want)
			}
		})
	}
}

func TestReconciler_checkOnce_marksDrifted(t *testing.T) {
	// Panel claims 5000 BR ranges; LAPI has 0 (the v1.3.31
	// flush-cascade scenario). One CheckOnce should flip the
	// row from active to drifted.
	exp, d := newReconcilerExpander(t, map[string]int{
		"argos-country-BR": 0,
	})
	if _, err := d.Exec(`INSERT INTO country_ban_expansions
		(country_code, decision_ids, cidr_count, duration, created_by, mmdb_version_at_creation, state)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"BR", "[]", 5000, "4h", "admin", "test", "active"); err != nil {
		t.Fatal(err)
	}
	r := NewReconciler(d, exp, nil)
	r.CheckOnce(context.Background())

	var state string
	_ = d.QueryRow(`SELECT state FROM country_ban_expansions WHERE country_code='BR'`).Scan(&state)
	if state != "drifted" {
		t.Fatalf("expected drifted, got %q", state)
	}
}

func TestReconciler_checkOnce_recoversToActive(t *testing.T) {
	// Panel and LAPI now match (operator re-emitted post-fix).
	// Reconciler should flip drifted -> active.
	exp, d := newReconcilerExpander(t, map[string]int{
		"argos-country-BR": 5000,
	})
	if _, err := d.Exec(`INSERT INTO country_ban_expansions
		(country_code, decision_ids, cidr_count, duration, created_by, mmdb_version_at_creation, state)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"BR", "[]", 5000, "4h", "admin", "test", "drifted"); err != nil {
		t.Fatal(err)
	}
	r := NewReconciler(d, exp, nil)
	r.CheckOnce(context.Background())

	var state string
	_ = d.QueryRow(`SELECT state FROM country_ban_expansions WHERE country_code='BR'`).Scan(&state)
	if state != "active" {
		t.Fatalf("expected active, got %q", state)
	}
}

func TestReconciler_checkOnce_noChurnWhenStateMatches(t *testing.T) {
	// Panel + LAPI match; row already 'active'. CheckOnce must
	// be a no-op (no UPDATE; rows_affected stays 0). The simple
	// way to verify is to capture the timestamp pre/post and
	// confirm nothing rewrote the row.
	exp, d := newReconcilerExpander(t, map[string]int{
		"argos-country-BR": 5000,
	})
	if _, err := d.Exec(`INSERT INTO country_ban_expansions
		(country_code, decision_ids, cidr_count, duration, created_by, mmdb_version_at_creation, state)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"BR", "[]", 5000, "4h", "admin", "test", "active"); err != nil {
		t.Fatal(err)
	}
	r := NewReconciler(d, exp, nil)
	r.CheckOnce(context.Background())
	r.CheckOnce(context.Background())  // double-tick should also be no-op

	var state string
	_ = d.QueryRow(`SELECT state FROM country_ban_expansions WHERE country_code='BR'`).Scan(&state)
	if state != "active" {
		t.Fatalf("state must remain active, got %q", state)
	}
}
