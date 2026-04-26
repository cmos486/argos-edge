package country

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// DefaultReconcilerInterval is how often the reconciler tick
// fires. 5 minutes balances "catch drift quickly" against the
// CountDecisionsByOrigin scan cost (one ListDecisions call per
// tick, served from the 15s cache). With 8 active country
// expansions on a stack, the per-tick cost is ~1ms.
const DefaultReconcilerInterval = 5 * time.Minute

// DriftThresholdPct is the divergence threshold above which a
// country_ban_expansions row gets transitioned to state='drifted'.
// 1% absorbs LAPI's flush-and-replenish noise (community-blocklist
// re-syncs every 2h and may briefly perturb the cache) while
// catching the real-world failures (smoke contamination, manual
// cscli mutation, the v1.3.31-era flush cascade).
const DriftThresholdPct = 1

// Reconciler periodically compares panel-side
// country_ban_expansions.cidr_count against LAPI's actual
// decision count per origin. Flags rows where the two diverge.
//
// Mirrors the publicip + drift detector lifecycle:
// goroutine + ticker + ctx.Done; first tick runs synchronously
// inside the goroutine so a fresh boot's drift state lands
// within seconds of startup.
type Reconciler struct {
	db       *sql.DB
	expander *Expander
	logger   *slog.Logger
}

// NewReconciler binds a reconciler to the panel DB + the
// existing Expander (which carries the LAPIWriter -- the
// reconciler reads via expander.LAPI for the
// CountDecisionsByOrigin call).
func NewReconciler(db *sql.DB, expander *Expander, logger *slog.Logger) *Reconciler {
	return &Reconciler{db: db, expander: expander, logger: logger}
}

// Start spawns the background tick loop. Returns immediately;
// the goroutine runs until ctx is cancelled. interval=0 falls
// back to DefaultReconcilerInterval. First tick is synchronous
// so post-boot drift lands within seconds.
func (r *Reconciler) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultReconcilerInterval
	}
	go func() {
		r.checkOnce(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.checkOnce(ctx)
			}
		}
	}()
}

// CheckOnce runs one reconciliation pass. Exposed for the smoke
// path which forces a check after a state change rather than
// waiting for the next tick.
func (r *Reconciler) CheckOnce(ctx context.Context) {
	r.checkOnce(ctx)
}

func (r *Reconciler) checkOnce(ctx context.Context) {
	if r.expander == nil || r.expander.LAPI == nil {
		return
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT id, country_code, cidr_count, state
		   FROM country_ban_expansions
		  ORDER BY id ASC`)
	if err != nil {
		r.warn("query expansions", err)
		return
	}
	defer rows.Close()

	type expansionRow struct {
		id      int64
		code    string
		count   int
		state   string
	}
	var pending []expansionRow
	for rows.Next() {
		var x expansionRow
		if err := rows.Scan(&x.id, &x.code, &x.count, &x.state); err != nil {
			r.warn("scan expansion", err)
			return
		}
		pending = append(pending, x)
	}
	if err := rows.Err(); err != nil {
		r.warn("rows err", err)
		return
	}

	for _, x := range pending {
		actual, err := r.expander.countByOrigin(ctx, originFor(x.code))
		if err != nil {
			r.warn("count by origin", err, "code", x.code)
			continue
		}
		newState := classify(x.count, actual)
		if newState == x.state {
			continue
		}
		if _, err := r.db.ExecContext(ctx,
			`UPDATE country_ban_expansions SET state = ? WHERE id = ?`,
			newState, x.id); err != nil {
			r.warn("update state", err, "code", x.code, "state", newState)
			continue
		}
		if r.logger != nil {
			r.logger.Info("country reconciler: state change",
				"code", x.code,
				"panel_count", x.count,
				"lapi_count", actual,
				"old_state", x.state,
				"new_state", newState)
		}
	}
}

// classify decides the row's new state from the panel-vs-LAPI
// counts. Tolerance scales by panel count so a 10-CIDR country
// doesn't drift on a single off-by-one, while a 5000-CIDR
// country drifts as soon as 51 decisions are missing.
func classify(panelCount, lapiCount int) string {
	if panelCount <= 0 {
		// Pathological: panel claims 0 expansion. Not drift; no
		// LAPI count to compare against meaningfully.
		return "active"
	}
	delta := panelCount - lapiCount
	if delta < 0 {
		delta = -delta
	}
	// tolerance = max(1, panelCount * DriftThresholdPct / 100)
	tolerance := panelCount * DriftThresholdPct / 100
	if tolerance < 1 {
		tolerance = 1
	}
	if delta > tolerance {
		return "drifted"
	}
	return "active"
}

// countByOrigin is a small helper so the reconciler doesn't
// need to know about the LAPIWriter interface details.
// expander.LAPI satisfies the surface; keeping the helper
// internal also lets tests inject a fake without exposing the
// LAPI type to consumers.
func (e *Expander) countByOrigin(ctx context.Context, origin string) (int, error) {
	type counter interface {
		CountDecisionsByOrigin(ctx context.Context, origin string) (int, error)
	}
	if c, ok := e.LAPI.(counter); ok {
		return c.CountDecisionsByOrigin(ctx, origin)
	}
	return 0, fmt.Errorf("LAPI client does not implement CountDecisionsByOrigin")
}

func (r *Reconciler) warn(what string, err error, kv ...any) {
	if r.logger == nil {
		return
	}
	if len(kv) == 0 {
		r.logger.Warn("country reconciler: "+what, "err", err)
		return
	}
	args := append([]any{"err", err}, kv...)
	r.logger.Warn("country reconciler: "+what, args...)
}

// helpers (avoids pulling in unused imports if the test build
// trims) -- kept here so files_test or other consumers can refer
// to the function by name.
var _ = strings.ToUpper
