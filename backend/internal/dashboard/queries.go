package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

// Where a response's numbers came from (X-Argos-Path) and how its
// percentiles were computed (percentile_method), v1.3.42.3.
const (
	PathRows            = "rows"
	PathRollup          = "rollup"
	PercentileExact     = "exact"
	PercentileHistogram = "histogram"
)

// Queries owns the DB handle and every aggregation.
type Queries struct {
	DB *sql.DB
}

// ----- Overview -----

func (q *Queries) Overview(ctx context.Context) (*Overview, error) {
	o := &Overview{path: PathRows}
	now := time.Now().UTC()
	last24h := now.Add(-24 * time.Hour)

	// total + errors + blocked from the access rows of the last 24 h:
	// closed hours from the rollup, the edges from the rows (v1.3.42.3).
	span, err := db.RollupSpanFor(ctx, q.DB, last24h, now)
	if err != nil {
		return nil, fmt.Errorf("overview span: %w", err)
	}
	if span.HasClosed() {
		rows, err := db.ReadRollupHours(ctx, q.DB, span.ClosedFrom, span.ClosedTo, "caddy_access", 0)
		if err != nil {
			return nil, fmt.Errorf("overview rollup: %w", err)
		}
		for _, r := range rows {
			o.TotalRequests24h += r.Requests
			if r.StatusClass == 5 {
				o.ErrorRequests24h += r.Requests
			}
			o.BlockedRequests24h += r.Forbidden + r.RateLimited
		}
		o.path = PathRollup
	}
	for _, e := range span.Edges() {
		var total, errs, blocked sql.NullInt64
		if err := q.DB.QueryRowContext(ctx, `
		SELECT
		  COUNT(*),
		  SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
		  SUM(CASE WHEN status = 403 OR status = 429 THEN 1 ELSE 0 END)
		FROM log_entries INDEXED BY idx_log_entries_source_ts
		WHERE source = 'caddy_access' AND timestamp >= ? AND `+e.UpperOp()+` ?`, e.From, e.To).Scan(&total, &errs, &blocked); err != nil {
			return nil, fmt.Errorf("overview totals: %w", err)
		}
		o.TotalRequests24h += total.Int64
		o.ErrorRequests24h += errs.Int64
		o.BlockedRequests24h += blocked.Int64
	}

	// active hosts
	if err := q.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM hosts WHERE enabled = 1`).Scan(&o.ActiveHosts); err != nil {
		return nil, fmt.Errorf("active hosts: %w", err)
	}

	// unhealthy targets: proxy = targets with enabled=0 OR in a TG with
	// health_check_enabled=1 that we cannot introspect live. For phase
	// 6 use the simpler (and honest) "targets disabled".
	if err := q.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM targets WHERE enabled = 0`).Scan(&o.UnhealthyTargets); err != nil {
		return nil, fmt.Errorf("unhealthy targets: %w", err)
	}

	return o, nil // certs + last backup filled by the handler (needs caddy + manager)
}

// ----- Traffic -----

// classTimesSQL streams the timestamps of one status class from the
// covering (status, timestamp) index: no row visits, so the 24 h
// series at 15 min stays exact without reading the raw rows (the ones
// that still carry `raw`). TestLongRangePlans pins the covering plan.
// It counts every source with a 2xx-5xx status, as the 7 d bridge did
// (waf_audit rows are a fraction of a percent of access rows); the
// rollup path filters the access source exactly.
const classTimesSQL = `SELECT timestamp FROM log_entries INDEXED BY idx_log_entries_status_ts
	WHERE status BETWEEN ? AND ? AND timestamp BETWEEN ? AND ?`

// edgeRowsSQL reads the access rows of one edge of a stitched window
// (at most about two hours of rows when the fill job keeps up). The
// upper bound operator is appended by the caller (< for the head edge,
// <= for the live tail) and an optional host filter after it.
const edgeRowsSQL = `SELECT timestamp, status, duration_ms, size_bytes, COALESCE(host_id, 0), path
	FROM log_entries INDEXED BY idx_log_entries_source_ts
	WHERE source = 'caddy_access' AND timestamp >= ? AND `

// Traffic serves a range. 1 h and 6 h (1 / 5 min buckets) read rows;
// 24 h, 7 d and 30 d are stitched: closed hours from the rollup, the
// hour in progress (and the partial hour at the window start) from the
// rows (v1.3.42.3, planning doc v1.3.42.3 section 2).
func (q *Queries) Traffic(ctx context.Context, from, to time.Time, g time.Duration, hostID int64) (*TrafficMetrics, error) {
	if g < 15*time.Minute {
		t, err := q.trafficRows(ctx, from, to, g, hostID, from, to)
		if err != nil {
			return nil, err
		}
		t.PercentileMethod = PercentileExact
		t.path = PathRows
		return t, nil
	}
	return q.trafficStitched(ctx, from, to, g, hostID)
}

type pathKey struct {
	host int64
	path string
}

// stitchAcc accumulates rollup rows and edge rows into one result.
type stitchAcc struct {
	g, gRT         time.Duration
	seriesFromRows bool // the series was read separately (15 min): edge rows must not add to it
	series         map[int64]*TrafficBucket
	rt             map[int64]*db.Hist
	byHost         map[int64]int64
	byPath         map[pathKey]int64
	bytes          int64
}

func newStitchAcc(g time.Duration, seriesFromRows bool) *stitchAcc {
	gRT := g
	if gRT < time.Hour {
		gRT = time.Hour
	}
	return &stitchAcc{g: g, gRT: gRT, seriesFromRows: seriesFromRows,
		series: map[int64]*TrafficBucket{}, rt: map[int64]*db.Hist{}, byHost: map[int64]int64{}, byPath: map[pathKey]int64{}}
}

func (a *stitchAcc) bucket(key int64) *TrafficBucket {
	b := a.series[key]
	if b == nil {
		b = &TrafficBucket{Time: time.Unix(key, 0).UTC()}
		a.series[key] = b
	}
	return b
}

func (a *stitchAcc) hist(key int64) *db.Hist {
	h := a.rt[key]
	if h == nil {
		h = &db.Hist{}
		a.rt[key] = h
	}
	return h
}

func (a *stitchAcc) addClass(b *TrafficBucket, class int, n int) {
	switch class {
	case 2:
		b.C2xx += n
	case 3:
		b.C3xx += n
	case 4:
		b.C4xx += n
	case 5:
		b.C5xx += n
	}
}

func (a *stitchAcc) addRollup(r db.RollupHourRow) {
	if !a.seriesFromRows {
		a.addClass(a.bucket(r.Hour.Truncate(a.g).Unix()), r.StatusClass, int(r.Requests))
	}
	a.hist(r.Hour.Truncate(a.gRT).Unix()).AddRow(r)
	if r.HostID > 0 {
		a.byHost[r.HostID] += r.Requests
	}
	a.bytes += r.BytesOut
}

func (a *stitchAcc) addRow(ts time.Time, status, dur, size int, host int64, path string) {
	if !a.seriesFromRows {
		class := 0
		if status >= 100 {
			class = status / 100
		}
		a.addClass(a.bucket(ts.Truncate(a.g).Unix()), class, 1)
	}
	a.hist(ts.Truncate(a.gRT).Unix()).AddDuration(dur)
	if host > 0 {
		a.byHost[host]++
	}
	if path != "" {
		a.byPath[pathKey{host, path}]++
	}
	a.bytes += int64(size)
}

// trafficStitched is the rollup path. With no closed hour in the
// window (rollup empty on a fresh install) it falls back to the rows.
func (q *Queries) trafficStitched(ctx context.Context, from, to time.Time, g time.Duration, hostID int64) (*TrafficMetrics, error) {
	span, err := db.RollupSpanFor(ctx, q.DB, from, to)
	if err != nil {
		return nil, fmt.Errorf("traffic span: %w", err)
	}
	if !span.HasClosed() {
		t, err := q.trafficRows(ctx, from, to, g, hostID, from, to)
		if err != nil {
			return nil, err
		}
		t.PercentileMethod = PercentileExact
		t.path = PathRows
		return t, nil
	}
	t := &TrafficMetrics{PercentileMethod: PercentileHistogram, path: PathRollup}
	acc := newStitchAcc(g, g < time.Hour)

	// 1. the series. Below one hour (24 h at 15 min) it is read on its
	// own: index-only per class without a host filter, the host's rows
	// with one (no index carries host and status together; a host's
	// 24 h is bounded and never pinned).
	if acc.seriesFromRows {
		if hostID == 0 {
			classes := []struct{ lo, hi, class int }{{200, 299, 2}, {300, 399, 3}, {400, 499, 4}, {500, 599, 5}}
			for _, c := range classes {
				rows, err := q.DB.QueryContext(ctx, classTimesSQL, c.lo, c.hi, from, to)
				if err != nil {
					return nil, fmt.Errorf("traffic class series %dxx: %w", c.class, err)
				}
				for rows.Next() {
					var ts time.Time
					if err := rows.Scan(&ts); err != nil {
						rows.Close()
						return nil, err
					}
					acc.addClass(acc.bucket(ts.Truncate(g).Unix()), c.class, 1)
				}
				rows.Close()
			}
		} else {
			rows, err := q.DB.QueryContext(ctx,
				`SELECT timestamp, status FROM log_entries WHERE source = 'caddy_access' AND timestamp BETWEEN ? AND ? AND host_id = ?`, from, to, hostID)
			if err != nil {
				return nil, fmt.Errorf("traffic host series: %w", err)
			}
			for rows.Next() {
				var ts time.Time
				var status int
				if err := rows.Scan(&ts, &status); err != nil {
					rows.Close()
					return nil, err
				}
				class := 0
				if status >= 100 {
					class = status / 100
				}
				acc.addClass(acc.bucket(ts.Truncate(g).Unix()), class, 1)
			}
			rows.Close()
		}
	}

	// 2. closed hours from the rollup.
	hours, err := db.ReadRollupHours(ctx, q.DB, span.ClosedFrom, span.ClosedTo, "caddy_access", hostID)
	if err != nil {
		return nil, fmt.Errorf("traffic rollup: %w", err)
	}
	for _, r := range hours {
		acc.addRollup(r)
	}
	paths, err := db.ReadRollupPaths(ctx, q.DB, span.ClosedFrom, span.ClosedTo, hostID)
	if err != nil {
		return nil, fmt.Errorf("traffic rollup paths: %w", err)
	}
	for _, p := range paths {
		acc.byPath[pathKey{p.HostID, p.Path}] += p.Requests
	}

	// 3. the edges from the rows.
	for _, e := range span.Edges() {
		sqlStr, args := edgeRowsSQL+e.UpperOp()+` ?`, []any{e.From, e.To}
		if hostID > 0 {
			sqlStr += ` AND host_id = ?`
			args = append(args, hostID)
		}
		rows, err := q.DB.QueryContext(ctx, sqlStr, args...)
		if err != nil {
			return nil, fmt.Errorf("traffic edge rows: %w", err)
		}
		for rows.Next() {
			var ts time.Time
			var status, dur, size int
			var host int64
			var path string
			if err := rows.Scan(&ts, &status, &dur, &size, &host, &path); err != nil {
				rows.Close()
				return nil, err
			}
			acc.addRow(ts, status, dur, size, host, path)
		}
		rows.Close()
	}

	// 4. shape the response.
	for _, bt := range bucketTimes(from, to, g) {
		if v, ok := acc.series[bt.Unix()]; ok {
			t.Timeseries = append(t.Timeseries, *v)
		} else {
			t.Timeseries = append(t.Timeseries, TrafficBucket{Time: bt})
		}
	}
	for _, bt := range bucketTimes(from, to, acc.gRT) {
		h := acc.rt[bt.Unix()]
		if h == nil || h.N == 0 {
			t.ResponseTimes = append(t.ResponseTimes, ResponseTimeBucket{Time: bt})
			continue
		}
		t.ResponseTimes = append(t.ResponseTimes, ResponseTimeBucket{Time: bt, P50: h.Percentile(50), P95: h.Percentile(95), P99: h.Percentile(99), N: int(h.N)})
	}
	names, err := q.hostNames(ctx)
	if err != nil {
		return nil, err
	}
	type hc struct {
		id int64
		n  int64
	}
	var hostCounts []hc
	for id, n := range acc.byHost {
		hostCounts = append(hostCounts, hc{id, n})
	}
	sort.Slice(hostCounts, func(i, j int) bool {
		if hostCounts[i].n != hostCounts[j].n {
			return hostCounts[i].n > hostCounts[j].n
		}
		return hostCounts[i].id < hostCounts[j].id
	})
	for _, c := range hostCounts {
		if dom, ok := names[c.id]; ok {
			t.TopHosts = append(t.TopHosts, HostVolume{HostDomain: dom, Count: c.n})
		}
		if len(t.TopHosts) == 10 {
			break
		}
	}
	type pc struct {
		k pathKey
		n int64
	}
	var pathCounts []pc
	for k, n := range acc.byPath {
		pathCounts = append(pathCounts, pc{k, n})
	}
	sort.Slice(pathCounts, func(i, j int) bool {
		if pathCounts[i].n != pathCounts[j].n {
			return pathCounts[i].n > pathCounts[j].n
		}
		if pathCounts[i].k.host != pathCounts[j].k.host {
			return pathCounts[i].k.host < pathCounts[j].k.host
		}
		return pathCounts[i].k.path < pathCounts[j].k.path
	})
	for i, c := range pathCounts {
		if i == 20 {
			break
		}
		t.TopPaths = append(t.TopPaths, PathVolume{HostDomain: names[c.k.host], Path: c.k.path, Count: c.n})
	}
	t.BandwidthOut = acc.bytes
	return t, nil
}

// hostNames maps host ids to domains.
func (q *Queries) hostNames(ctx context.Context) (map[int64]string, error) {
	names := map[int64]string{}
	rows, err := q.DB.QueryContext(ctx, `SELECT id, domain FROM hosts`)
	if err != nil {
		return nil, fmt.Errorf("host names: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var dom string
		if err := rows.Scan(&id, &dom); err != nil {
			return nil, err
		}
		names[id] = dom
	}
	return names, rows.Err()
}

// trafficRows is the row-visiting implementation for 1 h and 6 h and
// the fallback while the rollup has no hours. Sections 2, 4 and 5 use
// [detailFrom, detailTo] (always the whole window since v1.3.42.3);
// the series and top hosts use [from, to].
func (q *Queries) trafficRows(ctx context.Context, from, to time.Time, g time.Duration, hostID int64, detailFrom, detailTo time.Time) (*TrafficMetrics, error) {
	t := &TrafficMetrics{}

	// The modernc.org/sqlite driver serialises time.Time values as
	// `YYYY-MM-DD HH:MM:SS.fffffffff +0000 UTC` (Go's default time
	// format), which SQLite's strftime cannot parse. To sidestep
	// every timestamp-format quirk we fetch raw (timestamp, field)
	// rows and bucket them in Go. At homelab volumes (<1M rows/day)
	// the extra allocations are negligible.
	where := `WHERE source = 'caddy_access' AND timestamp BETWEEN ? AND ?`
	args := []any{from, to}
	if hostID > 0 {
		where += ` AND host_id = ?`
		args = append(args, hostID)
	}

	// 1. status-class timeseries: fetch (ts, status) rows, bucket in Go
	rows, err := q.DB.QueryContext(ctx,
		`SELECT timestamp, status FROM log_entries `+where+` ORDER BY timestamp ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("traffic timeseries: %w", err)
	}
	defer rows.Close()
	sparse := map[int64]*TrafficBucket{}
	for rows.Next() {
		var ts time.Time
		var status int
		if err := rows.Scan(&ts, &status); err != nil {
			return nil, err
		}
		key := ts.Truncate(g).Unix()
		b := sparse[key]
		if b == nil {
			b = &TrafficBucket{Time: time.Unix(key, 0).UTC()}
			sparse[key] = b
		}
		switch {
		case status >= 200 && status < 300:
			b.C2xx++
		case status >= 300 && status < 400:
			b.C3xx++
		case status >= 400 && status < 500:
			b.C4xx++
		case status >= 500:
			b.C5xx++
		}
	}
	for _, bt := range bucketTimes(from, to, g) {
		unix := bt.Unix()
		if v, ok := sparse[unix]; ok {
			t.Timeseries = append(t.Timeseries, *v)
		} else {
			t.Timeseries = append(t.Timeseries, TrafficBucket{Time: bt})
		}
	}

	// 2. response time p50/p95/p99 per bucket. Same Go-side bucketing,
	// over the detail window.
	detailArgs := []any{detailFrom, detailTo}
	if hostID > 0 {
		detailArgs = append(detailArgs, hostID)
	}
	rtRows, err := q.DB.QueryContext(ctx,
		`SELECT timestamp, duration_ms FROM log_entries `+where+
			` AND duration_ms > 0 ORDER BY timestamp ASC`, detailArgs...)
	if err != nil {
		return nil, fmt.Errorf("response times: %w", err)
	}
	defer rtRows.Close()
	bucketDurs := map[int64][]int{}
	for rtRows.Next() {
		var ts time.Time
		var d int
		if err := rtRows.Scan(&ts, &d); err != nil {
			return nil, err
		}
		key := ts.Truncate(g).Unix()
		bucketDurs[key] = append(bucketDurs[key], d)
	}
	for _, bt := range bucketTimes(detailFrom, detailTo, g) {
		unix := bt.Unix()
		ds := bucketDurs[unix]
		if len(ds) == 0 {
			t.ResponseTimes = append(t.ResponseTimes, ResponseTimeBucket{Time: bt})
			continue
		}
		sort.Ints(ds)
		p50 := ds[percentileIndex(len(ds), 50)]
		p95 := ds[percentileIndex(len(ds), 95)]
		p99 := ds[percentileIndex(len(ds), 99)]
		t.ResponseTimes = append(t.ResponseTimes, ResponseTimeBucket{
			Time: bt, P50: p50, P95: p95, P99: p99, N: len(ds),
		})
	}

	// 3. top hosts (only relevant when host_id not filtered)
	hostsSQL := `SELECT host_domain, COUNT(*) FROM log_entries
		WHERE source='caddy_access' AND timestamp BETWEEN ? AND ? AND host_domain <> ''`
	hostsArgs := []any{from, to}
	if hostID > 0 {
		hostsSQL += ` AND host_id = ?`
		hostsArgs = append(hostsArgs, hostID)
	}
	hostsSQL += ` GROUP BY host_domain ORDER BY COUNT(*) DESC LIMIT 10`
	hRows, err := q.DB.QueryContext(ctx, hostsSQL, hostsArgs...)
	if err != nil {
		return nil, fmt.Errorf("top hosts: %w", err)
	}
	for hRows.Next() {
		var hv HostVolume
		if err := hRows.Scan(&hv.HostDomain, &hv.Count); err != nil {
			hRows.Close()
			return nil, err
		}
		t.TopHosts = append(t.TopHosts, hv)
	}
	hRows.Close()

	// 4. top paths
	pathsSQL := `SELECT host_domain, path, COUNT(*) FROM log_entries
		WHERE source='caddy_access' AND timestamp BETWEEN ? AND ? AND path <> ''`
	pathsArgs := []any{detailFrom, detailTo}
	if hostID > 0 {
		pathsSQL += ` AND host_id = ?`
		pathsArgs = append(pathsArgs, hostID)
	}
	pathsSQL += ` GROUP BY host_domain, path ORDER BY COUNT(*) DESC LIMIT 20`
	pRows, err := q.DB.QueryContext(ctx, pathsSQL, pathsArgs...)
	if err != nil {
		return nil, fmt.Errorf("top paths: %w", err)
	}
	for pRows.Next() {
		var pv PathVolume
		if err := pRows.Scan(&pv.HostDomain, &pv.Path, &pv.Count); err != nil {
			pRows.Close()
			return nil, err
		}
		t.TopPaths = append(t.TopPaths, pv)
	}
	pRows.Close()

	// 5. bandwidth
	bwSQL := `SELECT COALESCE(SUM(size_bytes), 0) FROM log_entries
		WHERE source='caddy_access' AND timestamp BETWEEN ? AND ?`
	bwArgs := []any{detailFrom, detailTo}
	if hostID > 0 {
		bwSQL += ` AND host_id = ?`
		bwArgs = append(bwArgs, hostID)
	}
	if err := q.DB.QueryRowContext(ctx, bwSQL, bwArgs...).Scan(&t.BandwidthOut); err != nil {
		return nil, fmt.Errorf("bandwidth: %w", err)
	}
	return t, nil
}

// parseSQLiteTimeLenient handles the several shapes the modernc.org/
// sqlite driver + our time.Time bindings leave inside TEXT columns.
// Falls back to time.Time{} when nothing parses.
func parseSQLiteTimeLenient(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05.999999999 -07:00",
		"2006-01-02 15:04:05 -0700 MST",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// percentileIndex returns the index into a sorted slice of length n
// for the given percentile (0-100). Classic nearest-rank method,
// clamped to [0, n-1].
func percentileIndex(n, p int) int {
	if n <= 0 {
		return 0
	}
	idx := (p * n) / 100
	if idx >= n {
		idx = n - 1
	}
	return idx
}

// ----- Security -----

func (q *Queries) Security(ctx context.Context, from, to time.Time, g time.Duration) (*SecurityMetrics, error) {
	s := &SecurityMetrics{}

	// detected vs blocked timeseries -- bucket in Go for the same
	// timestamp-format reason Traffic does.
	detected := map[int64]int{}
	detRows, err := q.DB.QueryContext(ctx, `
		SELECT timestamp FROM log_entries
		WHERE source='waf_audit' AND waf_severity IN ('CRITICAL','ERROR','WARNING')
		  AND timestamp BETWEEN ? AND ?`, from, to)
	if err != nil {
		return nil, fmt.Errorf("waf detected: %w", err)
	}
	for detRows.Next() {
		var ts time.Time
		if err := detRows.Scan(&ts); err != nil {
			detRows.Close()
			return nil, err
		}
		detected[ts.Truncate(g).Unix()]++
	}
	detRows.Close()

	blocked := map[int64]int{}
	blkRows, err := q.DB.QueryContext(ctx, `
		SELECT timestamp FROM log_entries
		WHERE source='caddy_access' AND status=403
		  AND timestamp BETWEEN ? AND ?`, from, to)
	if err != nil {
		return nil, fmt.Errorf("waf blocked: %w", err)
	}
	for blkRows.Next() {
		var ts time.Time
		if err := blkRows.Scan(&ts); err != nil {
			blkRows.Close()
			return nil, err
		}
		blocked[ts.Truncate(g).Unix()]++
	}
	blkRows.Close()

	for _, bt := range bucketTimes(from, to, g) {
		u := bt.Unix()
		s.WafTimeseries = append(s.WafTimeseries, WafBucket{
			Time: bt, Detected: detected[u], Blocked: blocked[u],
		})
	}

	// top attack types
	atRows, err := q.DB.QueryContext(ctx, `
		SELECT waf_rule_id, MIN(waf_rule_message), COUNT(*)
		FROM log_entries
		WHERE source='waf_audit' AND waf_rule_id > 0
		  AND timestamp BETWEEN ? AND ?
		GROUP BY waf_rule_id
		ORDER BY COUNT(*) DESC
		LIMIT 10`, from, to)
	if err != nil {
		return nil, fmt.Errorf("top attack types: %w", err)
	}
	for atRows.Next() {
		var a AttackType
		var msg sql.NullString
		if err := atRows.Scan(&a.RuleID, &msg, &a.Count); err != nil {
			atRows.Close()
			return nil, err
		}
		a.Message = msg.String
		s.TopAttackTypes = append(s.TopAttackTypes, a)
	}
	atRows.Close()

	// top attacking ips. MAX(timestamp) comes back as a string (the
	// modernc driver only auto-converts direct timestamp columns, not
	// aggregate expressions), so we scan into a string and parse it
	// with Go's default time layout.
	ipRows, err := q.DB.QueryContext(ctx, `
		SELECT remote_ip, COUNT(*), COUNT(DISTINCT host_domain), MAX(timestamp)
		FROM log_entries
		WHERE source='waf_audit' AND remote_ip <> ''
		  AND waf_severity IN ('CRITICAL','ERROR','WARNING')
		  AND timestamp BETWEEN ? AND ?
		GROUP BY remote_ip
		ORDER BY COUNT(*) DESC
		LIMIT 20`, from, to)
	if err != nil {
		return nil, fmt.Errorf("top attack ips: %w", err)
	}
	for ipRows.Next() {
		var ai AttackIP
		var lastSeenStr string
		if err := ipRows.Scan(&ai.RemoteIP, &ai.Count, &ai.DistinctHosts, &lastSeenStr); err != nil {
			ipRows.Close()
			return nil, err
		}
		ai.LastSeen = parseSQLiteTimeLenient(lastSeenStr)
		s.TopAttackIPs = append(s.TopAttackIPs, ai)
	}
	ipRows.Close()

	// top attacked paths
	pthRows, err := q.DB.QueryContext(ctx, `
		SELECT host_domain, path, COUNT(*)
		FROM log_entries
		WHERE source='waf_audit' AND path <> ''
		  AND timestamp BETWEEN ? AND ?
		GROUP BY host_domain, path
		ORDER BY COUNT(*) DESC
		LIMIT 10`, from, to)
	if err != nil {
		return nil, fmt.Errorf("top attacked paths: %w", err)
	}
	for pthRows.Next() {
		var ap AttackPath
		if err := pthRows.Scan(&ap.HostDomain, &ap.Path, &ap.Count); err != nil {
			pthRows.Close()
			return nil, err
		}
		s.TopAttackedPaths = append(s.TopAttackedPaths, ap)
	}
	pthRows.Close()

	// rate limit hits
	if err := q.DB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM log_entries
		WHERE source='caddy_access' AND status=429
		  AND timestamp BETWEEN ? AND ?`, from, to).Scan(&s.RateLimitHits); err != nil {
		return nil, fmt.Errorf("rate limit hits: %w", err)
	}

	return s, nil
}

// AttackingIPCount is one row of AttackingIPCounts. Kept separate
// from AttackIP because the by_country aggregator does not need the
// distinct-hosts / last-seen columns the TopAttackIPs table shows.
type AttackingIPCount struct {
	RemoteIP string
	Count    int64
}

// AttackingIPCounts returns every attacking IP in the given window
// grouped by remote_ip, with its hit count. NO LIMIT -- the caller
// (api/dashboard.go) enriches each with GeoIP and folds them into a
// by_country aggregation. For a busy site this may be hundreds of
// rows; enrichIP is cache-backed so the N calls are cheap.
func (q *Queries) AttackingIPCounts(ctx context.Context, from, to time.Time) ([]AttackingIPCount, error) {
	rows, err := q.DB.QueryContext(ctx, `
		SELECT remote_ip, COUNT(*)
		FROM log_entries
		WHERE source='waf_audit' AND remote_ip <> ''
		  AND waf_severity IN ('CRITICAL','ERROR','WARNING')
		  AND timestamp BETWEEN ? AND ?
		GROUP BY remote_ip
		ORDER BY COUNT(*) DESC`, from, to)
	if err != nil {
		return nil, fmt.Errorf("attacking ip counts: %w", err)
	}
	defer rows.Close()
	var out []AttackingIPCount
	for rows.Next() {
		var r AttackingIPCount
		if err := rows.Scan(&r.RemoteIP, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ----- Health -----

// TargetGroupSummary queries the TG + target counts.
func (q *Queries) TargetGroupsHealth(ctx context.Context) ([]TargetGroupHealth, error) {
	rows, err := q.DB.QueryContext(ctx, `
		SELECT tg.name,
		       COALESCE(SUM(1), 0),
		       COALESCE(SUM(CASE WHEN t.enabled = 1 THEN 1 ELSE 0 END), 0)
		FROM target_groups tg
		LEFT JOIN targets t ON t.target_group_id = tg.id
		GROUP BY tg.id, tg.name
		ORDER BY tg.name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetGroupHealth
	for rows.Next() {
		var tg TargetGroupHealth
		if err := rows.Scan(&tg.Name, &tg.Total, &tg.Enabled); err != nil {
			return nil, err
		}
		switch {
		case tg.Total == 0:
			tg.Status = "down"
		case tg.Enabled == 0:
			tg.Status = "down"
		case tg.Enabled < tg.Total:
			tg.Status = "degraded"
		default:
			tg.Status = "ok"
		}
		out = append(out, tg)
	}
	return out, rows.Err()
}

// RecentErrors returns the last `limit` log entries from the last 24 h
// that look like real problems: caddy_error entries (level error/warn),
// or access logs with 5xx status. Ordered newest first.
//
// Shape matters (v1.3.38.1): the previous single query OR'ed the two
// sources with no time bound, which the planner ran as a multi-index
// OR over every caddy_error AND every caddy_access row followed by a
// temp-B-tree sort (12.6 s on a 500k-row prod copy; the whole
// /api/dashboard/health call sat at 21-31 s cold). Each branch below
// is a bounded range on idx_log_entries_source_ts (source, timestamp
// DESC) with its own LIMIT, and the UNION ALL only merges 2*limit
// rows (0.024 s on the same copy). The 24 h bound also matches what
// the card is for: errors happening now, not the oldest retained row.
func (q *Queries) RecentErrors(ctx context.Context, limit int) ([]RecentError, error) {
	if limit <= 0 {
		limit = 10
	}
	cutoff := time.Now().Add(-24 * time.Hour).UTC()
	rows, err := q.DB.QueryContext(ctx, `
		SELECT timestamp, source, level, message FROM (
			SELECT timestamp, source, level, message FROM log_entries
			WHERE source = 'caddy_error' AND timestamp >= ?
			  AND level IN ('error','warn')
			ORDER BY timestamp DESC LIMIT ?
		)
		UNION ALL
		SELECT timestamp, source, level, message FROM (
			SELECT timestamp, source, level, message FROM log_entries
			WHERE source = 'caddy_access' AND timestamp >= ?
			  AND status >= 500
			ORDER BY timestamp DESC LIMIT ?
		)
		ORDER BY timestamp DESC
		LIMIT ?`, cutoff, limit, cutoff, limit, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RecentError
	for rows.Next() {
		var re RecentError
		if err := rows.Scan(&re.Timestamp, &re.Source, &re.Level, &re.Message); err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, rows.Err()
}
