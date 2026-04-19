package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"
)

// Queries owns the DB handle and every aggregation.
type Queries struct {
	DB *sql.DB
}

// ----- Overview -----

func (q *Queries) Overview(ctx context.Context) (*Overview, error) {
	o := &Overview{}
	last24h := time.Now().UTC().Add(-24 * time.Hour)

	// total + errors + blocked from access log
	row := q.DB.QueryRowContext(ctx, `
		SELECT
		  COUNT(*),
		  SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),
		  SUM(CASE WHEN status = 403 OR status = 429 THEN 1 ELSE 0 END)
		FROM log_entries
		WHERE source = 'caddy_access' AND timestamp >= ?`, last24h)
	var errs, blocked sql.NullInt64
	if err := row.Scan(&o.TotalRequests24h, &errs, &blocked); err != nil {
		return nil, fmt.Errorf("overview totals: %w", err)
	}
	o.ErrorRequests24h = errs.Int64
	o.BlockedRequests24h = blocked.Int64

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

func (q *Queries) Traffic(ctx context.Context, from, to time.Time, g time.Duration, hostID int64) (*TrafficMetrics, error) {
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

	// 2. response time p50/p95/p99 per bucket. Same Go-side bucketing.
	rtRows, err := q.DB.QueryContext(ctx,
		`SELECT timestamp, duration_ms FROM log_entries `+where+
			` AND duration_ms > 0 ORDER BY timestamp ASC`, args...)
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
	for _, bt := range bucketTimes(from, to, g) {
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
	pathsArgs := []any{from, to}
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
	bwArgs := []any{from, to}
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

// RecentErrors returns the last `limit` log entries that look like
// real problems: caddy_error entries (level != info/debug), or access
// logs with 5xx status. Ordered newest first.
func (q *Queries) RecentErrors(ctx context.Context, limit int) ([]RecentError, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := q.DB.QueryContext(ctx, `
		SELECT timestamp, source, level, message FROM log_entries
		WHERE (source='caddy_error' AND level IN ('error','warn'))
		   OR (source='caddy_access' AND status >= 500)
		ORDER BY timestamp DESC
		LIMIT ?`, limit)
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
