// CLI subcommand: `argos demo seed-dense` / `argos demo clear-dense`.
//
// Writes a production-density log_entries table into the demo DB so
// long writes (retention purge, raw strip, rollup) and the 7 d
// dashboard can be gated on the demo BEFORE they touch prod. Strike
// 13 (v1.3.40.2) came from gating a 400k-row strip on a demo table
// that held a few thousand rows.
//
// The rows follow the shape of the prod table as measured on
// 2026-09-26 with read-only aggregate SELECTs (no prod row was
// copied): share per source, per day and per hour, status / method /
// duration / size mix, host rank shares, path / IP / user-agent
// cardinality and head shares, error-log families, and the raw
// column carrying a Caddy access-log JSON line of about 1.4 KB. The
// profile lives in the weighted tables below; every host, path, IP
// and user agent is synthetic (RFC 5737 / RFC 3849 addresses,
// example.{com,org,net} names).
//
// Usage:
//
//	argos demo seed-dense  [--yes] [--db <path>] [--rows 500000] [--days 7] [--seed 1]
//	argos demo clear-dense [--yes] [--db <path>]
//
// Same triple-key gate as `demo seed` (--yes, ARGOS_DEMO_SEED=1, DB
// path without "argos-prod"). Deterministic for a given --seed and
// --rows: two runs on a fresh DB give the same rows. Every dense row
// carries upstream = "demo-dense" so clear-dense removes exactly the
// rows this command wrote and `demo clear` (message LIKE 'demo:%')
// does not touch them.
//
// seed-dense needs the demo hosts (run `demo seed` first): host_id on
// access rows points at the hosts table like the header-injected
// X-Argos-Host-Id does on prod, which is what the dashboard top-hosts
// query groups by.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// denseMarker is the upstream value every dense row carries.
const denseMarker = "demo-dense"

// denseBatch rows per INSERT transaction. 5000 keeps the WAL below
// ~10 MB between autocheckpoints at 1.5 KB per row.
const denseBatch = 5000

type denseOpts struct {
	Yes    bool
	DBPath string
	Rows   int
	Days   int
	Seed   int64
	Stdout io.Writer
}

func parseDenseFlags(args []string) (*denseOpts, error) {
	fs := flag.NewFlagSet("demo seed-dense", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "confirm; required because this mutates the DB")
	dbPath := fs.String("db", "", "path to argos.db (default: $ARGOS_DB_PATH)")
	rows := fs.Int("rows", 500000, "log_entries rows to write")
	days := fs.Int("days", 7, "window ending now that the rows span")
	seed := fs.Int64("seed", 1, "PRNG seed; same seed + rows = same rows")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected positional args: %v", fs.Args())
	}
	if *rows <= 0 || *days <= 0 {
		return nil, fmt.Errorf("--rows and --days must be positive")
	}
	return &denseOpts{Yes: *yes, DBPath: *dbPath, Rows: *rows, Days: *days, Seed: *seed, Stdout: os.Stdout}, nil
}

func runDemoSeedDense(args []string) error {
	opts, err := parseDenseFlags(args)
	if err != nil {
		return err
	}
	dbPath, err := gateDemo(&demoOpts{Yes: opts.Yes, DBPath: opts.DBPath})
	if err != nil {
		return err
	}
	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()
	return seedDense(context.Background(), d, opts)
}

func runDemoClearDense(args []string) error {
	opts, err := parseDenseFlags(args)
	if err != nil {
		return err
	}
	dbPath, err := gateDemo(&demoOpts{Yes: opts.Yes, DBPath: opts.DBPath})
	if err != nil {
		return err
	}
	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()
	return clearDense(context.Background(), d, opts.Stdout)
}

// --- profile (prod aggregates, 2026-09-26, 7 days) -------------------

// weighted is a categorical distribution; pick returns an index.
type weighted struct {
	cum   []int
	total int
}

func newWeighted(w []int) weighted {
	cum := make([]int, len(w))
	t := 0
	for i, v := range w {
		t += v
		cum[i] = t
	}
	return weighted{cum: cum, total: t}
}

func (w weighted) pick(r *rand.Rand) int {
	n := r.Intn(w.total)
	return sort.SearchInts(w.cum, n+1)
}

// Share of rows per source: caddy_access ~96 %, caddy_error ~4 %
// (access 65-76k/day, error ~3k/day). audit stays with `demo seed`;
// waf_audit was empty on prod for the whole window.
var denseSourceW = newWeighted([]int{960, 40})

// Per-day share across the window (oldest first): 65-76k/day.
var denseDayW = []int{72, 76, 70, 65, 68, 74, 71}

// Per-hour share (UTC): flat 16-21.5k per hour over 7 days with a
// shallow dip around 03-06 UTC and the 01 UTC monitor peak.
var denseHourW = newWeighted([]int{
	190, 215, 185, 165, 160, 162, 170, 180,
	190, 200, 205, 210, 210, 205, 205, 200,
	200, 205, 210, 212, 208, 200, 195, 190,
})

var denseStatusCodes = []int{200, 403, 302, 308, 401, 301, 404, 500, 204, 304, 206}
var denseStatusW = newWeighted([]int{780, 88, 40, 30, 20, 20, 7, 3, 6, 4, 2})

var denseMethods = []string{"GET", "POST", "HEAD"}
var denseMethodW = newWeighted([]int{920, 76, 4})

// Duration buckets in ms: 52 % 1000-5000 (SSE / long-poll heavy
// prod), 29 % 20-50, 7 % 50-100, 5 % 100-250, 3 % 0-5, 3 % 250-1000,
// 1 % 5-20.
var denseDurBuckets = [][2]int{{1000, 5000}, {20, 50}, {50, 100}, {100, 250}, {0, 5}, {250, 1000}, {5, 20}}
var denseDurW = newWeighted([]int{52, 29, 7, 5, 3, 3, 1})

// Size buckets in bytes: 29 % <1K, 43 % 1-10K, 27 % 10-100K, 1 % >100K.
var denseSizeBuckets = [][2]int{{0, 1000}, {1000, 10000}, {10000, 100000}, {100000, 400000}}
var denseSizeW = newWeighted([]int{29, 43, 27, 1})

// Host rank shares (rows per host over 7 days, descending). Ranks
// beyond the demo hosts table land on host_id NULL with a synthetic
// domain, like prod's unattributed rows.
var denseHostW = newWeighted([]int{2720, 330, 270, 240, 140, 140, 140, 140, 140, 140, 140, 140, 140, 20, 20, 13, 10, 9, 7})

// Path head shares: 1 x 115k, 4 x 60k, 1 x 22k, 3 x 10k, then a tail
// of ~7,360 paths under 1k each (7,370 distinct on prod). Head = 81 %.
var densePathHead = []string{
	"/api/v1/notifications/stream/subscribe",
	"/", "/api/v1/health/live", "/socket.io/?EIO=4&transport=websocket", "/api/v1/metrics/summary",
	"/assets/index-9f8c2a1e.js",
	"/login", "/api/v1/system/status", "/favicon.ico",
}
var densePathHeadW = []int{115, 60, 60, 60, 60, 22, 10, 10, 10}

const densePathTailN = 7361
const densePathTailShare = 19 // percent of access rows

// User-agent head shares: 241k, 139k, 22k, 10k, 9.6k, 8.6k, 7.3k,
// 3.4k, then a tail (388 distinct on prod, avg 100 bytes).
var denseUAHead = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
	"Go-http-client/2.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
	"python-requests/2.32.3",
	"curl/8.5.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
}
var denseUAHeadW = []int{241, 139, 22, 10, 10, 9, 7, 3}

const denseUATailN = 380
const denseUATailShare = 8 // percent of access rows

// Distinct client IPs on prod: 941. RFC 5737 gives 768 IPv4; the rest
// come from the RFC 3849 documentation prefix.
const denseIPN = 941

// Error-log families (prod 7 d): health checker 20k, appsec
// unavailable 888, ACME renewal info 475, then a small tail.
type denseErrFamily struct {
	level, logger, msg, errText string
	attributed                  bool
}

var denseErrFamilies = []denseErrFamily{
	{"error", "http.handlers.reverse_proxy.health_checker.active", "HTTP request failed",
		"Get \"http://192.0.2.23:3001/\": dial tcp 192.0.2.23:3001: connect: connection refused", false},
	{"error", "http.handlers.crowdsec", "appsec unavailable, failing open",
		"Post \"http://crowdsec:7422/\": context deadline exceeded", true},
	{"info", "tls.renew", "certificate renewal scheduled", "", true},
	{"error", "http.log.error", "dial tcp: lookup upstream: no such host", "", true},
	{"warn", "http.handlers.reverse_proxy", "upstream unhealthy", "", false},
}
var denseErrW = newWeighted([]int{910, 40, 22, 18, 10})

// --- generation ------------------------------------------------------

type densePools struct {
	hosts   []denseHost
	paths   []string
	pathW   weighted
	uas     []string
	uaW     weighted
	ips     []string
	ipW     weighted
	cookies []string
}

type denseHost struct {
	id     *int64
	domain string
}

// zipfWeights returns n integer weights following 1/rank^s scaled so
// the largest is 1000 and none is below 1.
func zipfWeights(n int, s float64) []int {
	w := make([]int, n)
	for i := range w {
		v := 1000.0 / math.Pow(float64(i+1), s)
		if v < 1 {
			v = 1
		}
		w[i] = int(v)
	}
	return w
}

var denseWords = []string{
	"api", "v1", "v2", "users", "items", "orders", "assets", "img", "js", "css",
	"static", "media", "uploads", "search", "admin", "auth", "session", "cart",
	"product", "category", "feed", "rss", "wp-content", "wp-admin", "themes",
	"plugins", "fonts", "icons", "docs", "blog", "posts", "tags", "archive",
	"2025", "2026", "01", "02", "03", "index.html", "main.css", "app.js",
	"vendor.js", "logo.svg", "favicon.png", "manifest.json", "robots.txt",
	"sitemap.xml", "health", "metrics", "ws", "socket", "events", "stream",
	"export", "import", "report", "dashboard", "settings", "profile", "avatar",
}

func buildDensePools(ctx context.Context, d *sql.DB, r *rand.Rand) (*densePools, error) {
	p := &densePools{}

	rows, err := d.QueryContext(ctx, `SELECT id, domain FROM hosts ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var domain string
		if err := rows.Scan(&id, &domain); err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		idv := id
		p.hosts = append(p.hosts, denseHost{id: &idv, domain: domain})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("hosts: %w", err)
	}
	if len(p.hosts) == 0 {
		return nil, fmt.Errorf("hosts table is empty: run 'argos demo seed' first")
	}
	for i := len(p.hosts); i < len(denseHostW.cum); i++ {
		p.hosts = append(p.hosts, denseHost{domain: fmt.Sprintf("extra-%d.example.net", i+1)})
	}

	// Paths: head with explicit shares, tail with Zipf weights scaled so
	// the tail holds densePathTailShare percent of picks.
	p.paths = append(p.paths, densePathHead...)
	seen := map[string]bool{}
	for _, h := range densePathHead {
		seen[h] = true
	}
	for len(p.paths) < len(densePathHead)+densePathTailN {
		n := 3 + r.Intn(4)
		segs := make([]string, n)
		for i := range segs {
			segs[i] = denseWords[r.Intn(len(denseWords))]
		}
		if r.Intn(2) == 0 {
			segs[n-1] = fmt.Sprintf("%016x", r.Int63())[:8+r.Intn(9)] + "-" + segs[n-1]
		}
		path := "/" + strings.Join(segs, "/")
		if seen[path] {
			continue
		}
		seen[path] = true
		p.paths = append(p.paths, path)
	}
	p.pathW = newWeighted(headTailWeights(densePathHeadW, zipfWeights(densePathTailN, 0.9), 100-densePathTailShare, densePathTailShare))

	// User agents.
	p.uas = append(p.uas, denseUAHead...)
	uaTemplates := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36 Edg/%d.0.0.0",
		"Mozilla/5.0 (Linux; Android 14; SM-%d) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (compatible; bot-%d/1.%d; +https://example.org/bot)",
		"Mozilla/5.0 (X11; Linux x86_64; rv:%d.0) Gecko/20100101 Firefox/%d.0",
		"okhttp/4.%d.%d",
		"Uptime-Kuma/1.%d.%d",
		"Prometheus/2.%d.%d",
		"Mozilla/5.0 (iPad; CPU OS 16_%d like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.%d Mobile/15E148 Safari/604.1",
	}
	for len(p.uas) < len(denseUAHead)+denseUATailN {
		t := uaTemplates[r.Intn(len(uaTemplates))]
		p.uas = append(p.uas, fmt.Sprintf(t, 60+r.Intn(80), 60+r.Intn(80)))
	}
	p.uaW = newWeighted(headTailWeights(denseUAHeadW, zipfWeights(denseUATailN, 1.0), 100-denseUATailShare, denseUATailShare))

	// IPs: 768 IPv4 from the three RFC 5737 blocks plus 2001:db8::
	// hosts, Zipf-weighted (a few scanners / monitors dominate).
	for _, base := range []string{"192.0.2.", "198.51.100.", "203.0.113."} {
		for i := 1; i < 255; i++ {
			p.ips = append(p.ips, base+strconv.Itoa(i))
		}
	}
	for len(p.ips) < denseIPN {
		p.ips = append(p.ips, fmt.Sprintf("2001:db8:%x:%x::%x", r.Intn(0xffff), r.Intn(0xffff), 1+r.Intn(0xfffe)))
	}
	r.Shuffle(len(p.ips), func(i, j int) { p.ips[i], p.ips[j] = p.ips[j], p.ips[i] })
	p.ipW = newWeighted(zipfWeights(len(p.ips), 1.1))

	// A small cookie pool so raw lines carry a realistic Cookie header
	// without being unique per row (the ingestor never reads it).
	for i := 0; i < 64; i++ {
		p.cookies = append(p.cookies, fmt.Sprintf("session=%016x%016x; theme=dark", r.Int63(), r.Int63()))
	}
	return p, nil
}

// headTailWeights joins head and tail weights so that head picks make
// up headPct of the total and tail picks tailPct.
func headTailWeights(head, tail []int, headPct, tailPct int) []int {
	sum := func(w []int) int {
		t := 0
		for _, v := range w {
			t += v
		}
		return t
	}
	hs, ts := sum(head), sum(tail)
	// scale both to a common base of 1e6 * pct
	out := make([]int, 0, len(head)+len(tail))
	for _, v := range head {
		out = append(out, int(int64(v)*int64(headPct)*10000/int64(hs))+1)
	}
	for _, v := range tail {
		out = append(out, int(int64(v)*int64(tailPct)*10000/int64(ts))+1)
	}
	return out
}

func rangeInt(r *rand.Rand, b [2]int) int {
	if b[1] <= b[0] {
		return b[0]
	}
	return b[0] + r.Intn(b[1]-b[0])
}

type accessRaw struct {
	Level       string              `json:"level"`
	TS          float64             `json:"ts"`
	Logger      string              `json:"logger"`
	Msg         string              `json:"msg"`
	Request     accessRawRequest    `json:"request"`
	BytesRead   int                 `json:"bytes_read"`
	UserID      string              `json:"user_id"`
	Duration    float64             `json:"duration"`
	Size        int                 `json:"size"`
	Status      int                 `json:"status"`
	RespHeaders map[string][]string `json:"resp_headers"`
}

type accessRawRequest struct {
	RemoteIP   string              `json:"remote_ip"`
	RemotePort string              `json:"remote_port"`
	ClientIP   string              `json:"client_ip"`
	Proto      string              `json:"proto"`
	Method     string              `json:"method"`
	Host       string              `json:"host"`
	URI        string              `json:"uri"`
	Headers    map[string][]string `json:"headers"`
	TLS        accessRawTLS        `json:"tls"`
}

type accessRawTLS struct {
	Resumed     bool   `json:"resumed"`
	Version     int    `json:"version"`
	CipherSuite int    `json:"cipher_suite"`
	Proto       string `json:"proto"`
	ServerName  string `json:"server_name"`
}

var denseContentTypes = []string{"text/html; charset=utf-8", "application/json", "text/event-stream", "application/javascript", "text/css", "image/png", "image/svg+xml"}

func (p *densePools) accessRow(r *rand.Rand, ts time.Time) models.LogEntry {
	h := p.hosts[denseHostW.pick(r)]
	path := p.paths[p.pathW.pick(r)]
	ua := p.uas[p.uaW.pick(r)]
	ip := p.ips[p.ipW.pick(r)]
	status := denseStatusCodes[denseStatusW.pick(r)]
	method := denseMethods[denseMethodW.pick(r)]
	dur := rangeInt(r, denseDurBuckets[denseDurW.pick(r)])
	size := rangeInt(r, denseSizeBuckets[denseSizeW.pick(r)])
	if status == 304 || status == 204 || method == "HEAD" {
		size = 0
	}
	uri := path
	if r.Intn(4) == 0 {
		uri = path + "?v=" + strconv.Itoa(r.Intn(100000)) + "&t=" + strconv.FormatInt(ts.Unix(), 10)
	}
	hostID := ""
	if h.id != nil {
		hostID = strconv.FormatInt(*h.id, 10)
	}
	ct := denseContentTypes[r.Intn(len(denseContentTypes))]
	cfRay := fmt.Sprintf("%016x-MAD", r.Int63())
	reqHeaders := map[string][]string{
		"User-Agent":                {ua},
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		"Accept-Encoding":           {"gzip, deflate, br, zstd"},
		"Accept-Language":           {"en-US,en;q=0.9,es;q=0.8"},
		"Cookie":                    {p.cookies[r.Intn(len(p.cookies))]},
		"Sec-Fetch-Site":            {"same-origin"},
		"Sec-Fetch-Mode":            {"navigate"},
		"Sec-Fetch-Dest":            {"document"},
		"Sec-Ch-Ua-Mobile":          {"?0"},
		"Sec-Ch-Ua-Platform":        {"\"Linux\""},
		"Upgrade-Insecure-Requests": {"1"},
		"Cf-Connecting-Ip":          {ip},
		"Cf-Ray":                    {cfRay},
		"Cf-Ipcountry":              {"ES"},
		"X-Forwarded-For":           {ip},
		"X-Forwarded-Proto":         {"https"},
		"X-Argos-Target-Group":      {denseMarker},
	}
	if hostID != "" {
		reqHeaders["X-Argos-Host-Id"] = []string{hostID}
	}
	raw := accessRaw{
		Level:  "info",
		TS:     float64(ts.UnixNano()) / 1e9,
		Logger: "http.log.access.log0",
		Msg:    "handled request",
		Request: accessRawRequest{
			RemoteIP:   "198.51.100.1",
			RemotePort: strconv.Itoa(20000 + r.Intn(40000)),
			ClientIP:   ip,
			Proto:      "HTTP/2.0",
			Method:     method,
			Host:       h.domain,
			URI:        uri,
			Headers:    reqHeaders,
			TLS:        accessRawTLS{Resumed: r.Intn(2) == 0, Version: 772, CipherSuite: 4865, Proto: "h2", ServerName: h.domain},
		},
		BytesRead: 0,
		UserID:    "",
		Duration:  float64(dur) / 1000,
		Size:      size,
		Status:    status,
		RespHeaders: map[string][]string{
			"Server":                    {"Caddy"},
			"Content-Type":              {ct},
			"Date":                      {ts.UTC().Format(time.RFC1123)},
			"Content-Length":            {strconv.Itoa(size)},
			"Alt-Svc":                   {"h3=\":443\"; ma=2592000"},
			"Cache-Control":             {"no-cache, no-store, must-revalidate"},
			"Vary":                      {"Accept-Encoding, Cookie"},
			"X-Content-Type-Options":    {"nosniff"},
			"Strict-Transport-Security": {"max-age=31536000; includeSubDomains"},
		},
	}
	if method == "POST" {
		raw.BytesRead = 100 + r.Intn(4000)
		raw.Request.Headers["Content-Type"] = []string{"application/json"}
		raw.Request.Headers["Content-Length"] = []string{strconv.Itoa(raw.BytesRead)}
	}
	b, _ := json.Marshal(raw)
	e := models.LogEntry{
		Timestamp:  ts,
		Source:     models.LogCaddyAccess,
		Level:      "info",
		HostID:     h.id,
		HostDomain: h.domain,
		RemoteIP:   ip,
		Method:     method,
		Path:       path,
		Status:     status,
		DurationMs: dur,
		SizeBytes:  size,
		UserAgent:  ua,
		Upstream:   denseMarker,
		Raw:        string(b),
	}
	return e
}

func (p *densePools) errorRow(r *rand.Rand, ts time.Time) models.LogEntry {
	f := denseErrFamilies[denseErrW.pick(r)]
	raw := map[string]any{
		"level":  f.level,
		"ts":     float64(ts.UnixNano()) / 1e9,
		"logger": f.logger,
		"msg":    f.msg,
	}
	msg := f.logger + ": " + f.msg
	if f.errText != "" {
		raw["error"] = f.errText
		msg += " -- " + f.errText
	}
	e := models.LogEntry{
		Timestamp: ts,
		Source:    models.LogCaddyError,
		Level:     f.level,
		Upstream:  denseMarker,
		Message:   msg,
	}
	if f.attributed {
		h := p.hosts[denseHostW.pick(r)]
		raw["request"] = map[string]any{"host": h.domain, "remote_ip": p.ips[p.ipW.pick(r)]}
		e.HostDomain = h.domain
		e.HostID = h.id
	} else {
		raw["host"] = "192.0.2.23:3001"
	}
	b, _ := json.Marshal(raw)
	e.Raw = string(b)
	return e
}

// bucketCounts splits total rows over days*24 hour buckets following
// the day and hour weights, oldest bucket first. Rounding leftovers
// go to the newest bucket.
func bucketCounts(total, days int) []int {
	nb := days * 24
	w := make([]int, nb)
	sum := 0
	for d := 0; d < days; d++ {
		dw := denseDayW[d%len(denseDayW)]
		for h := 0; h < 24; h++ {
			hw := denseHourW.cum[h]
			if h > 0 {
				hw -= denseHourW.cum[h-1]
			}
			w[d*24+h] = dw * hw
			sum += w[d*24+h]
		}
	}
	out := make([]int, nb)
	given := 0
	for i := range w {
		out[i] = int(int64(total) * int64(w[i]) / int64(sum))
		given += out[i]
	}
	out[nb-1] += total - given
	return out
}

func seedDense(ctx context.Context, d *sql.DB, opts *denseOpts) error {
	start := time.Now()
	r := rand.New(rand.NewSource(opts.Seed))
	pools, err := buildDensePools(ctx, d, r)
	if err != nil {
		return err
	}
	var before int
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM log_entries WHERE upstream = ?`, denseMarker).Scan(&before); err != nil {
		return fmt.Errorf("count dense: %w", err)
	}
	if before > 0 {
		return fmt.Errorf("%d dense rows already present: run 'argos demo clear-dense --yes' first", before)
	}

	end := time.Now().UTC().Truncate(time.Minute)
	windowStart := end.Add(-time.Duration(opts.Days) * 24 * time.Hour)
	counts := bucketCounts(opts.Rows, opts.Days)

	batch := make([]models.LogEntry, 0, denseBatch)
	var written, access, errors int
	var rawBytes int64
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := db.InsertLogBatch(ctx, d, batch); err != nil {
			return fmt.Errorf("insert batch at row %d: %w", written, err)
		}
		written += len(batch)
		batch = batch[:0]
		return nil
	}
	for b, n := range counts {
		bucketStart := windowStart.Add(time.Duration(b) * time.Hour)
		offs := make([]int, n)
		for i := range offs {
			offs[i] = r.Intn(3600000)
		}
		sort.Ints(offs)
		for _, off := range offs {
			ts := bucketStart.Add(time.Duration(off) * time.Millisecond)
			var e models.LogEntry
			if denseSourceW.pick(r) == 0 {
				e = pools.accessRow(r, ts)
				access++
			} else {
				e = pools.errorRow(r, ts)
				errors++
			}
			rawBytes += int64(len(e.Raw))
			batch = append(batch, e)
			if len(batch) == denseBatch {
				if err := flush(); err != nil {
					return err
				}
				if written%50000 == 0 {
					fmt.Fprintf(opts.Stdout, "  %d/%d rows (%s)\n", written, opts.Rows, time.Since(start).Round(time.Second))
				}
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	if _, err := d.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	elapsed := time.Since(start)
	fmt.Fprintf(opts.Stdout, "seed-dense: %d rows (%d access, %d error) from %s to %s\n",
		written, access, errors, windowStart.Format(time.RFC3339), end.Format(time.RFC3339))
	fmt.Fprintf(opts.Stdout, "seed-dense: raw avg %d bytes, %.1f MB total; seed=%d; generation time %s\n",
		rawBytes/int64(maxInt(written, 1)), float64(rawBytes)/1e6, opts.Seed, elapsed.Round(time.Millisecond))
	return nil
}

func clearDense(ctx context.Context, d *sql.DB, out io.Writer) error {
	start := time.Now()
	res, err := d.ExecContext(ctx, `DELETE FROM log_entries WHERE upstream = ?`, denseMarker)
	if err != nil {
		return fmt.Errorf("delete dense rows: %w", err)
	}
	n, _ := res.RowsAffected()
	if _, err := d.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	fmt.Fprintf(out, "clear-dense: %d rows deleted in %s\n", n, time.Since(start).Round(time.Millisecond))
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
