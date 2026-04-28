// CLI subcommand: `argos demo ...`.
//
// Populates a standalone demo SQLite with production-density
// content across the panel surfaces so an operator (or a docs-
// screenshot session) sees populated tables instead of a fresh-
// install zero state. Companion to the ~/argos-demo/ scaffold.
//
// Usage:
//
//	argos demo seed              [--yes] [--db <path>] [--verbose]
//	argos demo clear             [--yes] [--db <path>]
//	argos demo stats             [--db <path>]
//	argos demo seed-self-block   [--yes] [--db <path>]
//	argos demo clear-self-block  [--yes] [--db <path>]
//
// Triple-key safety to prevent ever wiping the prod DB:
//
//   1. --yes flag must be present (except for `stats`, which is read-only).
//   2. ARGOS_DEMO_SEED=1 env var must be set.
//   3. ARGOS_DB_PATH must NOT contain "argos-prod".
//
// All seeded data is RFC 5737 IP space (192.0.2.x, 198.51.100.x,
// 203.0.113.x), example.com / example.org / example.net hostnames,
// and obviously-fake credentials. Idempotent: every surface uses
// either INSERT OR IGNORE (UNIQUE-keyed tables) or a DELETE-then-
// INSERT pass scoped by the "demo:" marker. Re-running seed
// produces a stable count.
//
// Same env contract as the other CLI subcommands: requires
// ARGOS_DB_PATH (or --db <path>).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

const demoMarker = "demo:"

// demoRand is seeded deterministically so successive seed runs
// produce the same payload. Predictable counts + predictable IPs
// make the count-assertion smoke phase reliable.
var demoRand = rand.New(rand.NewSource(0xa1605))

func runDemoCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: argos demo <seed|clear|stats|seed-self-block|clear-self-block> [args]")
	}
	switch args[0] {
	case "seed":
		return runDemoSeed(args[1:])
	case "clear":
		return runDemoClear(args[1:])
	case "stats":
		return runDemoStats(args[1:])
	case "seed-self-block":
		return runDemoSeedSelfBlock(args[1:])
	case "clear-self-block":
		return runDemoClearSelfBlock(args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(os.Stdout, "argos demo seed              [--yes] [--db <path>] [--verbose]")
		fmt.Fprintln(os.Stdout, "argos demo clear             [--yes] [--db <path>]")
		fmt.Fprintln(os.Stdout, "argos demo stats             [--db <path>]")
		fmt.Fprintln(os.Stdout, "argos demo seed-self-block   [--yes] [--db <path>]")
		fmt.Fprintln(os.Stdout, "argos demo clear-self-block  [--yes] [--db <path>]")
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintln(os.Stdout, "Required env: ARGOS_DEMO_SEED=1, ARGOS_DB_PATH (or --db)")
		fmt.Fprintln(os.Stdout, "Refuses to run when ARGOS_DB_PATH contains 'argos-prod'.")
		return nil
	default:
		return fmt.Errorf("unknown demo subcommand %q", args[0])
	}
}

type demoOpts struct {
	Yes     bool
	Verbose bool
	DBPath  string
	Stdout  io.Writer
}

func parseDemoFlags(args []string) (*demoOpts, error) {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "confirm; required because seed/clear mutates the DB")
	verbose := fs.Bool("verbose", false, "print per-surface counts as they're seeded")
	dbPath := fs.String("db", "", "path to argos.db (default: $ARGOS_DB_PATH)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected positional args: %v", fs.Args())
	}
	return &demoOpts{Yes: *yes, Verbose: *verbose, DBPath: *dbPath, Stdout: os.Stdout}, nil
}

// gateDemo enforces the three safety keys. Returns the resolved DB
// path on success.
func gateDemo(opts *demoOpts) (string, error) {
	if !opts.Yes {
		return "", fmt.Errorf("--yes required (this mutates the DB)")
	}
	if os.Getenv("ARGOS_DEMO_SEED") != "1" {
		return "", fmt.Errorf("ARGOS_DEMO_SEED=1 env var required (refuse-to-run safety)")
	}
	dbPath := opts.DBPath
	if dbPath == "" {
		dbPath = os.Getenv("ARGOS_DB_PATH")
	}
	if dbPath == "" {
		return "", fmt.Errorf("ARGOS_DB_PATH (or --db) required")
	}
	if strings.Contains(dbPath, "argos-prod") {
		return "", fmt.Errorf("refusing: ARGOS_DB_PATH=%q contains 'argos-prod' substring", dbPath)
	}
	return dbPath, nil
}

// gateDemoStats is the read-only gate. Identical to gateDemo but
// without the --yes requirement.
func gateDemoStats(opts *demoOpts) (string, error) {
	if os.Getenv("ARGOS_DEMO_SEED") != "1" {
		return "", fmt.Errorf("ARGOS_DEMO_SEED=1 env var required (refuse-to-run safety)")
	}
	dbPath := opts.DBPath
	if dbPath == "" {
		dbPath = os.Getenv("ARGOS_DB_PATH")
	}
	if dbPath == "" {
		return "", fmt.Errorf("ARGOS_DB_PATH (or --db) required")
	}
	if strings.Contains(dbPath, "argos-prod") {
		return "", fmt.Errorf("refusing: ARGOS_DB_PATH=%q contains 'argos-prod'", dbPath)
	}
	return dbPath, nil
}

func runDemoSeed(args []string) error {
	opts, err := parseDemoFlags(args)
	if err != nil {
		return err
	}
	dbPath, err := gateDemo(opts)
	if err != nil {
		return err
	}
	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()
	return seedDemoDB(context.Background(), d, opts)
}

func runDemoClear(args []string) error {
	opts, err := parseDemoFlags(args)
	if err != nil {
		return err
	}
	dbPath, err := gateDemo(opts)
	if err != nil {
		return err
	}
	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()
	return clearDemoDB(context.Background(), d, opts.Stdout)
}

// counters tracks how many rows each surface populated. Surfaces
// that the seed is purely additive on (none, post-v1.3.35.2 every
// surface uses DELETE+INSERT or INSERT OR IGNORE) report the
// post-seed row count.
type seedCounters struct {
	Hosts          int
	Whitelist      int
	Country        int
	CountryJobs    int
	Activity       int
	Settings       int
	Channels       int
	Rules          int
	Deliveries     int
	Backups        int
	LoginAttempts  int
}

// seedDemoDB orchestrates the per-surface seed functions. Each one
// is idempotent on its own; running the whole pass twice produces
// the same row counts.
func seedDemoDB(ctx context.Context, d *sql.DB, opts *demoOpts) error {
	now := time.Now().UTC()
	c := &seedCounters{}

	if err := seedHosts(ctx, d, c); err != nil {
		return err
	}
	verboseLog(opts, "hosts:        %d", c.Hosts)

	if err := seedWhitelist(ctx, d, c); err != nil {
		return err
	}
	verboseLog(opts, "whitelist:    %d", c.Whitelist)

	if err := seedCountryBans(ctx, d, c); err != nil {
		return err
	}
	verboseLog(opts, "country bans: %d (jobs: %d)", c.Country, c.CountryJobs)

	if err := seedActivityLog(ctx, d, c, now); err != nil {
		return err
	}
	verboseLog(opts, "activity:     %d", c.Activity)

	if err := seedSettings(ctx, d, c, now); err != nil {
		return err
	}
	verboseLog(opts, "settings:     %d keys", c.Settings)

	if err := seedNotificationChannels(ctx, d, c); err != nil {
		return err
	}
	verboseLog(opts, "channels:     %d", c.Channels)

	if err := seedNotificationRules(ctx, d, c); err != nil {
		return err
	}
	verboseLog(opts, "rules:        %d", c.Rules)

	if err := seedNotificationDeliveries(ctx, d, c, now); err != nil {
		return err
	}
	verboseLog(opts, "deliveries:   %d", c.Deliveries)

	if err := seedBackups(ctx, d, c, now); err != nil {
		return err
	}
	verboseLog(opts, "backups:      %d", c.Backups)

	if err := seedLoginAttempts(ctx, d, c, now); err != nil {
		return err
	}
	verboseLog(opts, "login attempts: %d", c.LoginAttempts)

	fmt.Fprintf(opts.Stdout,
		"demo seed complete: hosts=%d whitelist=%d countries=%d (jobs=%d) "+
			"activity=%d settings=%d channels=%d rules=%d deliveries=%d "+
			"backups=%d login_attempts=%d\n",
		c.Hosts, c.Whitelist, c.Country, c.CountryJobs,
		c.Activity, c.Settings, c.Channels, c.Rules, c.Deliveries,
		c.Backups, c.LoginAttempts)
	fmt.Fprintln(opts.Stdout, "all rows tagged with 'demo:' or scoped via foreign keys to demo: rows; clear with: argos demo clear --yes")
	return nil
}

func verboseLog(opts *demoOpts, format string, args ...any) {
	if opts == nil || !opts.Verbose {
		return
	}
	fmt.Fprintf(opts.Stdout, "  "+format+"\n", args...)
}

// --- 1. Hosts (14 entries, mix of TLS modes + true_detect_mode + lan_only) ---

func seedHosts(ctx context.Context, d *sql.DB, c *seedCounters) error {
	hosts := []struct {
		domain       string
		upHost       string
		upPort       int
		protocol     string
		tlsMode      string
		challenge    string
		dnsProvider  string
		lanOnly      int
		trueDetect   int
		authRequired int
	}{
		{"shop.example.com", "192.0.2.10", 8080, "http", "auto", "dns", "cloudflare", 0, 0, 0},
		{"blog.example.com", "192.0.2.11", 8080, "http", "auto", "dns", "cloudflare", 0, 0, 0},
		{"api.example.com", "192.0.2.12", 9000, "http", "auto", "dns", "cloudflare", 0, 0, 1},
		{"admin.example.com", "192.0.2.13", 3000, "http", "auto", "http", "cloudflare", 0, 1, 1},
		{"vault.example.com", "192.0.2.14", 8200, "https", "auto", "dns", "cloudflare", 0, 1, 1},
		{"dashboard.example.org", "192.0.2.15", 3000, "http", "auto", "dns", "cloudflare", 0, 0, 1},
		{"status.example.org", "192.0.2.16", 3001, "http", "auto", "dns", "cloudflare", 0, 0, 0},
		{"grafana.example.net", "192.0.2.20", 3000, "http", "auto", "dns", "cloudflare", 0, 1, 0},
		{"prometheus.example.net", "192.0.2.21", 9090, "http", "none", "dns", "cloudflare", 1, 0, 0},
		{"monitoring.example.com", "192.0.2.22", 3000, "http", "auto", "dns", "cloudflare", 0, 1, 0},
		{"kuma.example.com", "192.0.2.23", 3001, "http", "auto", "dns", "cloudflare", 0, 1, 0},
		{"webhook.example.com", "192.0.2.24", 4000, "http", "auto", "tls-alpn", "cloudflare", 0, 0, 0},
		{"dev.example.com", "192.0.2.30", 8080, "http", "auto", "dns", "cloudflare", 0, 0, 0},
		{"staging.example.com", "192.0.2.31", 8080, "http", "auto", "dns", "cloudflare", 0, 0, 0},
	}
	for _, h := range hosts {
		tgName := demoMarker + " " + h.domain
		if _, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO target_groups (name, protocol)
			VALUES (?, ?)`, tgName, h.protocol); err != nil {
			return fmt.Errorf("seed target_group %q: %w", tgName, err)
		}
		var tgID int64
		if err := d.QueryRowContext(ctx,
			`SELECT id FROM target_groups WHERE name = ?`, tgName).Scan(&tgID); err != nil {
			return fmt.Errorf("lookup target_group %q: %w", tgName, err)
		}
		if _, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO targets (target_group_id, host, port, weight)
			VALUES (?, ?, ?, 1)`, tgID, h.upHost, h.upPort); err != nil {
			return fmt.Errorf("seed target: %w", err)
		}
		hres, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO hosts
			  (domain, target_group_id, tls_mode, tls_email, enabled,
			   tls_challenge, tls_dns_provider, lan_only,
			   true_detect_mode, auth_required)
			VALUES (?, ?, ?, 'demo@example.com', 1, ?, ?, ?, ?, ?)`,
			h.domain, tgID, h.tlsMode,
			h.challenge, h.dnsProvider, h.lanOnly, h.trueDetect, h.authRequired)
		if err != nil {
			return fmt.Errorf("seed host %q: %w", h.domain, err)
		}
		hn, _ := hres.RowsAffected()
		if hn > 0 {
			c.Hosts++
		}
	}
	return nil
}

// --- 2. Whitelist (8 entries) ---

func seedWhitelist(ctx context.Context, d *sql.DB, c *seedCounters) error {
	whitelist := []struct {
		scope, value, reason string
	}{
		{"range", "192.0.2.0/24", "demo: office network"},
		{"ip", "198.51.100.10", "demo: monitoring vendor"},
		{"ip", "198.51.100.11", "demo: monitoring vendor backup"},
		{"ip", "198.51.100.50", "demo: vpn exit"},
		{"ip", "203.0.113.20", "demo: ci runner #1"},
		{"ip", "203.0.113.21", "demo: ci runner #2"},
		{"ip", "203.0.113.42", "demo: oncall pager"},
		{"ip", "192.0.2.200", "demo: legacy bastion"},
	}
	for _, w := range whitelist {
		res, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO security_whitelist (scope, value, reason)
			VALUES (?, ?, ?)`, w.scope, w.value, w.reason)
		if err != nil {
			return fmt.Errorf("seed whitelist %q: %w", w.value, err)
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			c.Whitelist++
		}
	}
	return nil
}

// --- 3. Country bans (8 countries; one in drifted state) ---

func seedCountryBans(ctx context.Context, d *sql.DB, c *seedCounters) error {
	countries := []struct {
		cc       string
		cidrs    int
		duration string
		reason   string
		state    string
	}{
		{"BR", 5009, "168h", "demo: spike from BR", "active"},
		{"CN", 38241, "720h", "demo: brute-force activity", "active"},
		{"KR", 3517, "168h", "demo: fingerprinted scanner", "active"},
		{"RU", 12048, "720h", "demo: post-incident lockdown", "drifted"},
		{"IR", 1454, "168h", "demo: sustained CVE probing", "active"},
		{"NG", 471, "168h", "demo: short-window crawl", "active"},
		{"VN", 2091, "168h", "demo: leak-driven block", "active"},
		{"TR", 3208, "168h", "demo: regional incident", "active"},
	}
	for _, cc := range countries {
		ids := make([]int, 0, 8)
		for i := 0; i < 8; i++ {
			ids = append(ids, 100000+demoRand.Intn(900000))
		}
		idsJSON, _ := json.Marshal(ids)
		res, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO country_ban_expansions
			  (country_code, decision_ids, cidr_count, reason, duration,
			   created_by, mmdb_version_at_creation, state)
			VALUES (?, ?, ?, ?, ?, 'demo', '2026.04', ?)`,
			cc.cc, string(idsJSON), cc.cidrs, cc.reason, cc.duration, cc.state)
		if err != nil {
			return fmt.Errorf("seed country %s: %w", cc.cc, err)
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			c.Country++
		}
	}

	// country_expansion_jobs history (10 rows: 8 completed matching the
	// active countries + 1 failed + 1 in-flight-then-recovered-failed)
	if _, err := d.ExecContext(ctx,
		`DELETE FROM country_expansion_jobs WHERE created_by = 'demo'`); err != nil {
		return fmt.Errorf("clear demo country jobs: %w", err)
	}
	jobs := []struct {
		cc           string
		state        string
		chunksTotal  int
		chunksDone   int
		cidrCommitted int
		err          string
		minutesAgo   int
	}{
		{"BR", "completed", 11, 11, 5009, "", 1440 * 7},
		{"CN", "completed", 77, 77, 38241, "", 1440 * 6},
		{"KR", "completed", 8, 8, 3517, "", 1440 * 6},
		{"RU", "completed", 25, 25, 12048, "", 1440 * 5},
		{"IR", "completed", 3, 3, 1454, "", 1440 * 5},
		{"NG", "completed", 1, 1, 471, "", 1440 * 4},
		{"VN", "completed", 5, 5, 2091, "", 1440 * 3},
		{"TR", "completed", 7, 7, 3208, "", 1440 * 2},
		{"JP", "failed", 0, 0, 0, "panel restarted", 1440 * 4},
		{"AU", "failed", 4, 1, 500, "LAPI 503 mid-chunk", 1440},
	}
	now := time.Now().UTC()
	for _, j := range jobs {
		ts := now.Add(-time.Duration(j.minutesAgo) * time.Minute)
		var startedAt, completedAt any
		if j.state != "pending" {
			startedAt = ts
		}
		if j.state == "completed" || j.state == "failed" {
			completedAt = ts.Add(time.Duration(j.chunksTotal) * 200 * time.Millisecond)
		}
		if _, err := d.ExecContext(ctx, `
			INSERT INTO country_expansion_jobs
			  (country_code, state, chunks_total, chunks_done,
			   cidr_committed, duration, reason, error_message,
			   created_at, started_at, completed_at, created_by)
			VALUES (?, ?, ?, ?, ?, '168h', ?, ?, ?, ?, ?, 'demo')`,
			j.cc, j.state, j.chunksTotal, j.chunksDone, j.cidrCommitted,
			"demo: "+j.cc+" expansion", j.err, ts, startedAt, completedAt); err != nil {
			return fmt.Errorf("seed country job %s: %w", j.cc, err)
		}
		c.CountryJobs++
	}
	return nil
}

// --- 4. Activity log (100 entries, multi-user, 14-day spread) ---

func seedActivityLog(ctx context.Context, d *sql.DB, c *seedCounters, now time.Time) error {
	// Clear previous demo: rows so re-seed gives a stable count.
	if _, err := d.ExecContext(ctx,
		`DELETE FROM log_entries WHERE source = 'audit' AND message LIKE 'demo:%'`); err != nil {
		return fmt.Errorf("clear demo activity: %w", err)
	}

	users := []string{"admin", "operator1", "operator2", "monitor"}
	srcIPs := []string{
		"192.0.2.100", "192.0.2.101", "192.0.2.102", // office network
		"198.51.100.50", // vpn exit
		"203.0.113.20", "203.0.113.21", // ci runners
	}
	templates := []struct {
		level    string
		template string
	}{
		{"info", "demo: panel mutation -- host added: %s"},
		{"info", "demo: panel mutation -- host updated: %s"},
		{"info", "demo: panel mutation -- target group updated"},
		{"warn", "demo: AppSec inbound score over threshold"},
		{"warn", "demo: drift detected -- scenarios out of sync"},
		{"info", "demo: scenario disabled: %s"},
		{"info", "demo: scenario re-enabled: %s"},
		{"info", "demo: country ban added: %s"},
		{"info", "demo: country ban revoked: %s"},
		{"info", "demo: cert renewal succeeded: %s"},
		{"warn", "demo: cert renewal soft-failed (will retry)"},
		{"warn", "demo: backup completed"},
		{"info", "demo: backup completed (kind=manual)"},
		{"error", "demo: target unhealthy: %s"},
		{"info", "demo: target recovered: %s"},
		{"info", "demo: notification channel created: %s"},
		{"info", "demo: notification rule updated"},
		{"info", "demo: whitelist entry added: %s"},
		{"info", "demo: AppSec threshold change: inbound %d -> %d"},
		{"info", "demo: panel restarted (argosVersion 1.3.35)"},
	}
	hostExamples := []string{"shop.example.com", "api.example.com", "blog.example.com",
		"admin.example.com", "vault.example.com", "grafana.example.net"}
	scenarios := []string{"crowdsecurity/http-bf-wordpress_bf",
		"crowdsecurity/http-probing", "crowdsecurity/http-cve",
		"crowdsecurity/http-sensitive-files", "crowdsecurity/ssh-slow-bf"}
	countries := []string{"BR", "CN", "KR", "RU", "IR", "NG", "VN", "TR"}
	channelNames := []string{"ops-alerts", "dev-warnings", "slack-bridge", "weekly-digest"}
	whitelistVals := []string{"198.51.100.10", "203.0.113.20", "203.0.113.42"}
	thresholds := [][2]int{{15, 12}, {12, 10}, {10, 12}}

	const total = 100
	for i := 0; i < total; i++ {
		// Spread over last 14 days, biased toward recent.
		minutesAgo := demoRand.Intn(60 * 24 * 14)
		ts := now.Add(-time.Duration(minutesAgo) * time.Minute)
		t := templates[demoRand.Intn(len(templates))]

		var msg string
		switch {
		case strings.Contains(t.template, "host added") || strings.Contains(t.template, "host updated") ||
			strings.Contains(t.template, "cert renewal succeeded") ||
			strings.Contains(t.template, "target unhealthy") || strings.Contains(t.template, "target recovered"):
			msg = fmt.Sprintf(t.template, hostExamples[demoRand.Intn(len(hostExamples))])
		case strings.Contains(t.template, "scenario"):
			msg = fmt.Sprintf(t.template, scenarios[demoRand.Intn(len(scenarios))])
		case strings.Contains(t.template, "country"):
			msg = fmt.Sprintf(t.template, countries[demoRand.Intn(len(countries))])
		case strings.Contains(t.template, "notification channel"):
			msg = fmt.Sprintf(t.template, channelNames[demoRand.Intn(len(channelNames))])
		case strings.Contains(t.template, "whitelist"):
			msg = fmt.Sprintf(t.template, whitelistVals[demoRand.Intn(len(whitelistVals))])
		case strings.Contains(t.template, "AppSec threshold"):
			th := thresholds[demoRand.Intn(len(thresholds))]
			msg = fmt.Sprintf(t.template, th[0], th[1])
		default:
			msg = t.template
		}

		user := users[demoRand.Intn(len(users))]
		ip := srcIPs[demoRand.Intn(len(srcIPs))]
		raw := fmt.Sprintf(`{"demo":true,"user":%q,"remote_ip":%q,"text":%q}`, user, ip, msg)

		if _, err := d.ExecContext(ctx, `
			INSERT INTO log_entries (timestamp, source, level, message, raw)
			VALUES (?, 'audit', ?, ?, ?)`,
			ts, t.level, msg, raw); err != nil {
			return fmt.Errorf("seed activity row: %w", err)
		}
		c.Activity++
	}
	return nil
}

// --- 5. Settings (AppSec tuning + drift state in 2 surfaces +
// disabled scenarios) ---

func seedSettings(ctx context.Context, d *sql.DB, c *seedCounters, now time.Time) error {
	// AppSec drift: inbound 12 (panel intent) vs runtime=15 (drift_detected=true).
	settingsRows := []struct{ k, v string }{
		{"appsec.tuning.inbound_threshold", "12"},
		{"appsec.tuning.outbound_threshold", "5"},
		{"appsec.tuning.last_modified_by", "demo"},
		{"appsec.disabled_scenarios", `["crowdsecurity/http-cve","crowdsecurity/aws-bf","crowdsecurity/ssh-slow-bf","crowdsecurity/http-bf-wordpress_bf","crowdsecurity/http-probing"]`},
		{"appsec.scenarios.drift_state", `{"drift_detected":true,"expected_disabled":["crowdsecurity/http-cve","crowdsecurity/aws-bf","crowdsecurity/ssh-slow-bf","crowdsecurity/http-bf-wordpress_bf","crowdsecurity/http-probing"],"actually_enabled":["crowdsecurity/http-bf-wordpress_bf","crowdsecurity/http-probing"],"last_check_at":"` + now.Format(time.RFC3339) + `"}`},
		{"appsec.tuning.drift_state", `{"drift_detected":true,"expected_inbound":12,"actual_inbound":15,"expected_outbound":5,"actual_outbound":4,"last_check_at":"` + now.Format(time.RFC3339) + `"}`},
	}
	for _, s := range settingsRows {
		if _, err := d.ExecContext(ctx,
			`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, s.k, s.v); err != nil {
			return fmt.Errorf("seed setting %q: %w", s.k, err)
		}
		c.Settings++
	}
	return nil
}

// --- 6. Notification channels (5 entries) ---

type demoChannel struct {
	name, ctype, template string
	parseMode             string // empty -> sender default (HTML for Telegram post-v1.3.34.1)
	cfg                   map[string]any
}

func demoChannels() []demoChannel {
	return []demoChannel{
		{
			"demo: ops-alerts", "telegram", "",
			"",
			map[string]any{"bot_token": "111111:demo-ops-bot-token-not-real", "chat_id": "1001"},
		},
		{
			"demo: dev-warnings", "telegram",
			`{{ .Severity | severityEmoji }} <b>{{ .Type | escapeHTML }}</b>` + "\n" +
				`{{ if .HostDomain }}host: <code>{{ .HostDomain | escapeHTML }}</code>{{ end }}` + "\n" +
				`<i>{{ .Message | escapeHTML }}</i>`,
			"",
			map[string]any{"bot_token": "222222:demo-dev-bot-token-not-real", "chat_id": "1002"},
		},
		{
			"demo: slack-bridge", "webhook", "",
			"",
			map[string]any{
				"url":     "https://example.com/services/T-DEMO/B-DEMO/slack-token",
				"method":  "POST",
				"headers": map[string]string{"Content-Type": "application/json"},
			},
		},
		{
			"demo: pagerduty", "webhook", "",
			"",
			map[string]any{
				"url":    "https://events.example.com/v2/enqueue",
				"method": "POST",
				"headers": map[string]string{
					"Content-Type": "application/json",
					"Authorization": "Token token=demo-pd-token-not-real",
				},
			},
		},
		{
			"demo: weekly-digest", "email", "",
			"",
			map[string]any{
				"host":          "smtp.example.com",
				"port":          587,
				"username":      "demo@example.com",
				"smtp_password": "demo-smtp-password-not-real",
				"tls_mode":      "starttls",
				"from":          "alerts@example.com",
				"to":            "ops@example.com",
			},
		},
	}
}

func seedNotificationChannels(ctx context.Context, d *sql.DB, c *seedCounters) error {
	for _, ch := range demoChannels() {
		cfgJSON, _ := json.Marshal(ch.cfg)
		res, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO notification_channels
			  (name, type, enabled, config, template, rate_limit_per_minute)
			VALUES (?, ?, 1, ?, ?, 10)`,
			ch.name, ch.ctype, string(cfgJSON), ch.template)
		if err != nil {
			return fmt.Errorf("seed channel %q: %w", ch.name, err)
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			c.Channels++
		}
	}
	return nil
}

// --- 7. Notification rules (6 routing rules) ---

func seedNotificationRules(ctx context.Context, d *sql.DB, c *seedCounters) error {
	if _, err := d.ExecContext(ctx,
		`DELETE FROM notification_rules WHERE name LIKE 'demo:%'`); err != nil {
		return fmt.Errorf("clear demo rules: %w", err)
	}

	type ruleSpec struct {
		name, channelName, eventType, severities string
		throttleSec                              int
	}
	rules := []ruleSpec{
		{"demo: bans -> ops-alerts", "demo: ops-alerts", "threat_ip_banned", "", 0},
		{"demo: critical -> pagerduty", "demo: pagerduty", "crowdsec_down", `["critical","error"]`, 60},
		{"demo: critical -> ops-alerts", "demo: ops-alerts", "crowdsec_down", `["critical"]`, 60},
		{"demo: drift -> ops-alerts", "demo: ops-alerts", "config_change", `["warning","error","critical"]`, 300},
		{"demo: login fail -> dev-warnings", "demo: dev-warnings", "login_failed", "", 600},
		{"demo: weekly digest -> email", "demo: weekly-digest", "backup_completed", `["info"]`, 0},
	}

	for _, r := range rules {
		var chID int64
		if err := d.QueryRowContext(ctx,
			`SELECT id FROM notification_channels WHERE name = ?`, r.channelName).Scan(&chID); err != nil {
			// channel might not exist yet (test schema may skip channels).
			// skip with a warn-equivalent: the rule is just unused.
			continue
		}
		if _, err := d.ExecContext(ctx, `
			INSERT INTO notification_rules
			  (name, channel_id, event_type, filter_host_ids,
			   filter_severities, enabled, throttle_window_seconds)
			VALUES (?, ?, ?, '', ?, 1, ?)`,
			r.name, chID, r.eventType, r.severities, r.throttleSec); err != nil {
			return fmt.Errorf("seed rule %q: %w", r.name, err)
		}
		c.Rules++
	}
	return nil
}

// --- 8. Notification deliveries (250 entries spread across 30 days) ---

func seedNotificationDeliveries(ctx context.Context, d *sql.DB, c *seedCounters, now time.Time) error {
	// Clear demo deliveries by event_payload marker. The rule_id JOIN
	// would race with seedNotificationRules' DELETE: that step
	// already wiped the demo: rules (cascading rule_id to NULL on
	// the deliveries side via ON DELETE SET NULL), so the join would
	// match zero rows and we'd accumulate deliveries each seed pass.
	if _, err := d.ExecContext(ctx, `
		DELETE FROM notification_deliveries
		 WHERE event_payload LIKE '%"demo":true%'`); err != nil {
		return fmt.Errorf("clear demo deliveries: %w", err)
	}

	rows, err := d.QueryContext(ctx,
		`SELECT id, channel_id, event_type FROM notification_rules WHERE name LIKE 'demo:%'`)
	if err != nil {
		return fmt.Errorf("query demo rules: %w", err)
	}
	type ruleRow struct {
		id, chID  int64
		eventType string
	}
	var demoRules []ruleRow
	for rows.Next() {
		var r ruleRow
		if err := rows.Scan(&r.id, &r.chID, &r.eventType); err != nil {
			rows.Close()
			return err
		}
		demoRules = append(demoRules, r)
	}
	rows.Close()
	if len(demoRules) == 0 {
		// no demo rules -> can't seed deliveries. Not fatal.
		return nil
	}

	statuses := []string{"sent", "sent", "sent", "sent", "sent", "sent", "sent", "sent", "sent",
		"failed", "rate_limited", "throttled"}
	const total = 250
	for i := 0; i < total; i++ {
		r := demoRules[demoRand.Intn(len(demoRules))]
		minutesAgo := demoRand.Intn(60 * 24 * 30)
		createdAt := now.Add(-time.Duration(minutesAgo) * time.Minute)
		status := statuses[demoRand.Intn(len(statuses))]
		var sentAt any
		errMsg := ""
		if status == "sent" {
			sentAt = createdAt.Add(time.Duration(demoRand.Intn(5000)) * time.Millisecond)
		} else {
			sentAt = nil
			switch status {
			case "failed":
				errMsg = "demo: synthetic 500 from upstream"
			case "rate_limited":
				errMsg = "demo: bucket exhausted"
			case "throttled":
				errMsg = "demo: rule throttle window active"
			}
		}
		payload := fmt.Sprintf(`{"demo":true,"type":%q,"severity":"warning","host_domain":"demo.example.com"}`,
			r.eventType)
		rendered := fmt.Sprintf("[demo] %s notification", r.eventType)
		attempts := 1
		if status == "failed" {
			attempts = demoRand.Intn(3) + 1
		}
		if _, err := d.ExecContext(ctx, `
			INSERT INTO notification_deliveries
			  (rule_id, channel_id, event_type, event_payload,
			   rendered_payload, status, error_message, attempts,
			   created_at, sent_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.id, r.chID, r.eventType, payload, rendered,
			status, errMsg, attempts, createdAt, sentAt); err != nil {
			return fmt.Errorf("seed delivery: %w", err)
		}
		c.Deliveries++
	}
	return nil
}

// --- 9. Backups (7 entries) ---

func seedBackups(ctx context.Context, d *sql.DB, c *seedCounters, now time.Time) error {
	if _, err := d.ExecContext(ctx,
		`DELETE FROM backups WHERE filename LIKE 'demo-%'`); err != nil {
		return fmt.Errorf("clear demo backups: %w", err)
	}
	specs := []struct {
		daysAgo int
		size    int64
		kind    string
		note    string
	}{
		{6, 12_582_912, "scheduled", ""},
		{5, 13_021_184, "scheduled", ""},
		{4, 13_516_800, "scheduled", "demo: post-host-edit"},
		{3, 13_959_168, "scheduled", ""},
		{2, 14_286_848, "manual", "demo: pre-v1.3.35 deploy snapshot"},
		{1, 14_581_760, "scheduled", ""},
		{0, 14_848_000, "scheduled", ""},
	}
	for _, s := range specs {
		ts := now.Add(-time.Duration(s.daysAgo*24) * time.Hour)
		filename := fmt.Sprintf("demo-argos-%s.tar.zst", ts.Format("20060102-150405"))
		// 64-hex-char fake sha256
		sha := fmt.Sprintf("%064x", demoRand.Int63())
		if _, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO backups
			  (filename, size_bytes, sha256, kind, note, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			filename, s.size, sha, s.kind, s.note, ts); err != nil {
			return fmt.Errorf("seed backup %q: %w", filename, err)
		}
		c.Backups++
	}
	return nil
}

// --- 10. Login attempts (40 entries: 30 success + 10 fail) ---

func seedLoginAttempts(ctx context.Context, d *sql.DB, c *seedCounters, now time.Time) error {
	// IN clause covers BOTH the success-username pool AND the
	// failure-username pool; otherwise re-seed leaves stale failure
	// rows (with usernames 'root' / 'guest') and the count drifts up.
	if _, err := d.ExecContext(ctx,
		`DELETE FROM login_attempts WHERE username IN ('admin','operator1','operator2','monitor','root','guest')`); err != nil {
		return fmt.Errorf("clear demo login attempts: %w", err)
	}
	users := []string{"admin", "operator1", "operator2", "monitor"}
	srcIPs := []string{"192.0.2.100", "192.0.2.101", "198.51.100.50", "203.0.113.20"}
	for i := 0; i < 30; i++ {
		ts := now.Add(-time.Duration(demoRand.Intn(60*24*14)) * time.Minute)
		if _, err := d.ExecContext(ctx, `
			INSERT INTO login_attempts (remote_ip, username, success, timestamp)
			VALUES (?, ?, 1, ?)`,
			srcIPs[demoRand.Intn(len(srcIPs))],
			users[demoRand.Intn(len(users))], ts); err != nil {
			return fmt.Errorf("seed login success: %w", err)
		}
		c.LoginAttempts++
	}
	failUsers := []string{"admin", "root", "operator1", "guest"}
	failIPs := []string{"192.0.2.250", "198.51.100.99", "203.0.113.99", "192.0.2.55"}
	for i := 0; i < 10; i++ {
		ts := now.Add(-time.Duration(demoRand.Intn(60*24*14)) * time.Minute)
		if _, err := d.ExecContext(ctx, `
			INSERT INTO login_attempts (remote_ip, username, success, timestamp)
			VALUES (?, ?, 0, ?)`,
			failIPs[demoRand.Intn(len(failIPs))],
			failUsers[demoRand.Intn(len(failUsers))], ts); err != nil {
			return fmt.Errorf("seed login failure: %w", err)
		}
		c.LoginAttempts++
	}
	return nil
}

// clearDemoDB removes every row tagged with the "demo:" marker. New
// surfaces (rules, deliveries, backups, login_attempts, country_jobs)
// are scoped via their own marker conventions.
func clearDemoDB(ctx context.Context, d *sql.DB, out io.Writer) error {
	type counters struct {
		hosts, whitelist, country, jobs, channels, rules, deliveries, activity, backups, login int
	}
	var c counters

	exec := func(q, label string) (int64, error) {
		res, err := d.ExecContext(ctx, q)
		if err != nil {
			return 0, fmt.Errorf("clear %s: %w", label, err)
		}
		n, _ := res.RowsAffected()
		return n, nil
	}

	if n, err := exec(`DELETE FROM log_entries WHERE message LIKE 'demo:%'`, "activity"); err != nil {
		return err
	} else {
		c.activity = int(n)
	}
	if n, err := exec(`DELETE FROM security_whitelist WHERE reason LIKE 'demo:%'`, "whitelist"); err != nil {
		return err
	} else {
		c.whitelist = int(n)
	}
	if n, err := exec(`DELETE FROM country_ban_expansions WHERE created_by = 'demo'`, "country"); err != nil {
		return err
	} else {
		c.country = int(n)
	}
	if n, err := exec(`DELETE FROM country_expansion_jobs WHERE created_by = 'demo'`, "country jobs"); err != nil {
		return err
	} else {
		c.jobs = int(n)
	}
	// Deliveries before rules (FK dependency).
	if n, err := exec(`DELETE FROM notification_deliveries
		WHERE rule_id IN (SELECT id FROM notification_rules WHERE name LIKE 'demo:%')`, "deliveries"); err != nil {
		return err
	} else {
		c.deliveries = int(n)
	}
	if n, err := exec(`DELETE FROM notification_rules WHERE name LIKE 'demo:%'`, "rules"); err != nil {
		return err
	} else {
		c.rules = int(n)
	}
	if n, err := exec(`DELETE FROM notification_channels WHERE name LIKE 'demo:%'`, "channels"); err != nil {
		return err
	} else {
		c.channels = int(n)
	}
	if n, err := exec(`DELETE FROM backups WHERE filename LIKE 'demo-%'`, "backups"); err != nil {
		return err
	} else {
		c.backups = int(n)
	}
	if n, err := exec(`DELETE FROM login_attempts WHERE username IN ('admin','operator1','operator2','monitor','root','guest')`, "login attempts"); err != nil {
		return err
	} else {
		c.login = int(n)
	}
	// Hosts must be deleted before target_groups (ON DELETE RESTRICT).
	if n, err := exec(`DELETE FROM hosts WHERE domain LIKE '%.example.com'
		OR domain LIKE '%.example.org' OR domain LIKE '%.example.net'`, "hosts"); err != nil {
		return err
	} else {
		c.hosts = int(n)
	}
	if _, err := exec(`DELETE FROM target_groups WHERE name LIKE 'demo:%'`, "target_groups"); err != nil {
		return err
	}

	fmt.Fprintf(out,
		"demo clear complete: hosts=%d whitelist=%d countries=%d (jobs=%d) "+
			"activity=%d channels=%d rules=%d deliveries=%d backups=%d "+
			"login_attempts=%d\n",
		c.hosts, c.whitelist, c.country, c.jobs, c.activity,
		c.channels, c.rules, c.deliveries, c.backups, c.login)
	fmt.Fprintln(out, "settings rows untouched (use docker volume rm for full reset)")
	return nil
}
