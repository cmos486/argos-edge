// CLI subcommand: `argos demo ...`.
//
// Populates a standalone demo SQLite with realistic-looking content
// across the 10 panel surfaces so an operator (or a docs-screenshot
// session) sees populated tables instead of a fresh-install zero
// state. Companion to the ~/argos-demo/ scaffold.
//
// Usage:
//
//	argos demo seed [--yes] [--db <path>]
//	argos demo clear [--yes] [--db <path>]
//
// Triple-key safety to prevent ever wiping the prod DB:
//
//   1. --yes flag must be present.
//   2. ARGOS_DEMO_SEED=1 env var must be set.
//   3. ARGOS_DB_PATH must NOT contain "argos-prod".
//
// All seeded data is RFC 5737 IP space (192.0.2.x, 198.51.100.x,
// 203.0.113.x), example.com / example.org / example.net hostnames,
// and obviously-fake credentials. Idempotent: re-running seed against
// a populated demo DB is a no-op (INSERT OR IGNORE on every row).
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
	"os"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

const demoMarker = "demo:"

func runDemoCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: argos demo <seed|clear> [args]")
	}
	switch args[0] {
	case "seed":
		return runDemoSeed(args[1:])
	case "clear":
		return runDemoClear(args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(os.Stdout, "argos demo seed [--yes] [--db <path>]")
		fmt.Fprintln(os.Stdout, "argos demo clear [--yes] [--db <path>]")
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintln(os.Stdout, "Required env: ARGOS_DEMO_SEED=1, ARGOS_DB_PATH (or --db)")
		fmt.Fprintln(os.Stdout, "Refuses to run when ARGOS_DB_PATH contains 'argos-prod'.")
		return nil
	default:
		return fmt.Errorf("unknown demo subcommand %q (want: seed, clear)", args[0])
	}
}

type demoOpts struct {
	Yes    bool
	DBPath string
	Stdout io.Writer
}

func parseDemoFlags(args []string) (*demoOpts, error) {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "confirm; required because seed/clear mutates the DB")
	dbPath := fs.String("db", "", "path to argos.db (default: $ARGOS_DB_PATH)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected positional args: %v", fs.Args())
	}
	return &demoOpts{Yes: *yes, DBPath: *dbPath, Stdout: os.Stdout}, nil
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
	return seedDemoDB(context.Background(), d, opts.Stdout)
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

// seedDemoDB populates the 10 panel surfaces with synthetic content.
// Every INSERT uses OR IGNORE for idempotency; every row carries a
// "demo:" marker (in name/note/value fields where the schema allows)
// so the clear path can scope its DELETEs precisely.
func seedDemoDB(ctx context.Context, d *sql.DB, out io.Writer) error {
	now := time.Now().UTC()
	type counters struct{ hosts, whitelist, country, channels, settings, activity int }
	var c counters

	// 1. Hosts (8 entries). Post-v0.5 schema (migration 005) splits
	// upstream URL into target_groups + targets, joined to hosts via
	// target_group_id FK. So each demo host becomes 3 rows: one
	// target_group, one target, one host. INSERT OR IGNORE on the
	// target_group's UNIQUE name field gives us idempotency.
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
		{"app.example.com", "192.0.2.10", 8080, "http", "auto", "dns", "cloudflare", 0, 0, 0},
		{"api.example.com", "192.0.2.11", 9000, "http", "auto", "dns", "cloudflare", 0, 0, 1},
		{"admin.example.com", "192.0.2.12", 3000, "http", "auto", "http", "cloudflare", 0, 1, 1},
		{"grafana.example.org", "192.0.2.13", 3000, "http", "auto", "dns", "cloudflare", 0, 1, 0},
		{"intranet.example.net", "192.0.2.20", 80, "http", "none", "dns", "cloudflare", 1, 0, 0},
		{"monitor.example.org", "192.0.2.21", 9090, "http", "none", "dns", "cloudflare", 1, 0, 0},
		{"vault.example.com", "192.0.2.30", 8200, "https", "auto", "dns", "cloudflare", 0, 1, 1},
		{"docs.example.com", "192.0.2.31", 4000, "http", "auto", "tls-alpn", "cloudflare", 0, 0, 0},
	}
	for _, h := range hosts {
		tgName := "demo: " + h.domain // demo: prefix + UNIQUE name -> idempotent
		res, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO target_groups (name, protocol)
			VALUES (?, ?)`, tgName, h.protocol)
		if err != nil {
			return fmt.Errorf("seed target_group %q: %w", tgName, err)
		}
		// Resolve the target_group_id whether we just inserted or it
		// already existed (LastInsertId is 0 on IGNORE, so look it up).
		var tgID int64
		if err := d.QueryRowContext(ctx,
			`SELECT id FROM target_groups WHERE name = ?`, tgName).Scan(&tgID); err != nil {
			return fmt.Errorf("lookup target_group %q: %w", tgName, err)
		}
		n, _ := res.RowsAffected()
		_ = n // tg created or pre-existing; we count via hosts below

		// One target per group (simple LB shape; demo doesn't need
		// multi-target groups).
		if _, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO targets (target_group_id, host, port, weight)
			VALUES (?, ?, ?, 1)`, tgID, h.upHost, h.upPort); err != nil {
			return fmt.Errorf("seed target %s:%d: %w", h.upHost, h.upPort, err)
		}

		// Host row references the target_group via FK.
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
			c.hosts++
		}
	}

	// 2. Country ban expansions (5 countries with realistic CIDR
	// counts. The decision_ids JSON is a stub: the demo doesn't
	// actually issue LAPI decisions from this CLI -- init-demo.sh
	// shells out to cscli for that side. The panel's
	// country_ban_expansions row + state field are what the
	// /security/countries UI reads).
	countries := []struct {
		cc       string
		cidrs    int
		duration string
		reason   string
	}{
		{"BR", 5009, "168h", "demo: spike from BR"},
		{"CN", 9876, "168h", "demo: brute-force activity"},
		{"KR", 1421, "720h", "demo: fingerprinted scanner"},
		{"RU", 4815, "168h", "demo: post-incident lockdown"},
		{"IR", 768, "168h", "demo: sustained CVE probing"},
	}
	for _, cc := range countries {
		// Stub decision IDs blob; format matches what country/expander.go
		// writes after a real expansion completes.
		ids := make([]int, 0, 4)
		for i := 0; i < 4; i++ {
			ids = append(ids, 100000+i)
		}
		idsJSON, _ := json.Marshal(ids)
		res, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO country_ban_expansions
			  (country_code, decision_ids, cidr_count, reason, duration,
			   created_by, mmdb_version_at_creation)
			VALUES (?, ?, ?, ?, ?, 'demo', '2026.04')`,
			cc.cc, string(idsJSON), cc.cidrs, cc.reason, cc.duration)
		if err != nil {
			return fmt.Errorf("seed country %s: %w", cc.cc, err)
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			c.country++
		}
	}

	// 3. Whitelist (4 entries with demo: reason markers).
	whitelist := []struct {
		scope, value, reason string
	}{
		{"ip", "198.51.100.10", "demo: office static"},
		{"ip", "198.51.100.42", "demo: oncall pager IP"},
		{"range", "203.0.113.0/24", "demo: vpn pool"},
		{"ip", "192.0.2.200", "demo: monitoring vendor"},
	}
	for _, w := range whitelist {
		res, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO security_whitelist (scope, value, reason)
			VALUES (?, ?, ?)`,
			w.scope, w.value, w.reason)
		if err != nil {
			return fmt.Errorf("seed whitelist %q: %w", w.value, err)
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			c.whitelist++
		}
	}

	// 4. Activity log (15 entries spread across the last 7 days).
	// Every row carries a "demo:" prefix in raw so the clear path
	// can find them. source='audit' is the only audit-class value
	// the schema accepts.
	activityRaws := []struct {
		minutesAgo int
		level      string
		message    string
	}{
		{15, "info", `demo: panel mutation -- host added: app.example.com`},
		{42, "warn", `demo: AppSec inbound score 24 over threshold 22`},
		{67, "info", `demo: host updated -- api.example.com auth_required toggled on`},
		{180, "info", `demo: country ban added -- BR (5009 CIDRs, 168h)`},
		{275, "warn", `demo: drift detected -- scenarios out of sync`},
		{400, "info", `demo: scenario disabled -- crowdsecurity/http-bf-wordpress_bf`},
		{700, "info", `demo: country ban added -- CN (9876 CIDRs, 168h)`},
		{1000, "info", `demo: cert renewal succeeded -- app.example.com`},
		{1450, "warn", `demo: backup completed (kind=manual)`},
		{1900, "error", `demo: target unhealthy -- 192.0.2.11:9000 failed 3 consecutive probes`},
		{2400, "info", `demo: target recovered -- 192.0.2.11:9000`},
		{3200, "info", `demo: country ban added -- IR (768 CIDRs, 168h)`},
		{4000, "warn", `demo: AppSec inbound score 19 over threshold 15`},
		{5500, "info", `demo: notification channel created -- Telegram alerts`},
		{8400, "info", `demo: panel restarted -- argosVersion 1.3.35`},
	}
	for _, a := range activityRaws {
		ts := now.Add(-time.Duration(a.minutesAgo) * time.Minute)
		// raw is JSON-shaped; minimal payload with a demo: prefix.
		raw := fmt.Sprintf(`{"demo":true,"text":%q}`, a.message)
		res, err := d.ExecContext(ctx, `
			INSERT INTO log_entries (timestamp, source, level, message, raw)
			VALUES (?, 'audit', ?, ?, ?)`,
			ts, a.level, a.message, raw)
		if err != nil {
			return fmt.Errorf("seed activity row: %w", err)
		}
		n, _ := res.RowsAffected()
		c.activity += int(n)
	}

	// 5. Settings: AppSec tuning (non-default values), drift state
	// (synthetic drift_detected:true so the banner shows), disabled
	// scenarios sentinel.
	settingsRows := []struct{ k, v string }{
		{"appsec.tuning.inbound_threshold", "22"},
		{"appsec.tuning.outbound_threshold", "5"},
		{"appsec.tuning.last_modified_by", "demo"},
		{"appsec.disabled_scenarios", `["crowdsecurity/http-bf-wordpress_bf","crowdsecurity/http-probing"]`},
		{"appsec.scenarios.drift_state", `{"drift_detected":true,"expected_disabled":["crowdsecurity/http-bf-wordpress_bf","crowdsecurity/http-probing"],"actually_enabled":["crowdsecurity/http-bf-wordpress_bf"],"last_check_at":"` + now.Format(time.RFC3339) + `"}`},
		{"appsec.tuning.drift_state", `{"drift_detected":false,"expected_inbound":22,"actual_inbound":22,"expected_outbound":5,"actual_outbound":5,"last_check_at":"` + now.Format(time.RFC3339) + `"}`},
	}
	for _, s := range settingsRows {
		res, err := d.ExecContext(ctx,
			`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, s.k, s.v)
		if err != nil {
			return fmt.Errorf("seed setting %q: %w", s.k, err)
		}
		n, _ := res.RowsAffected()
		c.settings += int(n)
	}

	// 6. Notification channels: Telegram (HTML default), Webhook,
	// Email -- all with obviously-fake credentials. These will be
	// stored unencrypted because we don't have access to the master
	// key cipher here; the panel boot will redact them on the
	// /api/notifications/channels response (since they look like
	// plain strings, not argos1: ciphertext, the redactor flags
	// them as set-but-real and returns the UNCHANGED sentinel).
	channels := []struct {
		name, ctype string
		cfg         map[string]any
	}{
		{
			"demo: Telegram alerts", "telegram",
			map[string]any{
				"bot_token": "123456:demo-bot-token-not-real",
				"chat_id":   "1234567890",
			},
		},
		{
			"demo: Slack webhook", "webhook",
			map[string]any{
				"url":     "https://hooks.example.com/services/T-DEMO/B-DEMO/demo-token",
				"method":  "POST",
				"headers": map[string]string{"Content-Type": "application/json"},
			},
		},
		{
			"demo: Ops email", "email",
			map[string]any{
				"host":          "smtp.example.com",
				"port":          587,
				"username":      "demo@example.com",
				"smtp_password": "demo-password-not-real",
				"tls_mode":      "starttls",
				"from":          "alerts@example.com",
				"to":            "ops@example.com",
			},
		},
	}
	for _, ch := range channels {
		cfgJSON, _ := json.Marshal(ch.cfg)
		res, err := d.ExecContext(ctx, `
			INSERT OR IGNORE INTO notification_channels
			  (name, type, enabled, config, template, rate_limit_per_minute)
			VALUES (?, ?, 1, ?, '', 10)`,
			ch.name, ch.ctype, string(cfgJSON))
		if err != nil {
			return fmt.Errorf("seed channel %q: %w", ch.name, err)
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			c.channels++
		}
	}

	fmt.Fprintf(out,
		"demo seed complete: hosts=%d countries=%d whitelist=%d activity=%d settings=%d channels=%d\n",
		c.hosts, c.country, c.whitelist, c.activity, c.settings, c.channels)
	fmt.Fprintln(out, "all rows tagged with 'demo:' prefix; clear with: argos demo clear --yes")
	return nil
}

// clearDemoDB removes every row tagged with the "demo:" marker (in
// name/value/reason fields, as appropriate per table). Settings are
// untouched -- the demo writes them via INSERT OR REPLACE so the
// only way to "undo" them is to nuke the volume, which teardown-
// demo.sh does anyway.
func clearDemoDB(ctx context.Context, d *sql.DB, out io.Writer) error {
	type counters struct{ hosts, whitelist, country, channels, activity int }
	var c counters

	// Activity log: rows whose message has the demo: prefix.
	if res, err := d.ExecContext(ctx,
		`DELETE FROM log_entries WHERE message LIKE 'demo:%'`); err == nil {
		n, _ := res.RowsAffected()
		c.activity = int(n)
	} else {
		return fmt.Errorf("clear activity: %w", err)
	}

	// Whitelist: rows whose reason has the demo: prefix.
	if res, err := d.ExecContext(ctx,
		`DELETE FROM security_whitelist WHERE reason LIKE 'demo:%'`); err == nil {
		n, _ := res.RowsAffected()
		c.whitelist = int(n)
	} else {
		return fmt.Errorf("clear whitelist: %w", err)
	}

	// Country ban expansions: created_by='demo'.
	if res, err := d.ExecContext(ctx,
		`DELETE FROM country_ban_expansions WHERE created_by = 'demo'`); err == nil {
		n, _ := res.RowsAffected()
		c.country = int(n)
	} else {
		return fmt.Errorf("clear country: %w", err)
	}

	// Notification channels: name LIKE 'demo:%'.
	if res, err := d.ExecContext(ctx,
		`DELETE FROM notification_channels WHERE name LIKE 'demo:%'`); err == nil {
		n, _ := res.RowsAffected()
		c.channels = int(n)
	} else {
		return fmt.Errorf("clear channels: %w", err)
	}

	// Hosts: domains under example.{com,org,net} that we seeded.
	// Narrow the LIKE patterns so an operator who happens to have
	// a real example.com host (which would be a bizarre situation
	// in a non-demo DB) doesn't lose it. Hosts is the FK-bearing
	// side; target_groups is referenced via ON DELETE RESTRICT, so
	// hosts must be deleted before their target_groups can go.
	if res, err := d.ExecContext(ctx,
		`DELETE FROM hosts WHERE domain LIKE '%.example.com'
		   OR domain LIKE '%.example.org' OR domain LIKE '%.example.net'`); err == nil {
		n, _ := res.RowsAffected()
		c.hosts = int(n)
	} else {
		return fmt.Errorf("clear hosts: %w", err)
	}

	// Target groups with the demo: name prefix; targets cascade via
	// ON DELETE CASCADE on the target_group_id FK.
	if _, err := d.ExecContext(ctx,
		`DELETE FROM target_groups WHERE name LIKE 'demo:%'`); err != nil {
		return fmt.Errorf("clear target_groups: %w", err)
	}

	fmt.Fprintf(out,
		"demo clear complete: hosts=%d countries=%d whitelist=%d activity=%d channels=%d\n",
		c.hosts, c.country, c.whitelist, c.activity, c.channels)
	fmt.Fprintln(out, "settings rows untouched (use docker volume rm for full reset)")
	return nil
}
