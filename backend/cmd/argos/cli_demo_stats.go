package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

// runDemoStats prints per-surface row counts for a demo DB. Read-
// only. Required env: ARGOS_DEMO_SEED=1, ARGOS_DB_PATH (or --db).
// Useful pre-screenshot to confirm the seed produced the expected
// densities; useful post-clear to confirm the clear cleaned what it
// should.
func runDemoStats(args []string) error {
	fs := flag.NewFlagSet("demo stats", flag.ContinueOnError)
	dbPath := fs.String("db", "", "path to argos.db (default: $ARGOS_DB_PATH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	opts := &demoOpts{DBPath: *dbPath, Stdout: os.Stdout}
	resolved, err := gateDemoStats(opts)
	if err != nil {
		return err
	}
	d, err := db.Open(resolved)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()
	return printDemoStats(context.Background(), d, opts.Stdout)
}

// printDemoStats writes the count summary. Each row reports counts
// for both demo-marked entries and the table total, so it's easy to
// spot a partially-cleared state (demo > 0 with a non-empty total)
// or a non-demo row that survived clear (demo = 0 but total > 0).
func printDemoStats(ctx context.Context, d *sql.DB, out io.Writer) error {
	queries := []struct {
		label string
		demoQ string
		totalQ string
	}{
		{"hosts (under example.{com,org,net})",
			`SELECT COUNT(*) FROM hosts WHERE domain LIKE '%.example.com' OR domain LIKE '%.example.org' OR domain LIKE '%.example.net'`,
			`SELECT COUNT(*) FROM hosts`},
		{"target_groups (demo: prefix)",
			`SELECT COUNT(*) FROM target_groups WHERE name LIKE 'demo:%'`,
			`SELECT COUNT(*) FROM target_groups`},
		{"security_whitelist (demo: reason)",
			`SELECT COUNT(*) FROM security_whitelist WHERE reason LIKE 'demo:%'`,
			`SELECT COUNT(*) FROM security_whitelist`},
		{"country_ban_expansions (created_by=demo)",
			`SELECT COUNT(*) FROM country_ban_expansions WHERE created_by = 'demo'`,
			`SELECT COUNT(*) FROM country_ban_expansions`},
		{"country_expansion_jobs (created_by=demo)",
			`SELECT COUNT(*) FROM country_expansion_jobs WHERE created_by = 'demo'`,
			`SELECT COUNT(*) FROM country_expansion_jobs`},
		{"log_entries (audit, demo: prefix)",
			`SELECT COUNT(*) FROM log_entries WHERE source = 'audit' AND message LIKE 'demo:%'`,
			`SELECT COUNT(*) FROM log_entries WHERE source = 'audit'`},
		{"notification_channels (demo: prefix)",
			`SELECT COUNT(*) FROM notification_channels WHERE name LIKE 'demo:%'`,
			`SELECT COUNT(*) FROM notification_channels`},
		{"notification_rules (demo: prefix)",
			`SELECT COUNT(*) FROM notification_rules WHERE name LIKE 'demo:%'`,
			`SELECT COUNT(*) FROM notification_rules`},
		{"notification_deliveries (joined to demo rules)",
			`SELECT COUNT(*) FROM notification_deliveries WHERE rule_id IN (SELECT id FROM notification_rules WHERE name LIKE 'demo:%')`,
			`SELECT COUNT(*) FROM notification_deliveries`},
		{"backups (filename demo-* prefix)",
			`SELECT COUNT(*) FROM backups WHERE filename LIKE 'demo-%'`,
			`SELECT COUNT(*) FROM backups`},
		{"login_attempts (demo users)",
			`SELECT COUNT(*) FROM login_attempts WHERE username IN ('admin','operator1','operator2','monitor','root','guest')`,
			`SELECT COUNT(*) FROM login_attempts`},
	}

	fmt.Fprintf(out, "%-50s  %8s  %8s\n", "surface", "demo", "total")
	fmt.Fprintf(out, "%s\n", "------------------------------------------------------------------------")

	for _, q := range queries {
		var demoCount, totalCount int
		if err := d.QueryRowContext(ctx, q.demoQ).Scan(&demoCount); err != nil {
			demoCount = -1
		}
		if err := d.QueryRowContext(ctx, q.totalQ).Scan(&totalCount); err != nil {
			totalCount = -1
		}
		fmt.Fprintf(out, "%-50s  %8d  %8d\n", q.label, demoCount, totalCount)
	}

	// Settings keys related to demo content.
	fmt.Fprintln(out, "")
	settingsKeys := []string{
		"appsec.tuning.inbound_threshold",
		"appsec.tuning.outbound_threshold",
		"appsec.disabled_scenarios",
		"appsec.scenarios.drift_state",
		"appsec.tuning.drift_state",
	}
	fmt.Fprintln(out, "settings (demo-relevant keys):")
	for _, k := range settingsKeys {
		var v string
		if err := d.QueryRowContext(ctx,
			`SELECT value FROM settings WHERE key = ?`, k).Scan(&v); err != nil {
			fmt.Fprintf(out, "  %-40s (unset)\n", k)
			continue
		}
		// Truncate long JSON blobs for legibility.
		display := v
		if len(display) > 80 {
			display = display[:77] + "..."
		}
		fmt.Fprintf(out, "  %-40s %s\n", k, display)
	}
	return nil
}

// runDemoSeedSelfBlock and runDemoClearSelfBlock toggle the
// SelfBlockBanner v2 surface. The banner reads the `panel.self_block`
// setting key (panel-side state) so the demo can show the banner
// without faking a real CrowdSec ban on the operator's IP.

func runDemoSeedSelfBlock(args []string) error {
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
	val := fmt.Sprintf(
		`{"active":true,"reason":"demo: synthetic self-block","banned_ip":"203.0.113.99","banned_at":%q}`,
		time.Now().UTC().Format(time.RFC3339))
	if _, err := d.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO settings (key, value) VALUES ('demo.self_block', ?)`, val); err != nil {
		return fmt.Errorf("seed self-block: %w", err)
	}
	fmt.Fprintln(opts.Stdout, "demo self-block: seeded settings.demo.self_block (key documents the banner state)")
	return nil
}

func runDemoClearSelfBlock(args []string) error {
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
	if _, err := d.ExecContext(context.Background(),
		`DELETE FROM settings WHERE key = 'demo.self_block'`); err != nil {
		return fmt.Errorf("clear self-block: %w", err)
	}
	fmt.Fprintln(opts.Stdout, "demo self-block: cleared")
	return nil
}

// quietUnusedOS keeps the os import alive for the gateDemo path
// (which reads ARGOS_DEMO_SEED via os.Getenv inside gate*).
var _ = os.Getenv
