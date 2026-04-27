// CLI subcommand: `argos channel ...`.
//
// Diagnostic dump of notification_channels rows for operators who need
// to inspect channel state without going through the panel API (auth
// required) or having sqlite3 in the panel container (alpine slim
// images don't ship it).
//
// Usage:
//
//	argos channel inspect [--type telegram] [--db <path>]
//
// Prints id, name, type, rate_limit_per_minute, template (as a JSON-
// quoted string so newlines are visible), and config with secret keys
// redacted. Diagnostic flags annotate Telegram channels for the
// v1.3.34.2 legacy-default detection.
//
// Same env contract as the other CLI subcommands: ARGOS_DB_PATH or
// --db must point at the argos.db file.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// secretKeysByType lists the config keys that hold encrypted secrets;
// values are replaced with "***REDACTED***" in the inspect output. Same
// set as notifications.secretFields() (unexported there).
var secretKeysByType = map[string][]string{
	"webhook":  {"headers"},
	"email":    {"smtp_password"},
	"telegram": {"bot_token"},
}

// runChannelCommand dispatches `argos channel <subcommand>`.
func runChannelCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: argos channel <inspect> [args]")
	}
	switch args[0] {
	case "inspect":
		return runChannelInspect(args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(os.Stdout, "argos channel inspect [--type <webhook|email|telegram|browser_push>] [--db <path>]")
		return nil
	default:
		return fmt.Errorf("unknown channel subcommand %q (want: inspect)", args[0])
	}
}

type channelInspectOpts struct {
	TypeFilter string
	DBPath     string
	Stdout     io.Writer
}

func runChannelInspect(args []string) error {
	fs := flag.NewFlagSet("channel inspect", flag.ContinueOnError)
	typeFilter := fs.String("type", "", "filter by channel type (webhook|email|telegram|browser_push)")
	dbPath := fs.String("db", "", "path to argos.db (default: $ARGOS_DB_PATH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional args: %v", fs.Args())
	}
	opts := channelInspectOpts{
		TypeFilter: *typeFilter,
		DBPath:     *dbPath,
		Stdout:     os.Stdout,
	}
	return inspectChannelsWithOpts(context.Background(), opts)
}

func inspectChannelsWithOpts(ctx context.Context, opts channelInspectOpts) error {
	dbPath := opts.DBPath
	if dbPath == "" {
		dbPath = os.Getenv("ARGOS_DB_PATH")
	}
	if dbPath == "" {
		return fmt.Errorf("ARGOS_DB_PATH (or --db) required")
	}
	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	q := `SELECT id, name, type, enabled, template, config, rate_limit_per_minute
	      FROM notification_channels`
	var argsSQL []any
	if opts.TypeFilter != "" {
		q += ` WHERE type = ?`
		argsSQL = append(argsSQL, opts.TypeFilter)
	}
	q += ` ORDER BY id ASC`
	rows, err := d.QueryContext(ctx, q, argsSQL...)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	out := opts.Stdout
	count := 0
	for rows.Next() {
		var (
			id      int64
			name    string
			typ     string
			enabled bool
			tmpl    sql.NullString
			cfgStr  string
			rate    int
		)
		if err := rows.Scan(&id, &name, &typ, &enabled, &tmpl, &cfgStr, &rate); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		count++
		printChannel(out, id, name, typ, enabled, tmpl.String, cfgStr, rate)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if count == 0 {
		fmt.Fprintln(out, "(no channels found)")
	}
	return nil
}

func printChannel(out io.Writer, id int64, name, typ string, enabled bool, template, cfgRaw string, rate int) {
	fmt.Fprintf(out, "channel #%d  name=%q type=%s enabled=%t rate_limit_per_minute=%d\n",
		id, name, typ, enabled, rate)

	tmplQuoted := jsonQuote(template)
	fmt.Fprintf(out, "  template: %s\n", tmplQuoted)

	// Diagnostic annotation for Telegram channels: detect the
	// pre-v1.3.34.1 default literal so the operator can confirm
	// whether the v1.3.34.2 boot migration applied.
	if typ == "telegram" {
		switch template {
		case "":
			fmt.Fprintln(out, "  template-state: empty (will use DefaultTemplate fallback at render time)")
		case notifications.LegacyTelegramDefaultTemplate:
			fmt.Fprintln(out, "  template-state: LEGACY pre-v1.3.34.1 MarkdownV2 default (boot migration should clear this on next start)")
		default:
			fmt.Fprintln(out, "  template-state: customised (auto-migration leaves this untouched)")
		}
	}

	// Config dump with secrets redacted.
	cfg := map[string]any{}
	if cfgRaw != "" {
		_ = json.Unmarshal([]byte(cfgRaw), &cfg)
	}
	for _, k := range secretKeysByType[typ] {
		if _, present := cfg[k]; present {
			cfg[k] = "***REDACTED***"
		}
	}
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		fmt.Fprintln(out, "  config: (empty)")
	} else {
		fmt.Fprintln(out, "  config:")
		for _, k := range keys {
			fmt.Fprintf(out, "    %s = %s\n", k, formatVal(cfg[k]))
		}
	}

	// Diagnostic annotation for parse_mode.
	if typ == "telegram" {
		pm, _ := cfg["parse_mode"].(string)
		switch pm {
		case "":
			fmt.Fprintln(out, "  parse_mode-state: unset (sender falls back to HTML since v1.3.34.1)")
		case "MarkdownV2":
			fmt.Fprintln(out, "  parse_mode-state: PINNED to MarkdownV2 (boot migration removes the key)")
		case "HTML":
			fmt.Fprintln(out, "  parse_mode-state: pinned to HTML")
		default:
			fmt.Fprintf(out, "  parse_mode-state: pinned to %q (custom)\n", pm)
		}
	}
	fmt.Fprintln(out, "")
}

// jsonQuote returns a Go-quoted string with embedded \n / \t / quotes
// visible -- much easier to compare against an expected literal than
// raw multi-line output.
func jsonQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return strings.ReplaceAll(s, "\n", "\\n")
	}
	return string(b)
}

func formatVal(v any) string {
	if s, ok := v.(string); ok {
		// Quote strings; non-string values (numbers, bools) get %v.
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprintf("%v", v)
}
