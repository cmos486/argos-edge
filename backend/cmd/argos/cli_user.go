// CLI subcommand: `argos user ...`.
//
// Handles the post-deploy lockout case where the operator forgot the
// admin password and the panel UI has no public reset endpoint. The
// commands run directly against the SQLite DB; SQLite WAL mode lets
// the running server keep serving while the CLI writes (and the
// server's auth handler picks up the new hash on the next login,
// since hashes are read per-request, not cached).
//
// Usage:
//
//	argos user list
//	argos user reset-password <username>                 (interactive)
//	argos user reset-password <username> --password <p>  (non-interactive,
//	                                                      for scripts;
//	                                                      leaks the
//	                                                      password to
//	                                                      shell history)
//
// All paths require ARGOS_DB_PATH (or --db <path>) to point at the
// argos.db file -- same env contract as the other CLI subcommands.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/cmos486/argos-edge/backend/internal/auth"
	"github.com/cmos486/argos-edge/backend/internal/db"
)

// runUserCommand dispatches `argos user <subcommand>`.
func runUserCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: argos user <list|reset-password> [args]")
	}
	switch args[0] {
	case "list":
		return runUserList(args[1:])
	case "reset-password":
		return runUserResetPassword(args[1:])
	case "-h", "--help", "help":
		fmt.Fprintln(os.Stdout, "argos user list")
		fmt.Fprintln(os.Stdout, "argos user reset-password <username> [--password <p>] [--db <path>]")
		return nil
	default:
		return fmt.Errorf("unknown user subcommand %q (want: list, reset-password)", args[0])
	}
}

// userResetPasswordOpts is the parsed shape of `user reset-password`.
// Extracted so the implementation is testable without going through
// flag.FlagSet (which reads os.Args by default).
type userResetPasswordOpts struct {
	Username  string
	Password  string // empty -> read from terminal
	DBPath    string // empty -> ARGOS_DB_PATH env
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	ReadPwFn  func(prompt string) (string, error) // injectable for tests
}

func runUserResetPassword(args []string) error {
	// Go's flag.Parse stops at the first non-flag arg, so we must
	// pull the username off the front before parsing flags. This
	// lets the operator write the natural form
	// `reset-password admin --password X` rather than forcing
	// flags-before-positionals.
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: argos user reset-password <username> [--password <p>] [--db <path>]")
	}
	username := args[0]
	rest := args[1:]

	fs := flag.NewFlagSet("user reset-password", flag.ContinueOnError)
	password := fs.String("password", "", "new password (non-interactive; leaks to shell history)")
	dbPath := fs.String("db", "", "path to argos.db (default: $ARGOS_DB_PATH)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected extra args after username: %v", fs.Args())
	}
	opts := userResetPasswordOpts{
		Username: username,
		Password: *password,
		DBPath:   *dbPath,
		Stdin:    os.Stdin,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
		ReadPwFn: readPasswordFromTerm,
	}
	return resetPasswordWithOpts(context.Background(), opts)
}

// resetPasswordWithOpts is the testable core. Open DB, look up user,
// read or accept password, hash, update, audit. Returns error for any
// step that should make the CLI exit non-zero.
func resetPasswordWithOpts(ctx context.Context, opts userResetPasswordOpts) error {
	if strings.TrimSpace(opts.Username) == "" {
		return fmt.Errorf("username is required")
	}
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

	var uid int64
	err = d.QueryRowContext(ctx,
		`SELECT id FROM users WHERE username = ?`, opts.Username).Scan(&uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("user %q not found (run `argos user list` to see existing usernames)", opts.Username)
		}
		return fmt.Errorf("lookup user: %w", err)
	}

	pw := opts.Password
	if pw == "" {
		// Interactive: read twice and confirm match. ReadPwFn must
		// suppress echo when the input is a TTY; the test
		// implementation just reads from a string buffer.
		first, err := opts.ReadPwFn("New password: ")
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		second, err := opts.ReadPwFn("Confirm new password: ")
		if err != nil {
			return fmt.Errorf("read password (confirm): %w", err)
		}
		if first != second {
			return fmt.Errorf("passwords do not match")
		}
		pw = first
	}

	hash, err := auth.HashPassword(pw)
	if err != nil {
		// auth.HashPassword enforces >=8 chars. Re-surface verbatim
		// rather than wrapping so the operator sees the actionable
		// message ("password must be at least 8 characters").
		return err
	}

	res, err := d.ExecContext(ctx,
		`UPDATE users SET password_hash = ? WHERE id = ?`, hash, uid)
	if err != nil {
		return fmt.Errorf("update password_hash: %w", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("expected 1 row updated, got %d", n)
	}

	// Audit row, mirroring runDisable2FACommand: source=cli so the
	// event is visible in the panel logs tab after the operator logs
	// back in. Failure here is non-fatal -- the password is already
	// changed.
	auditPayload := fmt.Sprintf(
		`{"user_id":0,"action":"password_reset","resource_type":"user","resource_id":%d,`+
			`"diff":{"username":%q,"source":"cli"}}`,
		uid, opts.Username,
	)
	if _, err := d.ExecContext(ctx, `
		INSERT INTO log_entries (timestamp, source, level, message, raw)
		VALUES (?, 'audit', 'warn', ?, ?)`,
		time.Now().UTC(),
		"password reset via CLI",
		auditPayload,
	); err != nil {
		fmt.Fprintf(opts.Stderr, "warning: audit log insert failed: %v\n", err)
	}

	fmt.Fprintf(opts.Stdout, "password reset for user %q (user_id=%d) at %s\n",
		opts.Username, uid, time.Now().UTC().Format(time.RFC3339))
	return nil
}

// readPasswordFromTerm wraps x/term.ReadPassword so we get echo
// suppression on a real TTY and a graceful fallback to plain reads
// when stdin isn't a terminal (test runners, piped input).
func readPasswordFromTerm(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Fallback: read a single line from stdin without echo
		// suppression. Used when scripts pipe the password in.
		var line string
		if _, err := fmt.Fscanln(os.Stdin, &line); err != nil {
			if err == io.EOF {
				return "", nil
			}
			return "", err
		}
		return line, nil
	}
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr) // newline after suppressed input
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

// runUserList dumps the users table to stdout in a fixed-width
// format. Includes id / username / totp_enabled / created_at so the
// operator can spot the right account when there's more than one.
func runUserList(args []string) error {
	fs := flag.NewFlagSet("user list", flag.ContinueOnError)
	dbPath := fs.String("db", "", "path to argos.db (default: $ARGOS_DB_PATH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	resolved := *dbPath
	if resolved == "" {
		resolved = os.Getenv("ARGOS_DB_PATH")
	}
	if resolved == "" {
		return fmt.Errorf("ARGOS_DB_PATH (or --db) required")
	}
	d, err := db.Open(resolved)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	rows, err := d.QueryContext(context.Background(), `
		SELECT id, username,
		       COALESCE(totp_enabled, 0) AS totp_enabled,
		       password_hash IS NOT NULL AS has_password,
		       created_at
		  FROM users
		 ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	fmt.Fprintf(os.Stdout, "%-4s  %-32s  %-4s  %-3s  %s\n", "ID", "USERNAME", "TOTP", "PWD", "CREATED")
	fmt.Fprintf(os.Stdout, "%s\n", strings.Repeat("-", 80))
	count := 0
	for rows.Next() {
		var (
			id          int64
			username    string
			totp        int
			hasPassword bool
			created     time.Time
		)
		if err := rows.Scan(&id, &username, &totp, &hasPassword, &created); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		totpStr := "off"
		if totp != 0 {
			totpStr = "on"
		}
		pwStr := "-"
		if hasPassword {
			pwStr = "yes"
		}
		fmt.Fprintf(os.Stdout, "%-4d  %-32s  %-4s  %-3s  %s\n",
			id, username, totpStr, pwStr, created.UTC().Format(time.RFC3339))
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows: %w", err)
	}
	if count == 0 {
		fmt.Fprintln(os.Stdout, "(no users)")
	}
	return nil
}
