// Package auth owns password hashing and the initial admin bootstrap.
// Session issuance and login handlers will be added alongside the API.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/bcrypt"
)

// Sentinel errors so callers can branch with errors.Is.
var (
	ErrNotFound     = errors.New("user not found")
	ErrUnauthorized = errors.New("unauthorized")
)

// BcryptCost is the work factor used for all password hashing. Keep >= 12
// per CLAUDE.md. Exported so tests can dial it down if ever needed.
const BcryptCost = 12

// User is the subset of the users row the rest of the panel cares about.
// password_hash never leaves this package.
type User struct {
	ID       int64
	Username string
}

// HashPassword returns a bcrypt hash of plain, rejecting passwords shorter
// than 8 characters. Bcrypt itself truncates at 72 bytes; callers upstream
// should enforce a reasonable upper bound too.
func HashPassword(plain string) (string, error) {
	if len(plain) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), BcryptCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash: %w", err)
	}
	return string(h), nil
}

// CreateUser inserts a new user with a freshly hashed password.
func CreateUser(ctx context.Context, d *sql.DB, username, password string) (User, error) {
	if username == "" {
		return User{}, fmt.Errorf("username required")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	res, err := d.ExecContext(ctx,
		`INSERT INTO users (username, password_hash) VALUES (?, ?)`,
		username, hash,
	)
	if err != nil {
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("last insert id: %w", err)
	}
	return User{ID: id, Username: username}, nil
}

// UserExists reports whether a row with the given username is present.
func UserExists(ctx context.Context, d *sql.DB, username string) (bool, error) {
	var n int
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE username = ?`, username,
	).Scan(&n); err != nil {
		return false, fmt.Errorf("query user: %w", err)
	}
	return n > 0, nil
}

// Authenticate verifies a username/password pair. Returns the user on
// success, ErrUnauthorized on any credential mismatch (including unknown
// username, to avoid leaking which half was wrong).
func Authenticate(ctx context.Context, d *sql.DB, username, password string) (User, error) {
	var u User
	var hash string
	err := d.QueryRowContext(ctx,
		`SELECT id, username, password_hash FROM users WHERE username = ?`, username,
	).Scan(&u.ID, &u.Username, &hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUnauthorized
		}
		return User{}, fmt.Errorf("query user: %w", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return User{}, ErrUnauthorized
	}
	if _, err := d.ExecContext(ctx,
		`UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?`, u.ID,
	); err != nil {
		return User{}, fmt.Errorf("update last_login: %w", err)
	}
	return u, nil
}

// Bootstrap creates the initial admin user if it does not already exist.
//
// Skips silently when username is empty (admin bootstrap disabled).
// Skips when the user already exists so restarts are idempotent.
// Errors when the user is missing but no password was supplied: this is the
// first boot and the operator needs to know they forgot a required env var
// rather than ending up with an unusable panel.
func Bootstrap(ctx context.Context, d *sql.DB, username, password string) error {
	if username == "" {
		return nil
	}
	exists, err := UserExists(ctx, d, username)
	if err != nil {
		return fmt.Errorf("check admin exists: %w", err)
	}
	if exists {
		slog.Debug("admin bootstrap skipped; user already exists", "user", username)
		return nil
	}
	if password == "" {
		return fmt.Errorf("ARGOS_INITIAL_ADMIN_PASSWORD required to create initial admin %q", username)
	}
	if _, err := CreateUser(ctx, d, username, password); err != nil {
		return fmt.Errorf("create initial admin: %w", err)
	}
	slog.Info("created initial admin user", "user", username)
	return nil
}
