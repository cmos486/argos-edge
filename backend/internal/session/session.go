// Package session manages server-side sessions backed by SQLite.
// Tokens are 32 bytes of crypto/rand, hex-encoded, stored in the sessions
// table. The cookie only holds the opaque token; all state lives in SQLite
// so revocation is immediate.
package session

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// TTL is how long a freshly issued session is valid. Phase 0 keeps this
// simple; rolling refresh and idle timeouts can come later.
const TTL = 24 * time.Hour

const tokenBytes = 32

// Sentinel errors.
var (
	ErrNotFound = errors.New("session not found")
	ErrExpired  = errors.New("session expired")
)

// Session is the stored row. Token is the opaque cookie value.
type Session struct {
	ID        int64
	UserID    int64
	Token     string
	ExpiresAt time.Time
}

// User is the subset of the users row attached to a session lookup.
type User struct {
	ID       int64
	Username string
}

// Create inserts a new session for userID with TTL from now.
func Create(ctx context.Context, d *sql.DB, userID int64) (Session, error) {
	token, err := newToken()
	if err != nil {
		return Session{}, err
	}
	expires := time.Now().Add(TTL).UTC()
	res, err := d.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)`,
		userID, token, expires,
	)
	if err != nil {
		return Session{}, fmt.Errorf("insert session: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Session{}, fmt.Errorf("last insert id: %w", err)
	}
	return Session{ID: id, UserID: userID, Token: token, ExpiresAt: expires}, nil
}

// Lookup resolves a token to its session + user. Returns ErrNotFound if the
// token is unknown and ErrExpired if the row exists but has lapsed.
func Lookup(ctx context.Context, d *sql.DB, token string) (Session, User, error) {
	var s Session
	var u User
	err := d.QueryRowContext(ctx,
		`SELECT s.id, s.user_id, s.token, s.expires_at, u.id, u.username
		 FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.token = ?`, token,
	).Scan(&s.ID, &s.UserID, &s.Token, &s.ExpiresAt, &u.ID, &u.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, User{}, ErrNotFound
		}
		return Session{}, User{}, fmt.Errorf("query session: %w", err)
	}
	if time.Now().After(s.ExpiresAt) {
		return Session{}, User{}, ErrExpired
	}
	return s, u, nil
}

// Delete removes a session by token. It is not an error if the token is
// already gone; logout should be idempotent.
func Delete(ctx context.Context, d *sql.DB, token string) error {
	if _, err := d.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(b), nil
}
