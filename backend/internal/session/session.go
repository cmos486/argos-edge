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

// DefaultAbsoluteTTL is the upper bound on a session's lifetime; a
// session created now cannot be renewed past this regardless of how
// active the user is. The runtime value is read from settings and
// overrides this default.
const DefaultAbsoluteTTL = 7 * 24 * time.Hour

// DefaultIdleTTL is how long a session can sit idle before auto-
// expiring. Updated at every request (throttled).
const DefaultIdleTTL = 24 * time.Hour

// LastSeenUpdateThrottle is the minimum time between last_seen_at
// writes to avoid one write per request. A session that is fully
// idle for this duration then bursts will still renew its idle
// window promptly.
const LastSeenUpdateThrottle = 5 * time.Minute

const tokenBytes = 32

// Sentinel errors.
var (
	ErrNotFound = errors.New("session not found")
	ErrExpired  = errors.New("session expired")
	ErrIdle     = errors.New("session idle")
)

// Session is the stored row. Token is the opaque cookie value.
// ClientIP and XFFChain are populated for sessions created from
// v1.3.23 onward; pre-v1.3.23 rows have empty strings.
type Session struct {
	ID         int64
	UserID     int64
	Token      string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	ClientIP   string
	XFFChain   string
}

// User is the subset of the users row attached to a session lookup.
type User struct {
	ID       int64
	Username string
}

// CreateOpts carries the optional v1.3.23 IP-capture inputs to
// Create. Empty / zero values are valid (NULL goes into the
// columns). Existing callers that don't have IP context can keep
// using Create with no opts.
type CreateOpts struct {
	ClientIP string
	XFFChain string
}

// Create inserts a new session for userID with absoluteTTL from now.
// last_seen_at starts equal to created_at. opts captures the IP that
// the login request arrived from so SelfBlockBanner v2 can enumerate
// active-session IPs without a per-request lookup.
func Create(ctx context.Context, d *sql.DB, userID int64, absoluteTTL time.Duration, opts CreateOpts) (Session, error) {
	if absoluteTTL <= 0 {
		absoluteTTL = DefaultAbsoluteTTL
	}
	token, err := newToken()
	if err != nil {
		return Session{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(absoluteTTL)
	// nullableString turns "" into a NULL in the column so legacy
	// rows and "no IP captured" stay distinguishable from "empty
	// string IP".
	var ip, xff sql.NullString
	if opts.ClientIP != "" {
		ip = sql.NullString{String: opts.ClientIP, Valid: true}
	}
	if opts.XFFChain != "" {
		xff = sql.NullString{String: opts.XFFChain, Valid: true}
	}
	res, err := d.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token, created_at, last_seen_at, expires_at, client_ip, xff_chain)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, token, now, now, expires, ip, xff,
	)
	if err != nil {
		return Session{}, fmt.Errorf("insert session: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Session{}, fmt.Errorf("last insert id: %w", err)
	}
	return Session{
		ID:         id,
		UserID:     userID,
		Token:      token,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  expires,
		ClientIP:   opts.ClientIP,
		XFFChain:   opts.XFFChain,
	}, nil
}

// ListActiveIPsForUser returns the distinct client_ip values from
// active (non-expired) sessions for the given user. Used by
// SelfBlockBanner v2 to enumerate IPs to probe LAPI for.
//
// Sessions with NULL client_ip (legacy pre-v1.3.23 logins) are
// excluded; they degrade gracefully -- the banner just doesn't
// see those IPs.
func ListActiveIPsForUser(ctx context.Context, d *sql.DB, userID int64) ([]string, error) {
	rows, err := d.QueryContext(ctx, `
		SELECT DISTINCT client_ip FROM sessions
		WHERE user_id = ?
		  AND expires_at > ?
		  AND client_ip IS NOT NULL
		  AND client_ip != ''
	`, userID, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("query active ips: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("scan ip: %w", err)
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// Lookup resolves a token to its session + user + enforces both the
// absolute expiry and the idle timeout passed in.
//
// idleTTL <= 0 disables the idle check.
//
// Returns ErrNotFound for unknown tokens, ErrExpired when now >
// expires_at, and ErrIdle when now - last_seen_at > idleTTL.
func Lookup(ctx context.Context, d *sql.DB, token string, idleTTL time.Duration) (Session, User, error) {
	var s Session
	var u User
	var lastSeen sql.NullTime
	err := d.QueryRowContext(ctx,
		`SELECT s.id, s.user_id, s.token, s.created_at, s.last_seen_at, s.expires_at,
		        u.id, u.username
		 FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.token = ?`, token,
	).Scan(&s.ID, &s.UserID, &s.Token, &s.CreatedAt, &lastSeen, &s.ExpiresAt, &u.ID, &u.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, User{}, ErrNotFound
		}
		return Session{}, User{}, fmt.Errorf("query session: %w", err)
	}
	if lastSeen.Valid {
		s.LastSeenAt = lastSeen.Time
	} else {
		s.LastSeenAt = s.CreatedAt
	}
	now := time.Now().UTC()
	if now.After(s.ExpiresAt) {
		return Session{}, User{}, ErrExpired
	}
	if idleTTL > 0 && now.Sub(s.LastSeenAt) > idleTTL {
		return Session{}, User{}, ErrIdle
	}
	return s, u, nil
}

// Touch updates last_seen_at if the throttle window has passed since
// the last update. Returns the new last-seen value (either the fresh
// one or the previous one if throttled).
func Touch(ctx context.Context, d *sql.DB, s Session) (time.Time, error) {
	now := time.Now().UTC()
	if now.Sub(s.LastSeenAt) < LastSeenUpdateThrottle {
		return s.LastSeenAt, nil
	}
	if _, err := d.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, now, s.ID,
	); err != nil {
		return s.LastSeenAt, fmt.Errorf("touch session: %w", err)
	}
	return now, nil
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
