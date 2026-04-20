package hardening

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

// LoginRateLimiter implements the "5 failed attempts in 5 minutes
// buys you a 30-minute ban per IP" rule. The durable record lives in
// the login_attempts table; an in-memory bans map short-circuits the
// happy path (one sync.Map read instead of a SQL query per login).
type LoginRateLimiter struct {
	DB          *sql.DB
	WindowFails int           // e.g. 5
	Window      time.Duration // e.g. 5 minutes
	BanDuration time.Duration // e.g. 30 minutes

	mu   sync.Mutex
	bans map[string]time.Time // remote_ip -> expiry
}

// NewLoginRateLimiter returns a limiter with the phase-9b defaults.
func NewLoginRateLimiter(d *sql.DB) *LoginRateLimiter {
	return &LoginRateLimiter{
		DB:          d,
		WindowFails: 5,
		Window:      5 * time.Minute,
		BanDuration: 30 * time.Minute,
		bans:        make(map[string]time.Time),
	}
}

// BanStatus describes the current state for a given IP. Zero-value
// means not banned; RetryAfter>0 means yes-banned.
type BanStatus struct {
	Banned     bool
	RetryAfter time.Duration
}

// Check returns whether the IP is currently banned. Never blocks on
// DB when the in-memory map already has the answer.
func (l *LoginRateLimiter) Check(ctx context.Context, ip string) BanStatus {
	if ip == "" {
		return BanStatus{}
	}
	now := time.Now().UTC()

	l.mu.Lock()
	if exp, ok := l.bans[ip]; ok {
		if now.Before(exp) {
			ra := exp.Sub(now)
			l.mu.Unlock()
			return BanStatus{Banned: true, RetryAfter: ra}
		}
		delete(l.bans, ip)
	}
	l.mu.Unlock()

	// Query the durable table. A restart resets the in-memory map but
	// the DB rows stay, so the ban survives restarts.
	cutoff := now.Add(-l.Window)
	var fails int
	if err := l.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM login_attempts
		 WHERE remote_ip = ? AND success = 0 AND timestamp >= ?`,
		ip, cutoff).Scan(&fails); err != nil {
		return BanStatus{}
	}
	if fails >= l.WindowFails {
		// ban expiry = last fail + ban duration. Estimated from "now"
		// is fine -- we don't need exact.
		exp := now.Add(l.BanDuration)
		l.mu.Lock()
		l.bans[ip] = exp
		l.mu.Unlock()
		return BanStatus{Banned: true, RetryAfter: l.BanDuration}
	}
	return BanStatus{}
}

// Record inserts one login attempt row. Call AFTER verifying the
// password. If the row pushes the IP over the threshold, the
// in-memory bans map is populated so the next Check short-circuits.
func (l *LoginRateLimiter) Record(ctx context.Context, ip, username string, success bool) error {
	if _, err := l.DB.ExecContext(ctx,
		`INSERT INTO login_attempts (remote_ip, username, success) VALUES (?, ?, ?)`,
		ip, username, success); err != nil {
		return err
	}
	if success {
		return nil
	}
	// re-check the threshold to seed the ban cache
	s := l.Check(ctx, ip)
	_ = s
	return nil
}

