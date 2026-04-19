package totp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a user ID does not exist. Used by both
// reads and the consume path so callers can branch with errors.Is.
var ErrNotFound = errors.New("user not found")

// UserState is a flattened view of the TOTP columns on users. The
// encrypted fields are returned as-is so the api layer can decide
// whether to decrypt (e.g. setup flow needs the secret, login flow
// needs only the enabled flag).
type UserState struct {
	UserID                     int64
	TOTPSecretEncrypted        string
	TOTPEnabled                bool
	TOTPEnabledAt              *time.Time
	TOTPRecoveryCodesEncrypted string
}

// GetUserTOTP loads the TOTP state for a user. ErrNotFound is returned
// when the user id does not exist. An existing user with no TOTP row
// yet comes back as a zero-valued UserState with Enabled=false and
// both encrypted fields empty.
func GetUserTOTP(ctx context.Context, d *sql.DB, userID int64) (UserState, error) {
	var (
		st        UserState
		secret    sql.NullString
		enabled   int
		enabledAt sql.NullTime
		recovery  sql.NullString
	)
	err := d.QueryRowContext(ctx, `
		SELECT id,
		       COALESCE(totp_secret_encrypted, ''),
		       totp_enabled,
		       totp_enabled_at,
		       COALESCE(totp_recovery_codes_encrypted, '')
		  FROM users
		 WHERE id = ?`, userID).
		Scan(&st.UserID, &secret, &enabled, &enabledAt, &recovery)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UserState{}, ErrNotFound
		}
		return UserState{}, fmt.Errorf("query user totp: %w", err)
	}
	st.TOTPSecretEncrypted = secret.String
	st.TOTPEnabled = enabled != 0
	if enabledAt.Valid {
		t := enabledAt.Time
		st.TOTPEnabledAt = &t
	}
	st.TOTPRecoveryCodesEncrypted = recovery.String
	return st, nil
}

// GetUserTOTPByUsername is GetUserTOTP keyed by username, for the login
// flow where we have the name before we have the id.
func GetUserTOTPByUsername(ctx context.Context, d *sql.DB, username string) (UserState, error) {
	var (
		st        UserState
		secret    sql.NullString
		enabled   int
		enabledAt sql.NullTime
		recovery  sql.NullString
	)
	err := d.QueryRowContext(ctx, `
		SELECT id,
		       COALESCE(totp_secret_encrypted, ''),
		       totp_enabled,
		       totp_enabled_at,
		       COALESCE(totp_recovery_codes_encrypted, '')
		  FROM users
		 WHERE username = ?`, username).
		Scan(&st.UserID, &secret, &enabled, &enabledAt, &recovery)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UserState{}, ErrNotFound
		}
		return UserState{}, fmt.Errorf("query user totp: %w", err)
	}
	st.TOTPSecretEncrypted = secret.String
	st.TOTPEnabled = enabled != 0
	if enabledAt.Valid {
		t := enabledAt.Time
		st.TOTPEnabledAt = &t
	}
	st.TOTPRecoveryCodesEncrypted = recovery.String
	return st, nil
}

// SetUserTOTP stores an encrypted secret for a user *without* flipping
// the enabled flag. Called during the setup flow; the user must then
// confirm with a fresh 6-digit code before we enable them.
// Recovery codes are stored in the same call so the encrypted blob is
// ready for the activate-time commit.
func SetUserTOTP(ctx context.Context, d *sql.DB, userID int64, encSecret, encRecovery string) error {
	res, err := d.ExecContext(ctx, `
		UPDATE users
		   SET totp_secret_encrypted = ?,
		       totp_recovery_codes_encrypted = ?,
		       totp_enabled = 0,
		       totp_enabled_at = NULL,
		       updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		encSecret, encRecovery, userID)
	if err != nil {
		return fmt.Errorf("set user totp: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ActivateTOTP flips the enabled flag and stamps totp_enabled_at.
// Called after the user confirms a first valid 6-digit code.
func ActivateTOTP(ctx context.Context, d *sql.DB, userID int64) error {
	res, err := d.ExecContext(ctx, `
		UPDATE users
		   SET totp_enabled = 1,
		       totp_enabled_at = CURRENT_TIMESTAMP,
		       updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("activate totp: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DisableTOTP clears the secret, recovery codes, enabled flag, and
// activation timestamp. Called from the UI "disable 2FA" handler and
// from the CLI break-glass (`argos disable-2fa --user X`).
func DisableTOTP(ctx context.Context, d *sql.DB, userID int64) error {
	res, err := d.ExecContext(ctx, `
		UPDATE users
		   SET totp_secret_encrypted = NULL,
		       totp_recovery_codes_encrypted = NULL,
		       totp_enabled = 0,
		       totp_enabled_at = NULL,
		       updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("disable totp: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveRecoveryCodes overwrites the encrypted recovery-code blob for a
// user. Used after ConsumeRecoveryCode to persist the shorter list.
func SaveRecoveryCodes(ctx context.Context, d *sql.DB, userID int64, encRecovery string) error {
	res, err := d.ExecContext(ctx, `
		UPDATE users
		   SET totp_recovery_codes_encrypted = ?,
		       updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`, encRecovery, userID)
	if err != nil {
		return fmt.Errorf("save recovery codes: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordTOTPAttempt inserts one row in totp_attempts. Call AFTER
// verification. success should be true only if the code (or recovery
// code) matched.
func RecordTOTPAttempt(ctx context.Context, d *sql.DB, userID int64, ip string, success bool) error {
	_, err := d.ExecContext(ctx, `
		INSERT INTO totp_attempts (user_id, ip, success)
		VALUES (?, ?, ?)`, userID, ip, success)
	if err != nil {
		return fmt.Errorf("record totp attempt: %w", err)
	}
	return nil
}

// RateLimitConfig pins the "5 fails in 15 min -> 30 min lockout"
// policy. Exported so main.go / tests can override if needed.
type RateLimitConfig struct {
	WindowFails int
	Window      time.Duration
	BanDuration time.Duration
}

// DefaultRateLimit is the policy the panel ships with.
func DefaultRateLimit() RateLimitConfig {
	return RateLimitConfig{
		WindowFails: 5,
		Window:      15 * time.Minute,
		BanDuration: 30 * time.Minute,
	}
}

// RateLimitStatus mirrors hardening.BanStatus. Kept local so this
// package stays dep-free of hardening.
type RateLimitStatus struct {
	Allowed    bool
	RetryAfter time.Duration
	Fails      int
}

// CheckTOTPRateLimit counts recent failures for (user_id, ip) within
// Window. When >= WindowFails, the caller must refuse to verify and
// return RetryAfter = BanDuration. Successful attempts reset nothing
// explicitly -- the window naturally rolls forward as time passes.
//
// Keyed by (user_id, ip) because a shared outbound NAT (office /
// home-lab) would otherwise let one user's typos lock another out.
func CheckTOTPRateLimit(ctx context.Context, d *sql.DB, userID int64, ip string, cfg RateLimitConfig) (RateLimitStatus, error) {
	if cfg.WindowFails <= 0 {
		cfg = DefaultRateLimit()
	}
	cutoff := time.Now().UTC().Add(-cfg.Window)
	var fails int
	err := d.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM totp_attempts
		 WHERE user_id = ? AND ip = ? AND success = 0 AND attempted_at >= ?`,
		userID, ip, cutoff).Scan(&fails)
	if err != nil {
		return RateLimitStatus{}, fmt.Errorf("count totp attempts: %w", err)
	}
	if fails >= cfg.WindowFails {
		return RateLimitStatus{Allowed: false, RetryAfter: cfg.BanDuration, Fails: fails}, nil
	}
	return RateLimitStatus{Allowed: true, Fails: fails}, nil
}

// PurgeTOTPAttempts drops totp_attempts rows older than 24h. Hooked
// into the same retention cron as login_attempts.
func PurgeTOTPAttempts(ctx context.Context, d *sql.DB) (int64, error) {
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	res, err := d.ExecContext(ctx,
		`DELETE FROM totp_attempts WHERE attempted_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purge totp attempts: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
