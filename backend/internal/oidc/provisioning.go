package oidc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims is the subset of an OIDC ID token argos reads. The spec
// lists many more (phone, address, gender, birthdate...) but we
// only persist sub/email/email_verified/name/preferred_username.
// Extra unknown claims are silently dropped.
type Claims struct {
	Subject           string `json:"-"` // filled from idToken.Subject after Verify
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

// ProvisionedUser is the minimal shape the api layer hands to the
// session machinery after an OIDC login. Mirrors session.User
// deliberately -- the rest of the panel never needs to know whether
// a session was minted from a local bcrypt check or an IdP callback.
type ProvisionedUser struct {
	ID          int64
	Username    string
	Email       string
	DisplayName string
	Provider    string // "oidc" today; kept as string for forward-compat
}

// ErrNoAutoProvision means a first-time OIDC user hit argos but
// oidc.auto_provision is false. The operator has to create the row
// by hand (or flip the setting) before the user can log in.
var ErrNoAutoProvision = errors.New("oidc: user unknown and auto_provision disabled")

// ErrEmailUnverified is returned when oidc.require_email_verified is
// on and the id_token either missed the claim or sent email_verified
// false. Defence against IdPs (or mis-configured IdPs) that let a user
// claim an address they do not control -- a concern with
// public-signup providers, harmless with self-hosted IdPs that enforce
// verification themselves. Gated by the opt-in setting so v1.0
// upgrades do not lock out existing users.
var ErrEmailUnverified = errors.New("oidc: email_verified required but claim is false or missing")

// UpsertUserFromClaims looks for a row keyed on
// (external_provider='oidc', external_id=sub); creates one if not
// found and auto_provision is on; updates email + display_name when
// the IdP has fresher values. Returns the provisioned user.
//
// Username derivation: preferred_username claim first (cleanest when
// present -- Authentik/Keycloak always ship it), else local-part of
// email, else "oidc:<sub>" as a last-resort fallback so the NOT NULL
// + UNIQUE constraint on users.username can't fail. Username
// collisions between "local alice" and "oidc alice@..." are resolved
// by suffixing "-oidc" once; beyond that we bail with a clear error
// so the operator fixes the collision themselves (rare and ugly
// enough that silent auto-resolution would be more confusing).
func UpsertUserFromClaims(
	ctx context.Context, d *sql.DB, cfg Config, cl Claims,
) (ProvisionedUser, error) {
	if cl.Subject == "" {
		return ProvisionedUser{}, fmt.Errorf("oidc: claims missing subject")
	}
	email := strings.ToLower(strings.TrimSpace(cl.Email))
	if email == "" {
		return ProvisionedUser{}, fmt.Errorf("oidc: claims missing email")
	}
	// Policy gate: reject unverified emails when the operator opted in.
	// Evaluated BEFORE the allowlist so an attacker who controls an
	// IdP claim cannot probe the allowlist by picking verified-false
	// emails in approved domains.
	if cfg.RequireEmailVerified && !cl.EmailVerified {
		return ProvisionedUser{}, ErrEmailUnverified
	}
	if err := cfg.CheckAllowlist(email); err != nil {
		return ProvisionedUser{}, err
	}

	// Look up by (provider, sub) first. This is the authoritative
	// identity key -- a provider changing a user's email should NOT
	// orphan the row.
	var (
		id         int64
		username   string
		existEmail sql.NullString
		existName  sql.NullString
	)
	err := d.QueryRowContext(ctx, `
		SELECT id, username, email, display_name
		  FROM users
		 WHERE external_provider='oidc' AND external_id=?`, cl.Subject).
		Scan(&id, &username, &existEmail, &existName)

	switch {
	case err == nil:
		// Existing OIDC user. Update email + display_name when stale.
		newName := pickDisplayName(cl)
		if existEmail.String != email || existName.String != newName {
			_, uerr := d.ExecContext(ctx, `
				UPDATE users
				   SET email=?, display_name=?, last_login=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
				 WHERE id=?`, email, newName, id)
			if uerr != nil {
				return ProvisionedUser{}, fmt.Errorf("oidc: update user: %w", uerr)
			}
		} else {
			_, _ = d.ExecContext(ctx,
				`UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?`, id)
		}
		return ProvisionedUser{
			ID:          id,
			Username:    username,
			Email:       email,
			DisplayName: newName,
			Provider:    "oidc",
		}, nil
	case !errors.Is(err, sql.ErrNoRows):
		return ProvisionedUser{}, fmt.Errorf("oidc: lookup user: %w", err)
	}

	// User unknown. Need auto_provision to create.
	if !cfg.AutoProvision {
		return ProvisionedUser{}, ErrNoAutoProvision
	}

	candidate := usernameCandidate(cl, email)
	candidate, err = uniqueUsername(ctx, d, candidate)
	if err != nil {
		return ProvisionedUser{}, err
	}
	displayName := pickDisplayName(cl)

	res, err := d.ExecContext(ctx, `
		INSERT INTO users
			(username, password_hash, email, display_name,
			 external_provider, external_id, created_via,
			 created_at, updated_at, last_login)
		VALUES (?, NULL, ?, ?, 'oidc', ?, 'oidc',
		        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
		candidate, email, displayName, cl.Subject)
	if err != nil {
		return ProvisionedUser{}, fmt.Errorf("oidc: insert user: %w", err)
	}
	newID, err := res.LastInsertId()
	if err != nil {
		return ProvisionedUser{}, fmt.Errorf("oidc: last insert id: %w", err)
	}
	return ProvisionedUser{
		ID:          newID,
		Username:    candidate,
		Email:       email,
		DisplayName: displayName,
		Provider:    "oidc",
	}, nil
}

func pickDisplayName(cl Claims) string {
	if n := strings.TrimSpace(cl.Name); n != "" {
		return n
	}
	if n := strings.TrimSpace(cl.PreferredUsername); n != "" {
		return n
	}
	if at := strings.IndexByte(cl.Email, '@'); at > 0 {
		return cl.Email[:at]
	}
	return ""
}

func usernameCandidate(cl Claims, email string) string {
	if u := sanitizeUsername(cl.PreferredUsername); u != "" {
		return u
	}
	if at := strings.IndexByte(email, '@'); at > 0 {
		if u := sanitizeUsername(email[:at]); u != "" {
			return u
		}
	}
	// Last resort. "oidc:<sub>" collides on the unique index only if
	// the same sub already exists, in which case we wouldn't have
	// reached this branch.
	return "oidc:" + cl.Subject
}

// sanitizeUsername keeps [a-zA-Z0-9_.-], stripping whitespace and
// anything else. Return "" when the result is empty so callers can
// fall through to the next candidate source.
func sanitizeUsername(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var out strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_' || r == '.' || r == '-':
			out.WriteRune(r)
		}
	}
	return out.String()
}

// uniqueUsername finds a free username by appending "-oidc" once if
// the candidate is taken. Further conflicts yield an explicit error
// so the operator can rename manually; silent numeric suffixing
// would hide a real problem (two humans with the same email prefix
// is rare enough to be worth a loud failure).
func uniqueUsername(ctx context.Context, d *sql.DB, candidate string) (string, error) {
	exists, err := usernameTaken(ctx, d, candidate)
	if err != nil {
		return "", err
	}
	if !exists {
		return candidate, nil
	}
	alt := candidate + "-oidc"
	exists, err = usernameTaken(ctx, d, alt)
	if err != nil {
		return "", err
	}
	if !exists {
		return alt, nil
	}
	return "", fmt.Errorf("oidc: username %q (and %q) already taken; rename one manually", candidate, alt)
}

func usernameTaken(ctx context.Context, d *sql.DB, name string) (bool, error) {
	var n int
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE username=?`, name).Scan(&n); err != nil {
		return false, fmt.Errorf("check username collision: %w", err)
	}
	return n > 0, nil
}

// compile-time satisfier so `time` stays imported if a later refactor
// drops CURRENT_TIMESTAMP from the INSERT and starts using Go-side
// clocks. Cheap insurance.
var _ = time.Now
