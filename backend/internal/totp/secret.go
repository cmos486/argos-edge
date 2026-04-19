// Package totp implements the per-user 2FA layer on top of RFC 6238.
// Secrets and recovery codes are encrypted at rest with the same
// AES-GCM master key the notifications package already uses; the
// package itself is dep-free of the rest of argos so it stays easy
// to unit-test.
//
// The public surface is intentionally narrow:
//   - GenerateSecret + FormatOtpauthURL produce what the QR wants.
//   - Verify checks a 6-digit code with the Google-Authenticator-style
//     defaults (SHA-1, 30s, 6 digits, +/-1 window).
//   - Recovery codes are generated in batches of 10 and stored as a
//     compact JSON blob (see recovery.go).
//   - Repo is the SQL layer.
package totp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"

	pqotp "github.com/pquerna/otp"
	pqtotp "github.com/pquerna/otp/totp"
)

// SecretBytes is the RFC-recommended 20-byte (160-bit) secret size.
// Google Authenticator, Aegis, and 1Password all accept this.
const SecretBytes = 20

// secretEncoder mirrors what pquerna/otp emits so our hand-rolled
// codepath and pquerna's Validate agree on the wire format.
var secretEncoder = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a fresh base32-encoded 160-bit secret without
// padding, uppercase. Callers are expected to encrypt this before
// persisting it.
func GenerateSecret() (string, error) {
	buf := make([]byte, SecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read rand: %w", err)
	}
	return secretEncoder.EncodeToString(buf), nil
}

// FormatOtpauthURL builds the otpauth://totp/... provisioning URI
// that authenticator apps understand. Issuer shows up as the account
// label in Aegis / GA; account is usually the username or email.
//
// We escape both components: a space in issuer becomes %20, an @ in
// account becomes %40, etc. The query-string issuer field is set too
// because some apps only read one or the other.
func FormatOtpauthURL(issuer, account, secret string) string {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	if issuer == "" {
		issuer = "argos-edge"
	}
	if account == "" {
		account = "user"
	}
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// pquernaOpts is the single source of truth for the TOTP configuration
// we use everywhere -- setup + verify + recovery must agree on skew,
// period, etc., or a code that works at provisioning time will fail
// thirty seconds later.
func pquernaOpts() pqtotp.ValidateOpts {
	return pqtotp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    pqotp.DigitsSix,
		Algorithm: pqotp.AlgorithmSHA1,
	}
}
