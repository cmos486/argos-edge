package totp

import (
	"strings"
	"time"

	pqtotp "github.com/pquerna/otp/totp"
)

// Verify returns true when code is a valid 6-digit TOTP derived from
// secret at the current wall-clock time, allowing +/-1 period of skew.
// Whitespace in the input is tolerated because users like to paste
// codes copied with trailing newlines from authenticator apps.
//
// Verification at a specific moment is available via VerifyAt -- used
// by the unit tests against RFC 6238 vectors.
func Verify(secret, code string) bool {
	return VerifyAt(secret, code, time.Now().UTC())
}

// VerifyAt is the testable variant of Verify. Production code should
// call Verify; tests pin t to known moments to replay RFC 6238 vectors.
func VerifyAt(secret, code string, t time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	ok, err := pqtotp.ValidateCustom(code, secret, t, pquernaOpts())
	if err != nil {
		return false
	}
	return ok
}
