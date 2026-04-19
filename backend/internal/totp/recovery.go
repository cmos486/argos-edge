package totp

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"strings"
)

// RecoveryCodeCount is the number of one-shot codes we hand out on
// enrollment. Ten is the GitHub/Okta default: enough that a user is
// very unlikely to run out before noticing, few enough to fit on an
// index card.
const RecoveryCodeCount = 10

// recoveryCodeBytes is the raw-entropy size before base32 encoding.
// 5 bytes -> 8 base32 chars. We split that into two 4-char groups
// with a dash in the middle for legibility, e.g. "abcd-efgh".
const recoveryCodeBytes = 5

// recoveryEncoder mirrors the secret encoder: base32, no padding.
// We lowercase the output so users don't have to care about caps-lock
// when typing a recovery code into a challenge screen.
var recoveryEncoder = base32.StdEncoding.WithPadding(base32.NoPadding)

// recoveryBlob is the shape persisted (after AES-GCM encryption) in
// users.totp_recovery_codes_encrypted. Keeping the full list as JSON
// rather than one row per code means a single read/write cycle per
// consume, and the blob is trivially small (ten 9-char strings).
type recoveryBlob struct {
	Codes []string `json:"codes"`
}

// GenerateRecoveryCodes returns 10 fresh codes in "abcd-efgh" format,
// lowercased. Callers should persist these encrypted and hand the
// plaintext to the user exactly once.
func GenerateRecoveryCodes() ([]string, error) {
	out := make([]string, 0, RecoveryCodeCount)
	for i := 0; i < RecoveryCodeCount; i++ {
		buf := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("read rand: %w", err)
		}
		enc := strings.ToLower(recoveryEncoder.EncodeToString(buf))
		if len(enc) != 8 {
			return nil, fmt.Errorf("recovery code encoded to unexpected length %d", len(enc))
		}
		out = append(out, enc[:4]+"-"+enc[4:])
	}
	return out, nil
}

// MarshalRecoveryCodes produces the JSON blob we actually encrypt +
// persist. Separated from the AES-GCM call so the package stays
// dep-free of internal/crypto.
func MarshalRecoveryCodes(codes []string) (string, error) {
	b, err := json.Marshal(recoveryBlob{Codes: codes})
	if err != nil {
		return "", fmt.Errorf("marshal recovery codes: %w", err)
	}
	return string(b), nil
}

// UnmarshalRecoveryCodes is the inverse. Returns a nil slice if the
// input is empty -- i.e. a user who has never finished TOTP setup.
func UnmarshalRecoveryCodes(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var blob recoveryBlob
	if err := json.Unmarshal([]byte(raw), &blob); err != nil {
		return nil, fmt.Errorf("unmarshal recovery codes: %w", err)
	}
	return blob.Codes, nil
}

// normalizeRecoveryCode trims and lowercases, and strips any dashes
// the user might have typed. That way a code can be entered as
// "abcd-efgh", "ABCDEFGH", "abcd efgh", or pasted with trailing \n
// and still match. We then re-insert the dash at position 4 so the
// comparison is against the canonical format we generated.
func normalizeRecoveryCode(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s) != 8 {
		return s // caller compares and fails cleanly
	}
	return s[:4] + "-" + s[4:]
}

// ConsumeRecoveryCode checks whether the user-submitted code is in
// the stored list. Returns (remainingCodes, matched). When matched is
// true, remainingCodes has the consumed code removed; the caller is
// expected to persist the new list back. When matched is false,
// remainingCodes is unchanged.
//
// Matching is constant-time per entry so a side-channel cannot leak
// *which* code matched. We still iterate the whole slice on a hit so
// the timing doesn't reveal position either.
func ConsumeRecoveryCode(stored []string, input string) ([]string, bool) {
	norm := normalizeRecoveryCode(input)
	if norm == "" {
		return stored, false
	}
	hitIdx := -1
	for i, c := range stored {
		// Compare constant-time-ish: XOR each byte of fixed-length
		// canonical strings. If lengths differ, bail without leaking.
		if len(c) != len(norm) {
			continue
		}
		var diff byte
		for j := 0; j < len(c); j++ {
			diff |= c[j] ^ norm[j]
		}
		if diff == 0 && hitIdx == -1 {
			hitIdx = i
		}
	}
	if hitIdx < 0 {
		return stored, false
	}
	out := make([]string, 0, len(stored)-1)
	out = append(out, stored[:hitIdx]...)
	out = append(out, stored[hitIdx+1:]...)
	return out, true
}
