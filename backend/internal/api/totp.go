package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/auth"
	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/session"
	"github.com/cmos486/argos-edge/backend/internal/totp"
)

// ---------- auth-required: setup / activate / disable / status ----------

// totpSetupResponse is what POST /api/auth/totp/setup returns. The
// secret is the base32 payload the user can type into an authenticator
// app by hand; otpauth_url is the QR payload; qr_png is the PNG
// base64-encoded so the UI can <img src="data:image/png;base64,..." />
// without a second request. recovery_codes are handed back ONCE -- the
// server never shows them again after activation.
type totpSetupResponse struct {
	Secret        string   `json:"secret"`
	OtpauthURL    string   `json:"otpauth_url"`
	QRPNG         string   `json:"qr_png_base64"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// TOTPSetup begins (or restarts) the enrollment flow for the current
// user. Generates a fresh secret + 10 recovery codes, encrypts both,
// and stores them with totp_enabled=0. The frontend shows the QR and
// recovery list, then the user confirms via /totp/activate.
//
// Re-running /setup before /activate is allowed (e.g. user lost track
// of the first QR): it overwrites the pending secret + recovery codes.
// Re-running /setup AFTER /activate is rejected; the user must first
// /disable to reset.
func (h *Handlers) TOTPSetup(w http.ResponseWriter, r *http.Request) {
	u, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.Cipher == nil {
		writeError(w, http.StatusServiceUnavailable, "master key not configured")
		return
	}

	st, err := totp.GetUserTOTP(r.Context(), h.DB, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load user totp state")
		return
	}
	if st.TOTPEnabled {
		writeError(w, http.StatusConflict, "2fa already enabled; disable first to reset")
		return
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate secret")
		return
	}
	codes, err := totp.GenerateRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate recovery codes")
		return
	}
	rawBlob, err := totp.MarshalRecoveryCodes(codes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "marshal recovery codes")
		return
	}
	encSecret, err := h.Cipher.Encrypt(secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encrypt secret")
		return
	}
	encRecovery, err := h.Cipher.Encrypt(rawBlob)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encrypt recovery codes")
		return
	}
	if err := totp.SetUserTOTP(r.Context(), h.DB, u.ID, encSecret, encRecovery); err != nil {
		writeError(w, http.StatusInternalServerError, "persist totp")
		return
	}
	// Issuer = "argos-edge", account = username.
	otpauthURL := totp.FormatOtpauthURL("argos-edge", u.Username, secret)
	png, err := totp.GeneratePNG(otpauthURL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate qr")
		return
	}
	writeJSON(w, http.StatusOK, totpSetupResponse{
		Secret:        secret,
		OtpauthURL:    otpauthURL,
		QRPNG:         base64.StdEncoding.EncodeToString(png),
		RecoveryCodes: codes,
	})
}

type totpActivateRequest struct {
	Code string `json:"code"`
}

// TOTPActivate confirms enrollment by validating a fresh 6-digit code
// against the pending secret. On success the totp_enabled flag flips
// and totp_enabled_at is stamped. Rejects if no pending secret exists.
func (h *Handlers) TOTPActivate(w http.ResponseWriter, r *http.Request) {
	u, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.Cipher == nil {
		writeError(w, http.StatusServiceUnavailable, "master key not configured")
		return
	}
	var req totpActivateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	st, err := totp.GetUserTOTP(r.Context(), h.DB, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load user totp state")
		return
	}
	if st.TOTPEnabled {
		writeError(w, http.StatusConflict, "2fa already enabled")
		return
	}
	if st.TOTPSecretEncrypted == "" {
		writeError(w, http.StatusBadRequest, "no pending setup; call /setup first")
		return
	}
	secret, err := h.Cipher.Decrypt(st.TOTPSecretEncrypted)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "decrypt secret")
		return
	}
	if !totp.Verify(secret, req.Code) {
		h.audit(r, "totp_activate_failed", "user", u.ID,
			map[string]any{
				"username":   u.Username,
				"remote_ip":  clientIP(r),
				"user_agent": userAgent(r),
			})
		writeError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	if err := totp.ActivateTOTP(r.Context(), h.DB, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "activate totp")
		return
	}
	h.audit(r, "totp_enabled", "user", u.ID,
		map[string]any{
			"username":   u.Username,
			"remote_ip":  clientIP(r),
			"user_agent": userAgent(r),
		})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type totpDisableRequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// TOTPDisable turns 2FA off for the current user. Requires both the
// password (so a temporarily-unattended session cannot disable it)
// AND a fresh code (so a stolen password alone is not enough).
// Recovery codes are accepted in place of the 6-digit code so a
// locked-out user who got in via /recovery can still disable.
func (h *Handlers) TOTPDisable(w http.ResponseWriter, r *http.Request) {
	u, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.Cipher == nil {
		writeError(w, http.StatusServiceUnavailable, "master key not configured")
		return
	}
	var req totpDisableRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Password == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "password and code required")
		return
	}
	// Re-verify password (cheap bcrypt check).
	if _, err := auth.Authenticate(r.Context(), h.DB, u.Username, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	st, err := totp.GetUserTOTP(r.Context(), h.DB, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load user totp state")
		return
	}
	if !st.TOTPEnabled {
		writeError(w, http.StatusConflict, "2fa not enabled")
		return
	}
	secret, err := h.Cipher.Decrypt(st.TOTPSecretEncrypted)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "decrypt secret")
		return
	}
	codeOK := totp.Verify(secret, req.Code)
	recoveryOK := false
	if !codeOK {
		// Fall back to recovery code.
		codes, _ := totp.UnmarshalRecoveryCodes(mustDecryptOrEmpty(h.Cipher, st.TOTPRecoveryCodesEncrypted))
		if _, ok := totp.ConsumeRecoveryCode(codes, req.Code); ok {
			recoveryOK = true
		}
	}
	if !codeOK && !recoveryOK {
		writeError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	if err := totp.DisableTOTP(r.Context(), h.DB, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "disable totp")
		return
	}
	h.audit(r, "totp_disabled", "user", u.ID, map[string]any{
		"username":     u.Username,
		"remote_ip":    clientIP(r),
		"user_agent":   userAgent(r),
		"via_recovery": recoveryOK,
		"source":       "user",
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type totpStatusResponse struct {
	Enabled        bool       `json:"enabled"`
	EnabledAt      *time.Time `json:"enabled_at,omitempty"`
	SetupPending   bool       `json:"setup_pending"`
	RecoveryRemain int        `json:"recovery_codes_remaining"`
}

// TOTPStatus tells the UI whether to show "Enable 2FA", "Finish setup",
// or "Disable 2FA" for this user. Safe to poll.
func (h *Handlers) TOTPStatus(w http.ResponseWriter, r *http.Request) {
	u, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	st, err := totp.GetUserTOTP(r.Context(), h.DB, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load user totp state")
		return
	}
	resp := totpStatusResponse{
		Enabled:      st.TOTPEnabled,
		EnabledAt:    st.TOTPEnabledAt,
		SetupPending: !st.TOTPEnabled && st.TOTPSecretEncrypted != "",
	}
	if st.TOTPEnabled && st.TOTPRecoveryCodesEncrypted != "" && h.Cipher != nil {
		if raw, derr := h.Cipher.Decrypt(st.TOTPRecoveryCodesEncrypted); derr == nil {
			if codes, uerr := totp.UnmarshalRecoveryCodes(raw); uerr == nil {
				resp.RecoveryRemain = len(codes)
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type totpRegenerateRequest struct {
	Password string `json:"password"`
}

type totpRegenerateResponse struct {
	Codes []string `json:"codes"`
}

// TOTPRegenerateRecovery POST /api/auth/totp/recovery/regenerate
//
// Mints a fresh batch of recovery codes, invalidating the previous
// set atomically. Gated by:
//  1. An authed session (the authed-group middleware).
//  2. TOTP already enabled for the user.
//  3. The user's current password re-submitted in the body
//     (sensitive-action pattern -- matches /totp/disable).
//  4. The user actually has a local password. OIDC-only rows have
//     NULL password_hash and no way to re-verify; they get a
//     distinct 400 so the UI can render "not available for SSO
//     accounts" rather than the generic "invalid credentials".
//
// Response carries the plaintext codes exactly once. The UI must
// surface them to the user with clear "save now" copy -- the server
// stores only the encrypted blob, there is no replay endpoint.
func (h *Handlers) TOTPRegenerateRecovery(w http.ResponseWriter, r *http.Request) {
	u, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.Cipher == nil {
		writeError(w, http.StatusServiceUnavailable, "master key not configured")
		return
	}
	var req totpRegenerateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password required")
		return
	}

	// Precondition: TOTP must already be on. Regenerating codes for a
	// user who has never enrolled is a UX dead-end (setup flow hands
	// them the initial set); 409 rather than 404 so callers can
	// differentiate "route missing" from "route OK, state wrong".
	st, err := totp.GetUserTOTP(r.Context(), h.DB, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load user totp state")
		return
	}
	if !st.TOTPEnabled {
		writeError(w, http.StatusConflict, "2fa not enabled")
		return
	}

	// Reject OIDC-only users explicitly. Without a local password
	// there is nothing to verify against, and quietly allowing
	// regenerate based on the session alone would weaken the
	// sensitive-action gate. The UI hides the button in that case;
	// this is a defensive 400 for direct-API callers.
	hasLocal, err := userHasLocalPassword(r.Context(), h.DB, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query user")
		return
	}
	if !hasLocal {
		writeError(w, http.StatusBadRequest, "feature not available for OIDC-only accounts")
		return
	}

	if _, err := auth.Authenticate(r.Context(), h.DB, u.Username, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Count the outgoing set BEFORE overwrite so the audit row shows
	// how many codes the user had left. Best-effort: a decrypt
	// failure here is recoverable (we still regenerate), we just
	// log an unknown count.
	wasRemaining := -1
	if st.TOTPRecoveryCodesEncrypted != "" {
		if raw, derr := h.Cipher.Decrypt(st.TOTPRecoveryCodesEncrypted); derr == nil {
			if codes, uerr := totp.UnmarshalRecoveryCodes(raw); uerr == nil {
				wasRemaining = len(codes)
			}
		}
	}

	codes, err := totp.GenerateRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate recovery codes")
		return
	}
	rawBlob, err := totp.MarshalRecoveryCodes(codes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "marshal recovery codes")
		return
	}
	enc, err := h.Cipher.Encrypt(rawBlob)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encrypt recovery codes")
		return
	}
	if err := totp.SaveRecoveryCodes(r.Context(), h.DB, u.ID, enc); err != nil {
		writeError(w, http.StatusInternalServerError, "save recovery codes")
		return
	}

	h.audit(r, "recovery_codes_regenerated", "user", u.ID, map[string]any{
		"username":      u.Username,
		"count":         len(codes),
		"was_remaining": wasRemaining,
		"remote_ip":     clientIP(r),
		"user_agent":    userAgent(r),
	})

	writeJSON(w, http.StatusOK, totpRegenerateResponse{Codes: codes})
}

// userHasLocalPassword reports whether users.password_hash is set
// (not NULL and not empty) for the given id. Local users can
// regenerate; OIDC-only rows cannot.
func userHasLocalPassword(ctx context.Context, d *sql.DB, id int64) (bool, error) {
	var hash sql.NullString
	if err := d.QueryRowContext(ctx,
		`SELECT password_hash FROM users WHERE id = ?`, id,
	).Scan(&hash); err != nil {
		return false, err
	}
	return hash.Valid && hash.String != "", nil
}

// ---------- no-auth: /verify and /recovery (pre-session TOTP step) ----------

type totpVerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
}

// TOTPVerify is the step between /api/auth/login (password OK, TOTP
// required) and a session cookie. The client sends back the
// challenge_id it received plus a fresh 6-digit code. On success we
// issue the session cookie exactly as /login would have done.
//
// Rate limit: shared with /recovery -- 5 failed attempts per
// (user_id, ip) in 15 min triggers a 30-min lockout.
func (h *Handlers) TOTPVerify(w http.ResponseWriter, r *http.Request) {
	if h.TOTPStore == nil || h.Cipher == nil {
		writeError(w, http.StatusServiceUnavailable, "totp not configured")
		return
	}
	var req totpVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.ChallengeID == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "challenge_id and code required")
		return
	}
	ch, err := h.TOTPStore.Get(req.ChallengeID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "challenge not found or expired")
		return
	}
	ip := clientIP(r)

	// Rate limit check BEFORE decrypt/verify.
	if st, err := totp.CheckTOTPRateLimit(r.Context(), h.DB, ch.UserID, ip, totp.DefaultRateLimit()); err == nil && !st.Allowed {
		secs := int(st.RetryAfter.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		h.audit(r, "totp_rate_limit_hit", "user", ch.UserID, map[string]any{
			"username":            ch.Username,
			"remote_ip":           ip,
			"user_agent":          userAgent(r),
			"retry_after_seconds": secs,
			"fails":               st.Fails,
		})
		writeError(w, http.StatusTooManyRequests,
			"too many failed attempts, try again later")
		return
	}

	state, err := totp.GetUserTOTP(r.Context(), h.DB, ch.UserID)
	if err != nil || !state.TOTPEnabled {
		writeError(w, http.StatusUnauthorized, "2fa not enabled for user")
		return
	}
	secret, err := h.Cipher.Decrypt(state.TOTPSecretEncrypted)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "decrypt secret")
		return
	}
	ok := totp.Verify(secret, req.Code)
	_ = totp.RecordTOTPAttempt(r.Context(), h.DB, ch.UserID, ip, ok)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	// Issue session. Same settings-derived TTL as /login.
	s, err := h.issueSession(r, ch.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	h.TOTPStore.Consume(req.ChallengeID)
	setSessionCookie(w, s, h.CookieSecure, h.cookieDomain(r.Context()))
	if h.Audit != nil {
		h.Audit.Record(r.Context(), ch.UserID, "totp_login_success", "user", ch.UserID,
			map[string]any{
				"username":   ch.Username,
				"remote_ip":  ip,
				"user_agent": userAgent(r),
				"via":        "totp",
			})
	}
	writeJSON(w, http.StatusOK, userResponse{Username: ch.Username})
}

type totpRecoveryRequest struct {
	ChallengeID  string `json:"challenge_id"`
	RecoveryCode string `json:"recovery_code"`
}

type totpRecoveryResponse struct {
	Username       string `json:"username"`
	RecoveryRemain int    `json:"recovery_codes_remaining"`
}

// TOTPRecovery consumes one recovery code to issue a session. Shares
// the rate limit counter with /verify so a brute-forcer does not get
// a free 5-attempt budget per endpoint.
func (h *Handlers) TOTPRecovery(w http.ResponseWriter, r *http.Request) {
	if h.TOTPStore == nil || h.Cipher == nil {
		writeError(w, http.StatusServiceUnavailable, "totp not configured")
		return
	}
	var req totpRecoveryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.ChallengeID == "" || req.RecoveryCode == "" {
		writeError(w, http.StatusBadRequest, "challenge_id and recovery_code required")
		return
	}
	ch, err := h.TOTPStore.Get(req.ChallengeID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "challenge not found or expired")
		return
	}
	ip := clientIP(r)

	if st, rlErr := totp.CheckTOTPRateLimit(r.Context(), h.DB, ch.UserID, ip, totp.DefaultRateLimit()); rlErr == nil && !st.Allowed {
		secs := int(st.RetryAfter.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		h.audit(r, "totp_rate_limit_hit", "user", ch.UserID, map[string]any{
			"username":            ch.Username,
			"remote_ip":           ip,
			"user_agent":          userAgent(r),
			"retry_after_seconds": secs,
			"fails":               st.Fails,
		})
		writeError(w, http.StatusTooManyRequests,
			"too many failed attempts, try again later")
		return
	}

	// Compare-and-swap loop. The blob is read + decrypted + one code
	// removed + re-encrypted + written back. Without CAS, two
	// concurrent submissions of the same code both pass the consume
	// step and both write a "one fewer" blob, effectively consuming
	// the code once but issuing two sessions. The SaveRecoveryCodesCAS
	// predicate rejects whichever write arrives second; that request
	// loops back and re-reads the post-commit blob, at which point the
	// code is gone and it fails as "invalid" -- no extra session.
	//
	// We cap retries at 3: in practice one retry is always enough
	// (SQLite serialises the writers), but a pathological burst hits
	// the limit and returns 503 rather than spinning forever.
	const maxRecoveryRetries = 3
	var (
		matched   bool
		remaining []string
	)
	for attempt := 0; attempt < maxRecoveryRetries; attempt++ {
		state, gerr := totp.GetUserTOTP(r.Context(), h.DB, ch.UserID)
		if gerr != nil || !state.TOTPEnabled {
			writeError(w, http.StatusUnauthorized, "2fa not enabled for user")
			return
		}
		prevEnc := state.TOTPRecoveryCodesEncrypted
		raw, derr := h.Cipher.Decrypt(prevEnc)
		if derr != nil {
			writeError(w, http.StatusInternalServerError, "decrypt recovery codes")
			return
		}
		codes, uerr := totp.UnmarshalRecoveryCodes(raw)
		if uerr != nil {
			writeError(w, http.StatusInternalServerError, "parse recovery codes")
			return
		}
		var localRemaining []string
		localRemaining, matched = totp.ConsumeRecoveryCode(codes, req.RecoveryCode)
		if !matched {
			// Record only terminal failures so retries don't inflate
			// the rate-limit counter -- a CAS miss is not the user's
			// bad input.
			_ = totp.RecordTOTPAttempt(r.Context(), h.DB, ch.UserID, ip, false)
			writeError(w, http.StatusUnauthorized, "invalid recovery code")
			return
		}
		newRaw, merr := totp.MarshalRecoveryCodes(localRemaining)
		if merr != nil {
			writeError(w, http.StatusInternalServerError, "marshal remaining codes")
			return
		}
		newEnc, eerr := h.Cipher.Encrypt(newRaw)
		if eerr != nil {
			writeError(w, http.StatusInternalServerError, "encrypt remaining codes")
			return
		}
		committed, serr := totp.SaveRecoveryCodesCAS(r.Context(), h.DB, ch.UserID, prevEnc, newEnc)
		if serr != nil {
			writeError(w, http.StatusInternalServerError, "save remaining codes")
			return
		}
		if committed {
			remaining = localRemaining
			break
		}
		// CAS miss: another request won the race. Loop back, re-read,
		// and either find the code still present (consume a different
		// one) or find it gone (return "invalid").
		if attempt == maxRecoveryRetries-1 {
			writeError(w, http.StatusServiceUnavailable,
				"concurrent modification, please retry")
			return
		}
	}
	_ = totp.RecordTOTPAttempt(r.Context(), h.DB, ch.UserID, ip, true)
	s, err := h.issueSession(r, ch.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	h.TOTPStore.Consume(req.ChallengeID)
	setSessionCookie(w, s, h.CookieSecure, h.cookieDomain(r.Context()))
	if h.Audit != nil {
		h.Audit.Record(r.Context(), ch.UserID, "totp_recovery_used", "user", ch.UserID,
			map[string]any{
				"username":   ch.Username,
				"remote_ip":  ip,
				"user_agent": userAgent(r),
				"remaining":  len(remaining),
			})
	}
	writeJSON(w, http.StatusOK, totpRecoveryResponse{
		Username:       ch.Username,
		RecoveryRemain: len(remaining),
	})
}

// ---------- helpers ----------

// issueSession is the shared "create DB session row, respect idle
// timeout settings" path used by both Login (password-only) and the
// TOTP verify/recovery endpoints. Returning a session without setting
// the cookie lets the caller layer on audit events before wearing the
// cookie.
func (h *Handlers) issueSession(r *http.Request, userID int64) (session.Session, error) {
	absTTL := session.DefaultAbsoluteTTL
	if h.Timeouts != nil {
		abs, _ := h.Timeouts.Get(r.Context())
		if abs > 0 {
			absTTL = abs
		}
	}
	return session.Create(r.Context(), h.DB, userID, absTTL)
}

// mustDecryptOrEmpty is a defensive helper for the recovery-code
// fallback in /disable. A corrupted blob should not block the user
// from turning off 2FA (they can always CLI-break-glass), so on
// decrypt error we just return "" -> ConsumeRecoveryCode returns no
// match -> caller falls through to "invalid code" without panicking.
func mustDecryptOrEmpty(c *crypto.Cipher, enc string) string {
	if enc == "" || c == nil {
		return ""
	}
	raw, err := c.Decrypt(enc)
	if err != nil {
		return ""
	}
	return raw
}
