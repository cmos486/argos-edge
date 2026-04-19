package api

import (
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
			map[string]any{"username": u.Username, "remote_ip": clientIP(r)})
		writeError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	if err := totp.ActivateTOTP(r.Context(), h.DB, u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "activate totp")
		return
	}
	h.audit(r, "totp_enabled", "user", u.ID,
		map[string]any{"username": u.Username, "remote_ip": clientIP(r)})
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
			map[string]any{"username": ch.Username, "remote_ip": ip, "via": "totp"})
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
	raw, err := h.Cipher.Decrypt(state.TOTPRecoveryCodesEncrypted)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "decrypt recovery codes")
		return
	}
	codes, err := totp.UnmarshalRecoveryCodes(raw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "parse recovery codes")
		return
	}
	remaining, matched := totp.ConsumeRecoveryCode(codes, req.RecoveryCode)
	_ = totp.RecordTOTPAttempt(r.Context(), h.DB, ch.UserID, ip, matched)
	if !matched {
		writeError(w, http.StatusUnauthorized, "invalid recovery code")
		return
	}
	// Re-encrypt the shorter list and persist.
	newRaw, err := totp.MarshalRecoveryCodes(remaining)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "marshal remaining codes")
		return
	}
	newEnc, err := h.Cipher.Encrypt(newRaw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encrypt remaining codes")
		return
	}
	if err := totp.SaveRecoveryCodes(r.Context(), h.DB, ch.UserID, newEnc); err != nil {
		writeError(w, http.StatusInternalServerError, "save remaining codes")
		return
	}
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
				"username":  ch.Username,
				"remote_ip": ip,
				"remaining": len(remaining),
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
