package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/cmos486/argos-edge/backend/internal/auth"
	"github.com/cmos486/argos-edge/backend/internal/session"
	"github.com/cmos486/argos-edge/backend/internal/totp"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userResponse struct {
	Username string `json:"username"`
}

// loginTOTPPending is the shape returned when a user has 2FA enabled:
// the password was correct but we withhold the session until the user
// completes /api/auth/totp/verify (or /recovery). The client uses
// challenge_id to correlate the second step with this login.
type loginTOTPPending struct {
	RequiresTOTP bool   `json:"requires_totp"`
	ChallengeID  string `json:"challenge_id"`
}

// Login verifies credentials and issues a session cookie. Phase 9b
// rate-limits failed attempts: 5 fails in 5 minutes from the same IP
// buys a 30-minute ban, enforced before bcrypt.Compare runs.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password required")
		return
	}

	ip := clientIP(r)

	// Rate-limit guard.
	if h.LoginRL != nil {
		st := h.LoginRL.Check(r.Context(), ip)
		if st.Banned {
			secs := int(st.RetryAfter.Seconds())
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			if h.Audit != nil {
				h.Audit.Record(r.Context(), 0, "rate_limited_login", "user", 0,
					map[string]any{"remote_ip": ip, "retry_after_seconds": secs})
			}
			writeError(w, http.StatusTooManyRequests,
				fmt.Sprintf("too many failed attempts, try again in %d minutes", secs/60+1))
			return
		}
	}

	u, err := auth.Authenticate(r.Context(), h.DB, req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthorized) {
			if h.LoginRL != nil {
				_ = h.LoginRL.Record(r.Context(), ip, req.Username, false)
			}
			if h.Audit != nil {
				h.Audit.Record(r.Context(), 0, "failed_login", "user", 0,
					map[string]any{"username": req.Username, "remote_ip": ip})
			}
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}

	// Phase 2FA: if the user has TOTP enabled, we do NOT issue the
	// session yet. Register a pending challenge and ask the client to
	// complete /api/auth/totp/verify (or /recovery) within the TTL.
	// The password was correct -- we credit the rate-limit table as a
	// success so retry budgets are not burned by a well-behaved client.
	if h.TOTPStore != nil {
		st, terr := totp.GetUserTOTP(r.Context(), h.DB, u.ID)
		if terr == nil && st.TOTPEnabled {
			ch, cerr := h.TOTPStore.Create(u.ID, u.Username, ip)
			if cerr != nil {
				writeError(w, http.StatusInternalServerError, "could not start 2fa challenge")
				return
			}
			if h.LoginRL != nil {
				_ = h.LoginRL.Record(r.Context(), ip, u.Username, true)
			}
			if h.Audit != nil {
				h.Audit.Record(r.Context(), u.ID, "login_totp_challenge", "user", u.ID,
					map[string]any{"username": u.Username, "remote_ip": ip})
			}
			writeJSON(w, http.StatusOK, loginTOTPPending{
				RequiresTOTP: true,
				ChallengeID:  ch.ID,
			})
			return
		}
	}

	// Determine absolute TTL from current timeout settings.
	var absTTL = session.DefaultAbsoluteTTL
	if h.Timeouts != nil {
		abs, _ := h.Timeouts.Get(r.Context())
		if abs > 0 {
			absTTL = abs
		}
	}
	s, err := session.Create(r.Context(), h.DB, u.ID, absTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	if h.LoginRL != nil {
		_ = h.LoginRL.Record(r.Context(), ip, u.Username, true)
	}
	setSessionCookie(w, s, h.CookieSecure, h.cookieDomain(r.Context()))
	if h.Audit != nil {
		h.Audit.Record(r.Context(), u.ID, "login", "user", u.ID,
			map[string]any{"username": u.Username, "remote_ip": ip})
	}
	writeJSON(w, http.StatusOK, userResponse{Username: u.Username})
}

// clientIP returns the observed client IP, preferring the X-Real-IP
// set by chi's RealIP middleware (which trusts X-Forwarded-For /
// X-Real-IP headers from the immediate proxy). Falls back to
// RemoteAddr without the port.
func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	addr := r.RemoteAddr
	if i := len(addr) - 1; i >= 0 {
		// strip :port
		for j := i; j >= 0; j-- {
			if addr[j] == ':' {
				return addr[:j]
			}
		}
	}
	return addr
}

// Logout deletes the current session and clears the cookie. Idempotent:
// calling it without a valid session still returns 204.
//
// Also evicts the ForwardAuth cache entry for this token so any
// protected host the user was accessing bounces on the very next
// request, not 30s later when the TTL rolls. Without this the user
// sees a confusing "signed out here but still admin over there"
// window.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		_ = session.Delete(r.Context(), h.DB, c.Value)
		if h.ForwardAuthCache != nil {
			h.ForwardAuthCache.Invalidate(c.Value)
		}
	}
	if u, ok := userFromContext(r.Context()); ok {
		h.audit(r, "logout", "user", u.ID, map[string]any{"username": u.Username})
	}
	clearSessionCookie(w, h.CookieSecure, h.cookieDomain(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}

// Me returns the username of the currently authenticated user. Relies on
// Authenticate middleware having already run.
func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	u, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, userResponse{Username: u.Username})
}
