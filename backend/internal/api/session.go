package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/session"
)

// CookieName is the name of the session cookie. Kept short; the same value
// is read by the frontend indirectly (it never accesses the cookie, only
// relies on the browser sending it).
const CookieName = "argos_session"

// cookieDomain reads the oidc.cookie_parent_domain setting. Empty
// string (default) = cookie stays bound to the panel host. Leading
// dot is optional in modern browsers but we normalise to "strip it"
// so the Set-Cookie header renders the cleanest possible form.
// Called once per cookie write -- O(1) SELECT on a 24-row table.
func (h *Handlers) cookieDomain(ctx context.Context) string {
	if h == nil || h.DB == nil {
		return ""
	}
	d := db.GetSettingValue(ctx, h.DB, "oidc.cookie_parent_domain", "")
	d = strings.TrimSpace(d)
	for len(d) > 0 && d[0] == '.' {
		d = d[1:]
	}
	return d
}

type ctxKey int

const (
	ctxUser ctxKey = iota // session.User
)

// setSessionCookie writes the argos_session cookie. When domain is
// non-empty it becomes a parent-domain cookie so subdomains of the
// panel (protected by ForwardAuth in Phase C/D) share the same
// session. A parent-domain cookie also forces SameSite=Lax rather
// than Strict -- Strict would drop the cookie on cross-subdomain
// redirects (panel -> protected host) and break the very flow we
// are trying to enable.
func setSessionCookie(w http.ResponseWriter, s session.Session, secure bool, domain string) {
	c := &http.Cookie{
		Name:     CookieName,
		Value:    s.Token,
		Path:     "/",
		Expires:  s.ExpiresAt,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
	if domain != "" {
		c.Domain = domain
		c.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, c)
}

// clearSessionCookie must target the SAME (name, path, domain)
// tuple the browser originally received, otherwise the expiring
// cookie does not replace the live one. Callers pass the same
// domain setSessionCookie used for the session being cleared.
func clearSessionCookie(w http.ResponseWriter, secure bool, domain string) {
	c := &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
	if domain != "" {
		c.Domain = domain
		c.SameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, c)
}

// Authenticate is a middleware that requires a valid session cookie.
// Phase 9b adds absolute + idle timeouts read from settings (cached
// one minute) and a throttled last_seen_at update. Missing, expired,
// or idle sessions yield 401.
func (h *Handlers) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil || c.Value == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		var idleTTL time.Duration
		if h.Timeouts != nil {
			_, idleTTL = h.Timeouts.Get(r.Context())
		} else {
			idleTTL = session.DefaultIdleTTL
		}
		s, u, err := session.Lookup(r.Context(), h.DB, c.Value, idleTTL)
		if err != nil {
			if errors.Is(err, session.ErrNotFound) ||
				errors.Is(err, session.ErrExpired) ||
				errors.Is(err, session.ErrIdle) {
				clearSessionCookie(w, h.CookieSecure, h.cookieDomain(r.Context()))
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			writeError(w, http.StatusInternalServerError, "session lookup failed")
			return
		}
		// Touch last_seen_at (throttled; no write unless >5 min old).
		// Best-effort: a transient DB error here does not block the request.
		_, _ = session.Touch(r.Context(), h.DB, s)
		ctx := context.WithValue(r.Context(), ctxUser, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func userFromContext(ctx context.Context) (session.User, bool) {
	u, ok := ctx.Value(ctxUser).(session.User)
	return u, ok
}
