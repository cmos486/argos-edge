package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/session"
)

// CookieName is the name of the session cookie. Kept short; the same value
// is read by the frontend indirectly (it never accesses the cookie, only
// relies on the browser sending it).
const CookieName = "argos_session"

type ctxKey int

const (
	ctxUser    ctxKey = iota // session.User
	ctxSession                // session.Session
)

func setSessionCookie(w http.ResponseWriter, s session.Session, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    s.Token,
		Path:     "/",
		Expires:  s.ExpiresAt,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
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
				clearSessionCookie(w, h.CookieSecure)
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			writeError(w, http.StatusInternalServerError, "session lookup failed")
			return
		}
		// Touch last_seen_at (throttled; no write unless >5 min old).
		if newLast, terr := session.Touch(r.Context(), h.DB, s); terr == nil {
			s.LastSeenAt = newLast
		}
		ctx := context.WithValue(r.Context(), ctxUser, u)
		ctx = context.WithValue(ctx, ctxSession, s)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func userFromContext(ctx context.Context) (session.User, bool) {
	u, ok := ctx.Value(ctxUser).(session.User)
	return u, ok
}

func sessionFromContext(ctx context.Context) (session.Session, bool) {
	s, ok := ctx.Value(ctxSession).(session.Session)
	return s, ok
}
