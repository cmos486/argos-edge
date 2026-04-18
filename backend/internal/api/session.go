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
		SameSite: http.SameSiteLaxMode,
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
		SameSite: http.SameSiteLaxMode,
	})
}

// Authenticate is a middleware that requires a valid session cookie.
// Expired or missing sessions yield 401; the handler never sees them.
func (h *Handlers) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil || c.Value == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		s, u, err := session.Lookup(r.Context(), h.DB, c.Value)
		if err != nil {
			if errors.Is(err, session.ErrNotFound) || errors.Is(err, session.ErrExpired) {
				clearSessionCookie(w, h.CookieSecure)
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			writeError(w, http.StatusInternalServerError, "session lookup failed")
			return
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
