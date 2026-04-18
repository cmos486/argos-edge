package api

import (
	"errors"
	"net/http"

	"github.com/cmos486/argos-edge/backend/internal/auth"
	"github.com/cmos486/argos-edge/backend/internal/session"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userResponse struct {
	Username string `json:"username"`
}

// Login verifies credentials and issues a session cookie.
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
	u, err := auth.Authenticate(r.Context(), h.DB, req.Username, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthorized) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	s, err := session.Create(r.Context(), h.DB, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	setSessionCookie(w, s, h.CookieSecure)
	writeJSON(w, http.StatusOK, userResponse{Username: u.Username})
}

// Logout deletes the current session and clears the cookie. Idempotent:
// calling it without a valid session still returns 204.
func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		_ = session.Delete(r.Context(), h.DB, c.Value)
	}
	clearSessionCookie(w, h.CookieSecure)
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
