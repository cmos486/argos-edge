package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/cmos486/argos-edge/backend/internal/caddy"
)

// Handlers groups dependency-bearing handlers. Standalone handlers that
// touch nothing (e.g. Healthz) stay as package-level functions.
type Handlers struct {
	DB           *sql.DB
	Caddy        *caddy.Client
	CookieSecure bool
}

// errorBody is the shape returned for any 4xx/5xx response from /api/*.
type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode json response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
