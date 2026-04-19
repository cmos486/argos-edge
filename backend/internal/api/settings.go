package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/robfig/cron/v3"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// settingWhitelist enumerates the keys PUT /api/settings/{key} accepts
// plus the per-key validator that parses and range-checks the value.
var settingWhitelist = map[string]func(string) error{
	"logs.retention_days":               intRange(1, 365),
	"logs.max_entries":                  intRange(10000, 5000000),
	"notifications.retention_days":      intRange(1, 365),
	"notifications.max_entries":         intRange(1000, 1000000),
	"notifications.vapid_contact_email": nonEmptyString,
	"backup.enabled":                    boolString,
	"backup.schedule":                   cronString,
	"backup.retention_days":             intRange(0, 365),
}

func nonEmptyString(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	return nil
}

func boolString(s string) error {
	switch s {
	case "true", "false":
		return nil
	}
	return fmt.Errorf("must be 'true' or 'false'")
}

func cronString(s string) error {
	if s == "" {
		return fmt.Errorf("must not be empty")
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	if _, err := parser.Parse(s); err != nil {
		return fmt.Errorf("invalid cron: %v", err)
	}
	return nil
}

func intRange(lo, hi int) func(string) error {
	return func(s string) error {
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("must be an integer")
		}
		if n < lo || n > hi {
			return fmt.Errorf("must be between %d and %d", lo, hi)
		}
		return nil
	}
}

// ListSettings returns every setting, optionally filtered by ?prefix=.
func (h *Handlers) ListSettings(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	items, err := db.ListSettingsByPrefix(r.Context(), h.DB, prefix)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list settings failed")
		return
	}
	if items == nil {
		items = []models.Setting{}
	}
	writeJSON(w, http.StatusOK, items)
}

// UpdateSetting applies PUT /api/settings/{key}. Unknown keys are rejected.
func (h *Handlers) UpdateSetting(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	validate, ok := settingWhitelist[key]
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown setting key")
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := validate(body.Value); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("%s: %v", key, err))
		return
	}
	if err := db.UpsertSetting(r.Context(), h.DB, key, body.Value); err != nil {
		writeError(w, http.StatusInternalServerError, "update setting failed")
		return
	}
	h.audit(r, "update", "setting", 0, map[string]any{"key": key, "value": body.Value})
	s, err := db.GetSetting(r.Context(), h.DB, key)
	if err != nil {
		if errors.Is(err, db.ErrSettingNotFound) {
			writeError(w, http.StatusInternalServerError, "setting vanished after upsert")
			return
		}
		writeError(w, http.StatusInternalServerError, "read back setting failed")
		return
	}
	writeJSON(w, http.StatusOK, s)
}
