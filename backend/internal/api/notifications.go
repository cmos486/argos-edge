package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// --- Channels ---

type channelPayload struct {
	Name               string                    `json:"name"`
	Type               notifications.ChannelType `json:"type"`
	Enabled            bool                      `json:"enabled"`
	Config             map[string]any            `json:"config"`
	Template           string                    `json:"template"`
	RateLimitPerMinute int                       `json:"rate_limit_per_minute"`
}

func (h *Handlers) requireNotif(w http.ResponseWriter) bool {
	if h.NotifRepo == nil || h.NotifWorker == nil {
		writeError(w, http.StatusServiceUnavailable, "notifications not wired")
		return false
	}
	return true
}

// ListNotificationChannels GET /api/notifications/channels
func (h *Handlers) ListNotificationChannels(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	out, err := h.NotifRepo.ListChannels(r.Context(), true)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list channels: "+err.Error())
		return
	}
	if out == nil {
		out = []notifications.Channel{}
	}
	writeJSON(w, http.StatusOK, out)
}

// GetNotificationChannel GET /api/notifications/channels/{id}
func (h *Handlers) GetNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ch, err := h.NotifRepo.GetChannel(r.Context(), id, true)
	if err != nil {
		if errors.Is(err, notifications.ErrChannelNotFound) {
			writeError(w, http.StatusNotFound, "channel not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

// CreateNotificationChannel POST /api/notifications/channels
func (h *Handlers) CreateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	var p channelPayload
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := validateChannelPayload(&p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	in := &notifications.Channel{
		Name:               p.Name,
		Type:               p.Type,
		Enabled:            p.Enabled,
		Config:             p.Config,
		Template:           p.Template,
		RateLimitPerMinute: p.RateLimitPerMinute,
	}
	out, err := h.NotifRepo.CreateChannel(r.Context(), in)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create: "+err.Error())
		return
	}
	h.audit(r, "create", "notification_channel", out.ID, map[string]any{"name": out.Name, "type": out.Type})
	writeJSON(w, http.StatusCreated, out)
}

// UpdateNotificationChannel PUT /api/notifications/channels/{id}
func (h *Handlers) UpdateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var p channelPayload
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	// Type is immutable across updates; pull the existing to seed it if
	// the caller omitted it.
	prev, err := h.NotifRepo.GetChannel(r.Context(), id, true)
	if err != nil {
		if errors.Is(err, notifications.ErrChannelNotFound) {
			writeError(w, http.StatusNotFound, "channel not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if p.Type == "" {
		p.Type = prev.Type
	}
	if err := validateChannelPayload(&p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	in := &notifications.Channel{
		Name:               p.Name,
		Type:               p.Type,
		Enabled:            p.Enabled,
		Config:             p.Config,
		Template:           p.Template,
		RateLimitPerMinute: p.RateLimitPerMinute,
	}
	out, err := h.NotifRepo.UpdateChannel(r.Context(), id, in)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update: "+err.Error())
		return
	}
	h.audit(r, "update", "notification_channel", id, map[string]any{"name": out.Name})
	writeJSON(w, http.StatusOK, out)
}

// DeleteNotificationChannel DELETE /api/notifications/channels/{id}
func (h *Handlers) DeleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.NotifRepo.DeleteChannel(r.Context(), id); err != nil {
		if errors.Is(err, notifications.ErrChannelNotFound) {
			writeError(w, http.StatusNotFound, "channel not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "delete", "notification_channel", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ToggleNotificationChannel POST /api/notifications/channels/{id}/toggle
func (h *Handlers) ToggleNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	out, err := h.NotifRepo.ToggleChannel(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "toggle", "notification_channel", id, map[string]any{"enabled": out.Enabled})
	writeJSON(w, http.StatusOK, out)
}

// TestNotificationChannel POST /api/notifications/channels/{id}/test
func (h *Handlers) TestNotificationChannel(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	ch, err := h.NotifRepo.GetChannel(r.Context(), id, false)
	if err != nil {
		if errors.Is(err, notifications.ErrChannelNotFound) {
			writeError(w, http.StatusNotFound, "channel not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rendered, sendErr := h.NotifWorker.SendTest(ctx, ch)
	resp := map[string]any{
		"success":      sendErr == nil,
		"sent_payload": rendered,
	}
	if sendErr != nil {
		resp["error_message"] = sendErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- Rules ---

type rulePayload struct {
	Name                  string                   `json:"name"`
	ChannelID             int64                    `json:"channel_id"`
	EventType             notifications.EventType  `json:"event_type"`
	FilterHostIDs         []int64                  `json:"filter_host_ids"`
	FilterSeverities      []notifications.Severity `json:"filter_severities"`
	Enabled               bool                     `json:"enabled"`
	ThrottleWindowSeconds int                      `json:"throttle_window_seconds"`
}

func (h *Handlers) ListNotificationRules(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	out, err := h.NotifRepo.ListRules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []notifications.Rule{}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) GetNotificationRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	out, err := h.NotifRepo.GetRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, notifications.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) CreateNotificationRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	var p rulePayload
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := validateRulePayload(&p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	in := &notifications.Rule{
		Name:                  p.Name,
		ChannelID:             p.ChannelID,
		EventType:             p.EventType,
		FilterHostIDs:         p.FilterHostIDs,
		FilterSeverities:      p.FilterSeverities,
		Enabled:               p.Enabled,
		ThrottleWindowSeconds: p.ThrottleWindowSeconds,
	}
	out, err := h.NotifRepo.CreateRule(r.Context(), in)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "create", "notification_rule", out.ID, map[string]any{"event_type": out.EventType})
	writeJSON(w, http.StatusCreated, out)
}

func (h *Handlers) UpdateNotificationRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	var p rulePayload
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := validateRulePayload(&p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	in := &notifications.Rule{
		Name:                  p.Name,
		ChannelID:             p.ChannelID,
		EventType:             p.EventType,
		FilterHostIDs:         p.FilterHostIDs,
		FilterSeverities:      p.FilterSeverities,
		Enabled:               p.Enabled,
		ThrottleWindowSeconds: p.ThrottleWindowSeconds,
	}
	out, err := h.NotifRepo.UpdateRule(r.Context(), id, in)
	if err != nil {
		if errors.Is(err, notifications.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "update", "notification_rule", id, nil)
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) DeleteNotificationRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.NotifRepo.DeleteRule(r.Context(), id); err != nil {
		if errors.Is(err, notifications.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "delete", "notification_rule", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ToggleNotificationRule(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	out, err := h.NotifRepo.ToggleRule(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "toggle", "notification_rule", id, map[string]any{"enabled": out.Enabled})
	writeJSON(w, http.StatusOK, out)
}

// --- Deliveries ---

func (h *Handlers) ListNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	q := r.URL.Query()
	f := notifications.DeliveryFilter{
		EventType: q.Get("event_type"),
		Status:    q.Get("status"),
	}
	if s := q.Get("channel_id"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			f.ChannelID = &n
		}
	}
	if s := q.Get("rule_id"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			f.RuleID = &n
		}
	}
	if s := q.Get("from"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.From = &t
		}
	}
	if s := q.Get("to"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.To = &t
		}
	}
	if s := q.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			f.Limit = n
		}
	}
	if s := q.Get("offset"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			f.Offset = n
		}
	}
	out, err := h.NotifRepo.ListDeliveries(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []notifications.Delivery{}
	}
	// also fold in stats for the cards header if requested
	resp := map[string]any{"deliveries": out}
	if q.Get("stats") == "1" && f.From != nil && f.To != nil {
		s, err := h.NotifRepo.DeliveryStats(r.Context(), *f.From, *f.To)
		if err == nil {
			resp["stats"] = s
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) GetNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	out, err := h.NotifRepo.GetDelivery(r.Context(), id)
	if err != nil {
		if errors.Is(err, notifications.ErrDeliveryNotFound) {
			writeError(w, http.StatusNotFound, "delivery not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) RetryNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	id, ok := int64Param(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	d, err := h.NotifRepo.GetDelivery(r.Context(), id)
	if err != nil {
		if errors.Is(err, notifications.ErrDeliveryNotFound) {
			writeError(w, http.StatusNotFound, "delivery not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	d2, err := h.NotifWorker.RetryDelivery(ctx, d)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "retry: "+err.Error())
		return
	}
	h.audit(r, "update", "notification_delivery", id, map[string]any{"action": "retry", "status": d2.Status})
	writeJSON(w, http.StatusOK, d2)
}

// --- Event catalog ---

func (h *Handlers) ListNotificationEventTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, notifications.Catalog())
}

// --- Push ---

type subscribePayload struct {
	Endpoint  string `json:"endpoint"`
	P256dhKey string `json:"p256dh_key"`
	AuthKey   string `json:"auth_key"`
	UserAgent string `json:"user_agent"`
}

func (h *Handlers) GetVAPIDPublicKey(w http.ResponseWriter, r *http.Request) {
	if h.VAPIDKeys == nil || h.VAPIDKeys.Public == "" {
		writeError(w, http.StatusServiceUnavailable, "vapid keys not configured")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"public_key": h.VAPIDKeys.Public})
}

func (h *Handlers) SubscribePush(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	u, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var p subscribePayload
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if p.Endpoint == "" || p.P256dhKey == "" || p.AuthKey == "" {
		writeError(w, http.StatusBadRequest, "endpoint, p256dh_key, auth_key required")
		return
	}
	sub, err := h.NotifRepo.UpsertPushSub(r.Context(), &notifications.PushSubscription{
		UserID:    u.ID,
		Endpoint:  p.Endpoint,
		P256dhKey: p.P256dhKey,
		AuthKey:   p.AuthKey,
		UserAgent: p.UserAgent,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "create", "push_subscription", sub.ID, map[string]any{"endpoint_host": truncateStr(sub.Endpoint, 80)})
	writeJSON(w, http.StatusCreated, sub)
}

func (h *Handlers) UnsubscribePush(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	u, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	var p struct {
		Endpoint string `json:"endpoint"`
	}
	if err := decodeJSON(r, &p); err != nil || p.Endpoint == "" {
		writeError(w, http.StatusBadRequest, "endpoint required")
		return
	}
	if err := h.NotifRepo.DeletePushSub(r.Context(), u.ID, p.Endpoint); err != nil {
		if errors.Is(err, notifications.ErrSubscriptionNotFound) {
			writeError(w, http.StatusNotFound, "subscription not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "delete", "push_subscription", 0, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListPushSubscriptions(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	u, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "auth required")
		return
	}
	out, err := h.NotifRepo.ListPushSubs(r.Context(), u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []notifications.PushSubscription{}
	}
	writeJSON(w, http.StatusOK, out)
}

// --- Recent alerts for Dashboard widget ---

func (h *Handlers) RecentAlerts(w http.ResponseWriter, r *http.Request) {
	if !h.requireNotif(w) {
		return
	}
	limit := 5
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 50 {
			limit = n
		}
	}
	since := time.Now().UTC().Add(-24 * time.Hour)
	out, err := h.NotifRepo.RecentAlerts(r.Context(), limit, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if out == nil {
		out = []notifications.Delivery{}
	}
	writeJSON(w, http.StatusOK, out)
}

// --- Validation helpers ---

func validateChannelPayload(p *channelPayload) error {
	if p.Name == "" {
		return errors.New("name required")
	}
	switch p.Type {
	case notifications.TypeWebhook, notifications.TypeEmail,
		notifications.TypeTelegram, notifications.TypeBrowserPush:
	default:
		return errors.New("type must be one of webhook, email, telegram, browser_push")
	}
	if p.RateLimitPerMinute < 0 || p.RateLimitPerMinute > 10000 {
		return errors.New("rate_limit_per_minute must be 0..10000")
	}
	// Per-type minimum config checks. UNCHANGED is treated as "keep
	// previous" and is ignored here.
	switch p.Type {
	case notifications.TypeWebhook:
		url, _ := p.Config["url"].(string)
		if url == "" {
			return errors.New("webhook: config.url required")
		}
	case notifications.TypeEmail:
		host, _ := p.Config["smtp_host"].(string)
		if host == "" {
			return errors.New("email: config.smtp_host required")
		}
		if _, hasFrom := p.Config["from"].(string); !hasFrom {
			return errors.New("email: config.from required")
		}
	case notifications.TypeTelegram:
		chat, _ := p.Config["chat_id"].(string)
		if chat == "" {
			return errors.New("telegram: config.chat_id required")
		}
		// bot_token may be UNCHANGED on update; do not enforce presence
		// at the API layer beyond type check
	}
	return nil
}

func validateRulePayload(p *rulePayload) error {
	if p.Name == "" {
		return errors.New("name required")
	}
	if p.ChannelID <= 0 {
		return errors.New("channel_id required")
	}
	if p.EventType == "" {
		return errors.New("event_type required")
	}
	known := false
	for _, c := range notifications.Catalog() {
		if c.Type == p.EventType {
			known = true
			break
		}
	}
	if !known {
		return errors.New("unknown event_type")
	}
	if p.ThrottleWindowSeconds < 0 || p.ThrottleWindowSeconds > 86400 {
		return errors.New("throttle_window_seconds must be 0..86400")
	}
	return nil
}

// int64Param is a helper for chi URL params -> int64.
func int64Param(r *http.Request, key string) (int64, bool) {
	s := chi.URLParam(r, key)
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// jsonPing is a tiny util used nowhere outside tests; referenced here
// to ensure encoding/json remains imported if every other user is
// removed. Not reachable at runtime.
var _ = json.RawMessage(nil)
