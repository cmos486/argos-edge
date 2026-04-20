// Package notifications is the phase-5 event + dispatch system. It
// exposes an Emitter (Emit) that internal subsystems (audit recorder,
// log ingestor, cert cron, healthcheck cron) call to publish events;
// a Worker drains the queue, matches active rules, renders a template
// and dispatches to a Sender implementation per channel type.
//
// Everything is in-process: the queue is a buffered channel, throttle
// and rate-limit state live in sync.Maps guarded by a mutex. The
// notification_deliveries table is the durable audit trail.
package notifications

import (
	"context"
	"time"
)

// Severity classifies events. Sorted lowest-to-highest importance.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// ChannelType enumerates the four sender backends phase 5 ships.
type ChannelType string

const (
	TypeWebhook     ChannelType = "webhook"
	TypeEmail       ChannelType = "email"
	TypeTelegram    ChannelType = "telegram"
	TypeBrowserPush ChannelType = "browser_push"
)

// DeliveryStatus is the terminal state of one delivery attempt chain.
type DeliveryStatus string

const (
	StatusPending     DeliveryStatus = "pending"
	StatusSent        DeliveryStatus = "sent"
	StatusFailed      DeliveryStatus = "failed"
	StatusThrottled   DeliveryStatus = "throttled"
	StatusRateLimited DeliveryStatus = "rate_limited"
)

// Event is what subsystems publish. Data is free-form per type and
// referenced from templates via {{ .Data.foo }}.
type Event struct {
	Type       EventType      `json:"type"`
	Severity   Severity       `json:"severity"`
	HostID     int64          `json:"host_id,omitempty"`
	HostDomain string         `json:"host_domain,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
	Message    string         `json:"message"`
	Data       map[string]any `json:"data,omitempty"`
}

// Channel is the persisted configuration for one dispatch endpoint.
// Config holds a type-specific JSON object whose secret fields are
// replaced with ciphertext before persisting. When returned through
// the API, secrets are REDACTED.
type Channel struct {
	ID                 int64          `json:"id"`
	Name               string         `json:"name"`
	Type               ChannelType    `json:"type"`
	Enabled            bool           `json:"enabled"`
	Config             map[string]any `json:"config"`
	Template           string         `json:"template,omitempty"`
	RateLimitPerMinute int            `json:"rate_limit_per_minute"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
}

// Rule binds an event type to a channel with optional filters + throttle.
type Rule struct {
	ID                    int64      `json:"id"`
	Name                  string     `json:"name"`
	ChannelID             int64      `json:"channel_id"`
	EventType             EventType  `json:"event_type"`
	FilterHostIDs         []int64    `json:"filter_host_ids,omitempty"`
	FilterSeverities      []Severity `json:"filter_severities,omitempty"`
	Enabled               bool       `json:"enabled"`
	ThrottleWindowSeconds int        `json:"throttle_window_seconds"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// Delivery is one attempt chain to send an Event via a Channel through
// a Rule. One event -> N deliveries (one per matched rule).
type Delivery struct {
	ID              int64          `json:"id"`
	RuleID          *int64         `json:"rule_id,omitempty"`
	ChannelID       *int64         `json:"channel_id,omitempty"`
	EventType       EventType      `json:"event_type"`
	EventPayload    string         `json:"event_payload"`
	RenderedPayload string         `json:"rendered_payload"`
	Status          DeliveryStatus `json:"status"`
	ErrorMessage    string         `json:"error_message,omitempty"`
	Attempts        int            `json:"attempts"`
	CreatedAt       time.Time      `json:"created_at"`
	SentAt          *time.Time     `json:"sent_at,omitempty"`
}

// PushSubscription is one browser's Web Push endpoint + VAPID keys.
type PushSubscription struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Endpoint  string    `json:"endpoint"`
	P256dhKey string    `json:"p256dh_key"`
	AuthKey   string    `json:"auth_key"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
}

// Sender is the interface implemented by each channel backend. Called
// by the worker after template rendering; the sender only cares about
// the channel's config + the rendered body.
type Sender interface {
	Send(ctx context.Context, ch *Channel, ev *Event, rendered string) error
}

// SenderRegistry maps channel type -> implementation.
type SenderRegistry map[ChannelType]Sender
