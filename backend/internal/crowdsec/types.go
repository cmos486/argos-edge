// Package crowdsec is the phase-7 client for the bundled CrowdSec
// LAPI. It exposes a typed wrapper over the subset of /v1 endpoints
// the panel needs: list decisions (bouncer-key auth), add + delete
// decisions (machine JWT auth), and a heartbeat for the /threats
// status card. A monitor goroutine diffs the decisions list every
// poll and emits notification events on transitions.
package crowdsec

import "time"

// Decision is a flattened view of the LAPI Decision object, keeping
// only the fields the UI renders. The wire format is considerably
// richer; fields we do not need today are ignored on unmarshal.
type Decision struct {
	ID        int64          `json:"id"`
	Origin    string         `json:"origin"`   // CAPI | crowdsec | cscli | manual
	Type      string         `json:"type"`     // ban | captcha
	Scope     string         `json:"scope"`    // Ip | Range | Country | Username
	Value     string         `json:"value"`    // the IP / CIDR / country code
	Scenario  string         `json:"scenario"` // which bucket triggered the ban
	Duration  string         `json:"duration"` // eg "4h0m0s" per CrowdSec
	Until     time.Time      `json:"until"`
	CreatedAt time.Time      `json:"created_at,omitempty"`
	Geo       *GeoEnrichment `json:"geo,omitempty"`
}

// GeoEnrichment mirrors the shape dashboard.GeoEnrichment ships; kept
// here so this package stays decoupled from the dashboard package.
// The api layer fills it from a geoip.Result.
type GeoEnrichment struct {
	CountryCode string `json:"country_code,omitempty"`
	CountryName string `json:"country_name,omitempty"`
	ASN         uint   `json:"asn,omitempty"`
	ASNOrg      string `json:"asn_org,omitempty"`
	IsPrivate   bool   `json:"is_private,omitempty"`
}

// Scenario describes an installed detection bucket.
type Scenario struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Status  string `json:"status,omitempty"` // enabled/disabled
}

// Collection bundles scenarios + parsers. Phase 7 ships two:
// crowdsecurity/base-http-scenarios and crowdsecurity/http-cve.
type Collection struct {
	Name      string   `json:"name"`
	Version   string   `json:"version,omitempty"`
	Parsers   []string `json:"parsers,omitempty"`
	Scenarios []string `json:"scenarios,omitempty"`
}

// Status is the shape GET /api/threats/status returns. "state" is
// one of not_configured | connected | disconnected | degraded.
type Status struct {
	State         string     `json:"state"`
	LAPIVersion   string     `json:"lapi_version,omitempty"`
	LAPIURL       string     `json:"lapi_url,omitempty"`
	LastHeartbeat *time.Time `json:"last_heartbeat,omitempty"`
	BouncerOK     bool       `json:"bouncer_ok"`
	MachineOK     bool       `json:"machine_ok"`
	Error         string     `json:"error,omitempty"`
}

// AddDecisionInput is what POST /api/threats/decisions accepts.
type AddDecisionInput struct {
	IP            string `json:"ip"`
	DurationHours int    `json:"duration_hours"`
	Reason        string `json:"reason,omitempty"`
}

// Stats is the response for GET /api/threats/stats?range=24h.
type Stats struct {
	Range           string         `json:"range"`
	ActiveDecisions int            `json:"active_decisions"`
	ByOrigin        map[string]int `json:"by_origin"`
	ByScenario      map[string]int `json:"by_scenario"`
	ByScope         map[string]int `json:"by_scope"`
	LastUpdated     time.Time      `json:"last_updated"`
}

// AlertEventMeta is the key/value bag CrowdSec emits on each event.
// For AppSec alerts the interesting keys are uri, target_fqdn,
// rule_name, method, message, matched_zones.
type AlertEventMeta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// AlertEvent is one parsed line that contributed to an alert. AppSec
// generates one event per request/rule match; scenarios built on top
// of caddy-logs collapse many events into one alert.
type AlertEvent struct {
	Timestamp string           `json:"timestamp,omitempty"`
	Meta      []AlertEventMeta `json:"meta,omitempty"`
}

// AlertSource identifies who triggered the alert. For AppSec hits the
// scope is always "Ip" and value is the remote IP.
type AlertSource struct {
	Scope string `json:"scope,omitempty"`
	Value string `json:"value,omitempty"`
	IP    string `json:"ip,omitempty"`
	AS    string `json:"as_number,omitempty"`
}

// AlertDecision is the subset of CrowdSec's per-alert decision row
// argos cares about. AppSec hits in BLOCK mode produce a decision
// (a `ban` for the source IP; the bouncer applies it inline AND
// stores it in LAPI for the duration). DETECT mode produces zero
// decisions on the same alert. argos uses len(Decisions) > 0 as the
// canonical "was this hit blocked or just logged" signal -- more
// reliable than reading the panel's current `appsec.mode` setting,
// which can flip between when the alert fired and when the panel UI
// queries it.
type AlertDecision struct {
	ID       int64  `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`     // ban | captcha | throttle
	Origin   string `json:"origin,omitempty"`   // CAPI | crowdsec | cscli | manual
	Scope    string `json:"scope,omitempty"`    // Ip | Range
	Value    string `json:"value,omitempty"`
	Duration string `json:"duration,omitempty"`
}

// Alert is the subset of /v1/alerts payload argos reads today.
// Additional fields CrowdSec ships (labels, leakspeed, scenario_hash
// etc.) are ignored on unmarshal.
type Alert struct {
	ID            int64           `json:"id"`
	Kind          string          `json:"kind"` // "waf" for AppSec
	Scenario      string          `json:"scenario"`
	Message       string          `json:"message,omitempty"`
	CreatedAtText string          `json:"created_at,omitempty"` // RFC3339ish
	StartAt       string          `json:"start_at,omitempty"`
	StopAt        string          `json:"stop_at,omitempty"`
	Source        AlertSource     `json:"source"`
	Events        []AlertEvent    `json:"events,omitempty"`
	EventsCount   int             `json:"events_count,omitempty"`
	Decisions     []AlertDecision `json:"decisions,omitempty"`
}

// WasBlocked reports whether this alert resulted in an active
// ban/captcha decision (block-mode behaviour) versus a log-only
// notification (detect-mode behaviour). Determined per-alert from
// the decisions array CrowdSec emits, not from the panel's current
// `appsec.mode` setting -- so a mode swap does not retroactively
// reclassify historical hits.
func (a *Alert) WasBlocked() bool {
	return len(a.Decisions) > 0
}

// CreatedAt returns CreatedAtText parsed as UTC time; zero time if
// unparseable (CrowdSec sometimes emits a bare-space format).
func (a *Alert) CreatedAt() time.Time {
	if a.CreatedAtText == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, a.CreatedAtText); err == nil {
		return t.UTC()
	}
	// Fallback: "2026-04-19 15:53:25 +0000 UTC" -- crowdsec embed.
	if t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", a.CreatedAtText); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// EventMeta returns a merged view of all events' meta, newest first.
// AppSec alerts typically have exactly one event, but the generic
// helper keeps the semantics honest across scenarios.
func (a *Alert) EventMeta() map[string]string {
	out := map[string]string{}
	for _, ev := range a.Events {
		for _, m := range ev.Meta {
			if _, ok := out[m.Key]; !ok {
				out[m.Key] = m.Value
			}
		}
	}
	return out
}
