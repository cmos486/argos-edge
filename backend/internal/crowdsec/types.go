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
