// Package appsec owns the argos-side logic for the CrowdSec AppSec
// (WAF inline) feature. It does not run the WAF itself -- that lives
// in the crowdsec container, served over :7422 (block) and :7423
// (detect). The package is the thin bridge the HTTP API talks to:
//
//   - Status()  tells the UI which mode is active, how many AppSec
//     collections/rules are installed, and who last flipped
//     the switch.
//   - Metrics() pulls recent waf-kind alerts from LAPI, parses them
//     into argos' typed shape, and bucket-sums them. A 30s
//     in-memory cache mirrors the dashboard pattern so a
//     click-happy UI does not saturate LAPI.
//
// Mode changes themselves are owned by reconciler.SetAppSecMode; this
// package never writes the setting. That split keeps the Caddy
// reconcile path (risky, touches live traffic) in one file instead
// of spread between api, reconciler, and appsec.
package appsec

import "time"

// Status is the shape GET /api/appsec/status returns.
type Status struct {
	Mode                 string     `json:"mode"` // detect | block | disabled
	CollectionsInstalled []string   `json:"collections_installed"`
	TotalRules           int        `json:"total_rules"`
	LastModeChangeAt     *time.Time `json:"last_mode_change_at,omitempty"`
	LastModeChangeBy     string     `json:"last_mode_change_by,omitempty"`
}

// CategoryCount aggregates hits by high-level attack family. Derived
// from scenario names (vpatch-CVE-* -> "cve", generic-* -> "generic",
// crs -> "crs", etc.).
type CategoryCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// TopIP enriches a hit-count with GeoIP (filled by the API layer,
// kept here as a passthrough struct so this package does not import
// internal/geoip and tangle dependencies).
type TopIP struct {
	IP       string         `json:"ip"`
	Count    int64          `json:"count"`
	LastSeen time.Time      `json:"last_seen"`
	Geo      *GeoEnrichment `json:"geo,omitempty"`
}

// GeoEnrichment mirrors the shape dashboard.GeoEnrichment already
// ships; duplicated to keep appsec dep-free of geoip.
type GeoEnrichment struct {
	CountryCode string `json:"country_code,omitempty"`
	CountryName string `json:"country_name,omitempty"`
	ASN         uint   `json:"asn,omitempty"`
	ASNOrg      string `json:"asn_org,omitempty"`
	IsPrivate   bool   `json:"is_private,omitempty"`
}

type TopPath struct {
	Host  string `json:"host,omitempty"`
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

type TopRule struct {
	Rule    string `json:"rule"`
	Message string `json:"message,omitempty"`
	Count   int64  `json:"count"`
}

type TimeBucket struct {
	Time    time.Time `json:"time"`
	Hits    int64     `json:"hits"`
	Blocked int64     `json:"blocked"`
}

// Metrics is the shape GET /api/appsec/metrics returns. Blocked /
// Logged split is derived from the current argos appsec.mode, not
// from per-alert inspection -- AppSec alerts do not carry the
// remediation that was returned to the bouncer, so splitting
// historically accurately would require argos to keep a mode-change
// time-series. The simpler attribution is good enough for the
// at-a-glance dashboard and is documented in the UI copy.
type Metrics struct {
	Window       string          `json:"window"`
	Mode         string          `json:"mode"`
	TotalHits    int64           `json:"total_hits"`
	Blocked      int64           `json:"blocked"`
	Logged       int64           `json:"logged"`
	ByCategory   []CategoryCount `json:"by_category"`
	TopIPs       []TopIP         `json:"top_ips"`
	TopPaths     []TopPath       `json:"top_paths"`
	TopRules     []TopRule       `json:"top_rules"`
	HitsOverTime []TimeBucket    `json:"hits_over_time"`
}
