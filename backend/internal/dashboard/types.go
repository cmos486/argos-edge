// Package dashboard powers the Phase 6 /api/dashboard/* endpoints.
// Short ranges run live against log_entries; from 24 h up the closed
// hours come from the hourly rollup (v1.3.42.3). A 30s in-memory cache
// per (endpoint, range, host_id) key keeps clickhappy users from
// saturating SQLite.
package dashboard

import "time"

// ----- Overview -----

type Overview struct {
	TotalRequests24h   int64      `json:"total_requests_24h"`
	BlockedRequests24h int64      `json:"blocked_requests_24h"`
	ErrorRequests24h   int64      `json:"error_requests_24h"`
	ActiveHosts        int        `json:"active_hosts"`
	UnhealthyTargets   int        `json:"unhealthy_targets"`
	CertsExpiringSoon  int        `json:"certs_expiring_soon"`
	LastBackupAt       *time.Time `json:"last_backup_at,omitempty"`
	LastBackupStatus   string     `json:"last_backup_status"`
	// GeneratedAt is when this value was computed; the UI shows its age
	// because the cache may serve it for up to TTL (v1.3.38.2).
	GeneratedAt time.Time `json:"generated_at"`
	path        string
}

// SourcePath is the X-Argos-Path value: "rollup" or "rows".
func (o *Overview) SourcePath() string { return o.path }

// ----- Traffic -----

type TrafficMetrics struct {
	GeneratedAt   time.Time            `json:"generated_at"`
	Range         string               `json:"range"`
	Granularity   string               `json:"granularity"`
	Timeseries    []TrafficBucket      `json:"timeseries"`
	ResponseTimes []ResponseTimeBucket `json:"response_times"`
	TopHosts      []HostVolume         `json:"top_hosts"`
	TopPaths      []PathVolume         `json:"top_paths"`
	BandwidthOut  int64                `json:"bandwidth_out_bytes"`
	// PercentileMethod (v1.3.42.3) says how response_times were
	// computed: "exact" on rows (1 h, 6 h), "histogram" on the rollup's
	// duration buckets (24 h, 7 d, 30 d: each value is the upper edge of
	// the bucket holding the rank, 50 / 100 / 250 / 500 / 1,000 / 2,500 /
	// 5,000 ms, or the merged maximum above 5,000).
	PercentileMethod string `json:"percentile_method"`
	// Note is set only while a long range cannot be served from the
	// rollup (no hours yet): says which sections are empty and why.
	Note string `json:"note,omitempty"`
	path string
}

// SourcePath is the X-Argos-Path value: "rollup" or "rows".
func (t *TrafficMetrics) SourcePath() string { return t.path }

type TrafficBucket struct {
	Time time.Time `json:"time"`
	C2xx int       `json:"c2xx"`
	C3xx int       `json:"c3xx"`
	C4xx int       `json:"c4xx"`
	C5xx int       `json:"c5xx"`
}

type ResponseTimeBucket struct {
	Time time.Time `json:"time"`
	P50  int       `json:"p50_ms"`
	P95  int       `json:"p95_ms"`
	P99  int       `json:"p99_ms"`
	N    int       `json:"n"`
}

type HostVolume struct {
	HostDomain string `json:"host_domain"`
	Count      int64  `json:"count"`
}

type PathVolume struct {
	HostDomain string `json:"host_domain"`
	Path       string `json:"path"`
	Count      int64  `json:"count"`
}

// ----- Security -----

type SecurityMetrics struct {
	GeneratedAt      time.Time      `json:"generated_at"`
	Range            string         `json:"range"`
	Granularity      string         `json:"granularity"`
	WafTimeseries    []WafBucket    `json:"waf_timeseries"`
	TopAttackTypes   []AttackType   `json:"top_attack_types"`
	TopAttackIPs     []AttackIP     `json:"top_attack_ips"`
	TopAttackedPaths []AttackPath   `json:"top_attacked_paths"`
	RateLimitHits    int64          `json:"rate_limit_hits"`
	ByCountry        []CountryCount `json:"by_country"`
	// Hits from loopback / private ranges (RFC 1918, 127/8, fc00::/7).
	// Carried separately because those IPs cannot be placed on a world
	// map and would distort the scale if silently folded into a "XX"
	// or "unknown" bucket. The UI shows them as a sidenote under the
	// map ("plus N hits from local network").
	PrivateHits int64 `json:"private_hits"`
	// WafEngines (v1.3.39) says which WAF engine produced the events in
	// this response: the per-host Coraza WAF (waf_audit rows) and the
	// global CrowdSec AppSec (LAPI alerts). The UI names the engine
	// instead of saying "No WAF events" while AppSec is blocking.
	WafEngines *WafEngines `json:"waf_engines,omitempty"`
}

// WafEngines is the per-engine breakdown of the security section.
type WafEngines struct {
	Coraza      WafEngineCoraza `json:"coraza"`
	AppSec      WafEngineAppSec `json:"appsec"`
	EventsTotal int             `json:"events_total"`
}

// WafEngineCoraza: the per-host Coraza WAF. Events are waf_audit rows
// at WARNING or above in the range.
type WafEngineCoraza struct {
	EnabledHosts int `json:"enabled_hosts"`
	TotalHosts   int `json:"total_hosts"`
	Events       int `json:"events"`
}

// WafEngineAppSec: CrowdSec AppSec over the same range. Hits are
// kind=waf alerts (one per request), bans the appsec-* overflow
// alerts; Events is their sum. Blocked / Logged attribute each alert
// to the mode active when it fired (the alert itself does not say).
type WafEngineAppSec struct {
	Mode    string `json:"mode"`
	Hits    int    `json:"hits"`
	Bans    int    `json:"bans"`
	Events  int    `json:"events"`
	Blocked int    `json:"blocked"`
	Logged  int    `json:"logged"`
}

// CountryCount is one row of the by_country aggregation that feeds
// the Dashboard world map. Hits from a single country are summed
// across ALL attacking IPs in the window -- not just the top N
// shown in TopAttackIPs -- so the choropleth reflects where traffic
// actually came from.
type CountryCount struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Count       int64  `json:"count"`
}

// WafBucket is one point of the security chart. Detected are Coraza
// audit rows (WARNING or above); Blocked are 403 responses at the
// edge from any cause (bans, AppSec, Coraza in block mode); AppSec
// (v1.3.39) are AppSec alerts, hits and bans, in the bucket.
type WafBucket struct {
	Time     time.Time `json:"time"`
	Detected int       `json:"detected"`
	Blocked  int       `json:"blocked"`
	AppSec   int       `json:"appsec"`
}

// AttackType is one row of "top attack types". Coraza rows carry the
// CRS rule id; AppSec rows (v1.3.39) carry the scenario in Rule and
// Engine "appsec".
type AttackType struct {
	RuleID  int    `json:"rule_id"`
	Rule    string `json:"rule,omitempty"`
	Engine  string `json:"engine,omitempty"`
	Message string `json:"message"`
	Count   int64  `json:"count"`
}

type AttackIP struct {
	RemoteIP      string         `json:"remote_ip"`
	Count         int64          `json:"count"`
	DistinctHosts int            `json:"distinct_hosts"`
	LastSeen      time.Time      `json:"last_seen"`
	Geo           *GeoEnrichment `json:"geo,omitempty"`
}

// GeoEnrichment is the subset of geoip.Result shipped inline with
// TopAttackIPs (and parallel endpoints). Duplicated rather than
// imported to keep this package dep-free; the api layer populates
// it from geoip.Result via a direct field copy.
type GeoEnrichment struct {
	CountryCode string `json:"country_code,omitempty"`
	CountryName string `json:"country_name,omitempty"`
	ASN         uint   `json:"asn,omitempty"`
	ASNOrg      string `json:"asn_org,omitempty"`
	IsPrivate   bool   `json:"is_private,omitempty"`
}

type AttackPath struct {
	HostDomain string `json:"host_domain"`
	Path       string `json:"path"`
	Count      int64  `json:"count"`
}

// ----- Health -----

type HealthStatus struct {
	TargetGroups []TargetGroupHealth `json:"target_groups"`
	Certs        []CertSummary       `json:"certs"`
	LastBackup   *BackupSummary      `json:"last_backup,omitempty"`
	PanelUptime  string              `json:"panel_uptime"`
	CaddyStatus  string              `json:"caddy_status"`
	RecentErrors []RecentError       `json:"recent_errors"`
	GeneratedAt  time.Time           `json:"generated_at"`
}

type TargetGroupHealth struct {
	Name    string `json:"name"`
	Total   int    `json:"total"`
	Enabled int    `json:"enabled"`
	Status  string `json:"status"` // ok | degraded | down
}

type CertSummary struct {
	Domain   string    `json:"domain"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
	Status   string    `json:"status"` // ok | warning (<30d) | critical (<14d) | unknown
}

type BackupSummary struct {
	Filename  string    `json:"filename"`
	CreatedAt time.Time `json:"created_at"`
	SizeBytes int64     `json:"size_bytes"`
	Kind      string    `json:"kind"`
}

type RecentError struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Level     string    `json:"level,omitempty"`
	Message   string    `json:"message"`
}
