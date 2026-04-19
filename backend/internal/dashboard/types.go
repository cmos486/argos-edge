// Package dashboard powers the Phase 6 /api/dashboard/* endpoints.
// Queries run live against log_entries (no rollup table) with a 30s
// in-memory cache per (endpoint, range, host_id) key so clickhappy
// users do not saturate SQLite.
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
}

// ----- Traffic -----

type TrafficMetrics struct {
	Range         string               `json:"range"`
	Granularity   string               `json:"granularity"`
	Timeseries    []TrafficBucket      `json:"timeseries"`
	ResponseTimes []ResponseTimeBucket `json:"response_times"`
	TopHosts      []HostVolume         `json:"top_hosts"`
	TopPaths      []PathVolume         `json:"top_paths"`
	BandwidthOut  int64                `json:"bandwidth_out_bytes"`
}

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
	Range            string       `json:"range"`
	Granularity      string       `json:"granularity"`
	WafTimeseries    []WafBucket  `json:"waf_timeseries"`
	TopAttackTypes   []AttackType `json:"top_attack_types"`
	TopAttackIPs     []AttackIP   `json:"top_attack_ips"`
	TopAttackedPaths []AttackPath `json:"top_attacked_paths"`
	RateLimitHits    int64        `json:"rate_limit_hits"`
}

type WafBucket struct {
	Time     time.Time `json:"time"`
	Detected int       `json:"detected"`
	Blocked  int       `json:"blocked"`
}

type AttackType struct {
	RuleID  int    `json:"rule_id"`
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
