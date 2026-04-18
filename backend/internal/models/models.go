// Package models holds the plain data types the panel persists or
// serialises. Keep these dependency-free so any layer can depend on
// them without pulling in SQL, HTTP, or Caddy concerns.
package models

import "time"

// TLSMode controls whether Caddy should automate certificates for a host.
type TLSMode string

const (
	TLSModeAuto TLSMode = "auto" // Let's Encrypt via DNS-01 (cloudflare)
	TLSModeNone TLSMode = "none" // plain HTTP, no TLS
)

// Protocol is the scheme a target group uses to talk to its backends.
type Protocol string

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
)

// Algorithm is the load-balancing selection policy for a target group.
type Algorithm string

const (
	AlgoRoundRobin Algorithm = "round_robin"
	AlgoLeastConn  Algorithm = "least_conn"
	AlgoIPHash     Algorithm = "ip_hash"
	AlgoRandom     Algorithm = "random"
)

// HealthCheckMethod is the HTTP verb active checks issue.
type HealthCheckMethod string

const (
	HealthGet  HealthCheckMethod = "GET"
	HealthHead HealthCheckMethod = "HEAD"
	HealthPost HealthCheckMethod = "POST"
)

// TargetGroup is the AWS-style indirection between a public host and
// its pool of backend servers. It owns protocol, tls verification,
// load-balancing algorithm and active health-check configuration.
//
// Targets is hydrated by GetTargetGroup; it is nil in list queries to
// keep payloads small. TargetsCount is populated in both paths.
type TargetGroup struct {
	ID                          int64             `json:"id"`
	Name                        string            `json:"name"`
	Protocol                    Protocol          `json:"protocol"`
	VerifyTLS                   bool              `json:"verify_tls"`
	Algorithm                   Algorithm         `json:"algorithm"`
	HealthCheckEnabled          bool              `json:"health_check_enabled"`
	HealthCheckPath             string            `json:"health_check_path"`
	HealthCheckMethod           HealthCheckMethod `json:"health_check_method"`
	HealthCheckExpectStatus     string            `json:"health_check_expect_status"`
	HealthCheckIntervalSeconds  int               `json:"health_check_interval_seconds"`
	HealthCheckTimeoutSeconds   int               `json:"health_check_timeout_seconds"`
	HealthCheckFailsToUnhealthy int               `json:"health_check_fails_to_unhealthy"`
	HealthCheckPassesToHealthy  int               `json:"health_check_passes_to_healthy"`
	CreatedAt                   time.Time         `json:"created_at"`
	UpdatedAt                   time.Time         `json:"updated_at"`
	Targets                     []Target          `json:"targets,omitempty"`
	TargetsCount                int               `json:"targets_count"`
	TargetsEnabledCount         int               `json:"targets_enabled_count"`
}

// Target is one host:port endpoint inside a TargetGroup.
type Target struct {
	ID            int64     `json:"id"`
	TargetGroupID int64     `json:"target_group_id"`
	Host          string    `json:"host"`
	Port          int       `json:"port"`
	Weight        int       `json:"weight"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TargetGroupSummary is the compact view the hosts endpoint embeds so
// the UI can render the Upstream column without a second request.
type TargetGroupSummary struct {
	ID                  int64     `json:"id"`
	Name                string    `json:"name"`
	Protocol            Protocol  `json:"protocol"`
	Algorithm           Algorithm `json:"algorithm"`
	TargetsCount        int       `json:"targets_count"`
	TargetsEnabledCount int       `json:"targets_enabled_count"`
}

// Host is a public domain managed by the panel. Starting in phase 2
// the upstream is always a TargetGroup; protocol, tls verification,
// load-balancing algorithm and health checks live on the group. In
// phase 3 the host may also own a set of rules that override the
// default target group for matching requests; RulesCount mirrors the
// size of that set so the list endpoint can render "3 rules" without
// a second request.
type Host struct {
	ID            int64               `json:"id"`
	Domain        string              `json:"domain"`
	TargetGroupID int64               `json:"target_group_id"`
	TargetGroup   *TargetGroupSummary `json:"target_group,omitempty"`
	TLSMode       TLSMode             `json:"tls_mode"`
	TLSEmail      string              `json:"tls_email"`
	Enabled       bool                `json:"enabled"`
	RulesCount    int                 `json:"rules_count"`
	CreatedAt     time.Time           `json:"created_at"`
	UpdatedAt     time.Time           `json:"updated_at"`
}

// CertStatus mirrors one entry from Caddy's certificate storage.
type CertStatus struct {
	Domain        string    `json:"domain"`
	Issuer        string    `json:"issuer"`
	NotAfter      time.Time `json:"not_after"`
	LastCheckedAt time.Time `json:"last_checked_at"`
}

// LogSource names the origin of a log entry.
type LogSource string

const (
	LogCaddyAccess LogSource = "caddy_access"
	LogCaddyError  LogSource = "caddy_error"
	LogAudit       LogSource = "audit"
	LogWAFAudit    LogSource = "waf_audit"
)

// LogEntry is one row of the unified log store consumed by /api/logs
// and its SSE/CSV/stats siblings.
type LogEntry struct {
	ID              int64     `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	Source          LogSource `json:"source"`
	Level           string    `json:"level,omitempty"`
	HostID          *int64    `json:"host_id,omitempty"`
	HostDomain      string    `json:"host_domain,omitempty"`
	RuleID          *int64    `json:"rule_id,omitempty"`
	RemoteIP        string    `json:"remote_ip,omitempty"`
	Method          string    `json:"method,omitempty"`
	Path            string    `json:"path,omitempty"`
	Status          int       `json:"status,omitempty"`
	DurationMs      int       `json:"duration_ms,omitempty"`
	SizeBytes       int       `json:"size_bytes,omitempty"`
	UserAgent       string    `json:"user_agent,omitempty"`
	Upstream        string    `json:"upstream,omitempty"`
	Message         string    `json:"message,omitempty"`
	Raw             string    `json:"raw,omitempty"`
	WAFRuleID       int       `json:"waf_rule_id,omitempty"`
	WAFRuleMessage  string    `json:"waf_rule_message,omitempty"`
	WAFSeverity     string    `json:"waf_severity,omitempty"`
	WAFAnomalyScore int       `json:"waf_anomaly_score,omitempty"`
}

// Setting is one row of the key/value settings table.
type Setting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WAFMode is the Coraza SecRuleEngine state.
type WAFMode string

const (
	WAFModeDetect WAFMode = "detect"
	WAFModeBlock  WAFMode = "block"
)

// RateLimitKey selects how caddy-ratelimit identifies a client.
type RateLimitKey string

const (
	RateLimitKeyIP     RateLimitKey = "ip"
	RateLimitKeyHeader RateLimitKey = "header"
	RateLimitKeyGlobal RateLimitKey = "global"
)

// HostSecurity is the per-host WAF + rate-limit configuration.
type HostSecurity struct {
	HostID                 int64        `json:"host_id"`
	WAFEnabled             bool         `json:"waf_enabled"`
	WAFMode                WAFMode      `json:"waf_mode"`
	WAFParanoia            int          `json:"waf_paranoia"`
	WAFBlockStatus         int          `json:"waf_block_status"`
	WAFBlockBody           string       `json:"waf_block_body"`
	RateLimitEnabled       bool         `json:"rate_limit_enabled"`
	RateLimitRequests      int          `json:"rate_limit_requests"`
	RateLimitWindowSeconds int          `json:"rate_limit_window_seconds"`
	RateLimitKey           RateLimitKey `json:"rate_limit_key"`
	RateLimitHeaderName    string       `json:"rate_limit_header_name"`
	RateLimitStatus        int          `json:"rate_limit_status"`
	UpdatedAt              time.Time    `json:"updated_at"`
}

// WAFExclusion disables a single CRS rule for the host, either globally
// (PathPattern == "") or only for requests whose path matches the
// glob-ish pattern (Coraza evaluates it as a @beginsWith).
type WAFExclusion struct {
	ID          int64     `json:"id"`
	HostID      int64     `json:"host_id"`
	CRSRuleID   int       `json:"crs_rule_id"`
	PathPattern string    `json:"path_pattern"`
	Reason      string    `json:"reason"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// WAFCustomRule is raw SecRule/SecAction text appended to the host's
// Coraza config after the CRS include block.
type WAFCustomRule struct {
	ID        int64     `json:"id"`
	HostID    int64     `json:"host_id"`
	Name      string    `json:"name"`
	SecRule   string    `json:"secrule"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// HostSecurityBundle is the shape GET /api/hosts/{id}/security returns:
// the core config plus the exclusions and custom rules that belong to
// the same host, all resolved in one round-trip.
type HostSecurityBundle struct {
	HostSecurity
	Exclusions  []WAFExclusion  `json:"exclusions"`
	CustomRules []WAFCustomRule `json:"custom_rules"`
}
