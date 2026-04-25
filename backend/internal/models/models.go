// Package models holds the plain data types the panel persists or
// serialises. Keep these dependency-free so any layer can depend on
// them without pulling in SQL, HTTP, or Caddy concerns.
package models

import "time"

// TLSMode controls whether Caddy should automate certificates for a host.
type TLSMode string

const (
	TLSModeAuto   TLSMode = "auto"   // Let's Encrypt via the challenge selected on the host
	TLSModeNone   TLSMode = "none"   // plain HTTP, no TLS
	TLSModeManual TLSMode = "manual" // operator-uploaded cert + key in host_manual_certs (v1.1)
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
	// PreserveHost forwards the original Host header to upstream
	// when true. Default false. Required by backends that bind
	// session cookies / WebSocket auth to the request hostname
	// (UniFi Network Controller is the canonical case); without
	// it the upstream sees Host=<dialed-host:port> and rejects
	// the WS upgrade.
	PreserveHost                bool              `json:"preserve_host"`
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
	// AuthRequired = 1 makes Caddy round-trip every request through
	// /api/auth/forward before the reverse_proxy fires. Only the
	// parent-domain cookie set by the panel (or any subdomain of
	// oidc.cookie_parent_domain) is accepted. Default 0 = public.
	AuthRequired bool `json:"auth_required"`
	// LanOnly = 1 makes Caddy serve the host only to clients whose
	// remote_ip matches RFC 1918 + loopback + ULA. Public IPs get a
	// 403. Useful for admin panels exposed via public DNS + valid
	// TLS but reachable only from the LAN / VPN. Default 0 = the
	// host is reachable from anywhere on the open internet.
	// Implementation note: client IP detection follows Caddy's
	// trusted_proxies config (set by argos to RFC 1918 + loopback
	// in v1.3.8). When argos is the first hop after the public
	// internet the remote_ip matcher operates on the real client
	// IP; when a CDN / additional reverse proxy fronts argos, the
	// operator must extend trusted_proxies so the X-Forwarded-For
	// chain resolves correctly.
	LanOnly bool `json:"lan_only"`
	// TLSACMECAURL, when set, overrides the acme.ca_url global
	// setting for this host only. Empty string = inherit the global
	// (which itself falls back to Caddy's LE production default).
	// Env var ARGOS_ACME_CA_URL trumps both at reconcile time.
	TLSACMECAURL string `json:"tls_acme_ca_url"`
	// TLSChallenge selects which ACME challenge Caddy uses for this
	// host when tls_mode=auto. One of "dns", "http", "tls-alpn".
	// Default "dns" matches pre-022 behaviour.
	TLSChallenge TLSChallenge `json:"tls_challenge"`
	// TLSDNSProvider names the dns_providers row the reconciler
	// resolves credentials from when tls_challenge='dns'. Default
	// 'cloudflare' preserves the pre-v1.3 single-provider behaviour.
	// Ignored when tls_challenge != 'dns'.
	TLSDNSProvider string `json:"tls_dns_provider"`
	RulesCount     int    `json:"rules_count"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// TLSChallenge names one of the three ACME challenge types argos
// supports. The values mirror the CHECK constraint on hosts.tls_challenge.
type TLSChallenge string

const (
	TLSChallengeDNS     TLSChallenge = "dns"
	TLSChallengeHTTP    TLSChallenge = "http"
	TLSChallengeTLSALPN TLSChallenge = "tls-alpn"
)

// CertStatus mirrors one entry from Caddy's certificate storage,
// enriched with panel-side renewal telemetry.
type CertStatus struct {
	Domain        string    `json:"domain"`
	HostID        int64     `json:"host_id"`
	Issuer        string    `json:"issuer"`
	NotAfter      time.Time `json:"not_after"`
	LastCheckedAt time.Time `json:"last_checked_at"`
	// DaysLeft is floor((not_after - now) / 24h). Negative values
	// mean the cert has already expired.
	DaysLeft int `json:"days_left"`
	// Status buckets DaysLeft into operator-facing labels:
	// "ok" (>30d), "warning" (7-30d), "critical" (<7d), "expired".
	Status string `json:"status"`
	// NextRenewalEstimate is the earliest time Caddy's default
	// certmagic renewal window (~30 days before expiry) kicks in.
	// Informational; actual timing depends on Caddy's internal tick.
	NextRenewalEstimate time.Time `json:"next_renewal_estimate"`
	// LastRenewalEvent summarises the most recent caddy_error log
	// row mentioning this domain. Nil when no such row exists.
	LastRenewalEvent *CertEvent `json:"last_renewal_event,omitempty"`
	// Challenge mirrors hosts.tls_challenge so the UI can show
	// which ACME challenge this cert was issued with.
	Challenge TLSChallenge `json:"challenge,omitempty"`
}

// CertEvent is a compact projection of a log_entries row used to
// surface the last renewal attempt next to each CertStatus.
type CertEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
	// Success is a best-effort read: log rows whose message lacks
	// "error" / "fail" are treated as success. Good enough for a
	// UI badge; the details drawer in /logs is the source of truth.
	Success bool `json:"success"`
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

// DNSProviderRow is one row of the dns_providers catalogue-with-creds
// table. CredentialsEncrypted is the argos1: ciphertext of a JSON
// blob whose shape is owned by internal/dnsproviders; the panel only
// decrypts it at reconcile time + on explicit "update credentials" API
// calls. It never ships over the wire.
type DNSProviderRow struct {
	ID                   int64     `json:"id"`
	Name                 string    `json:"name"`
	Enabled              bool      `json:"enabled"`
	CredentialsEncrypted []byte    `json:"-"`
	UpdatedAt            time.Time `json:"updated_at"`
}
