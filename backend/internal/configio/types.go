// Package configio handles YAML export + import of the panel's
// configuration state. Backup/restore in internal/backup is the
// binary path (tar.gz of argos.db + caddy); this package is the
// human-auditable / portable path.
//
// Secrets are always redacted in export (literal string "__REDACTED__"
// in place of the value). On import: replace mode creates those
// channels with enabled=false so the operator is forced to
// reconfigure; merge mode preserves the previous ciphertext when the
// channel already exists by name.
package configio

import (
	"encoding/json"
)

// BundleVersion is the value for ConfigBundle.Version. Bump when the
// shape changes in a way older bundles should not be silently
// imported into.
const BundleVersion = "1"

// RedactedPlaceholder is the literal value an Export writes in place
// of every secret field. Import recognises it verbatim.
const RedactedPlaceholder = "__REDACTED__"

// ConfigBundle is the full shape of an export file.
type ConfigBundle struct {
	// ExportedAt is a plain string (RFC3339) rather than time.Time so
	// bundles round-trip cleanly through any YAML library (PyYAML,
	// e.g., emits times without the "T" separator Go expects).
	Version              string                 `yaml:"version"`
	ExportedAt           string                 `yaml:"exported_at"`
	ArgosVersion         string                 `yaml:"argos_version,omitempty"`
	Hosts                []HostExport           `yaml:"hosts"`
	TargetGroups         []TargetGroupExport    `yaml:"target_groups"`
	Rules                []RuleExport           `yaml:"rules"`
	HostSecurity         []HostSecurityExport   `yaml:"host_security"`
	NotificationChannels []ChannelExport        `yaml:"notification_channels"`
	NotificationRules    []NotifRuleExport      `yaml:"notification_rules"`
	Settings             map[string]string      `yaml:"settings"`
}

// HostExport mirrors models.Host without internal ids, so the YAML is
// portable across installs. Upstream resolution is by TargetGroup.Name
// (a natural key inside the bundle).
type HostExport struct {
	Domain          string `yaml:"domain"`
	TargetGroupName string `yaml:"target_group"`
	TLSMode         string `yaml:"tls_mode"`
	TLSEmail        string `yaml:"tls_email,omitempty"`
	Enabled         bool   `yaml:"enabled"`
}

// TargetGroupExport includes its list of targets inline.
type TargetGroupExport struct {
	Name                        string         `yaml:"name"`
	Protocol                    string         `yaml:"protocol"`
	VerifyTLS                   bool           `yaml:"verify_tls"`
	Algorithm                   string         `yaml:"algorithm"`
	HealthCheckEnabled          bool           `yaml:"health_check_enabled"`
	HealthCheckPath             string         `yaml:"health_check_path,omitempty"`
	HealthCheckMethod           string         `yaml:"health_check_method,omitempty"`
	HealthCheckExpectStatus     string         `yaml:"health_check_expect_status,omitempty"`
	HealthCheckIntervalSeconds  int            `yaml:"health_check_interval_seconds,omitempty"`
	HealthCheckTimeoutSeconds   int            `yaml:"health_check_timeout_seconds,omitempty"`
	HealthCheckFailsToUnhealthy int            `yaml:"health_check_fails_to_unhealthy,omitempty"`
	HealthCheckPassesToHealthy  int            `yaml:"health_check_passes_to_healthy,omitempty"`
	Targets                     []TargetExport `yaml:"targets"`
}

type TargetExport struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	Weight  int    `yaml:"weight"`
	Enabled bool   `yaml:"enabled"`
}

// RuleExport references its host by domain (unique) since IDs are
// local to each install.
type RuleExport struct {
	HostDomain string          `yaml:"host"`
	Priority   int             `yaml:"priority"`
	Name       string          `yaml:"name,omitempty"`
	Enabled    bool            `yaml:"enabled"`
	// Action / Matchers are persisted as raw JSON in the DB so we
	// round-trip them unchanged rather than re-modelling every concrete
	// variant in YAML.
	Action   json.RawMessage   `yaml:"action"`
	Matchers []json.RawMessage `yaml:"matchers"`
}

// HostSecurityExport bundles the per-host WAF + rate limit config
// plus its exclusions and custom rules.
type HostSecurityExport struct {
	HostDomain             string                `yaml:"host"`
	WAFEnabled             bool                  `yaml:"waf_enabled"`
	WAFMode                string                `yaml:"waf_mode"`
	WAFParanoia            int                   `yaml:"waf_paranoia"`
	WAFBlockStatus         int                   `yaml:"waf_block_status"`
	WAFBlockBody           string                `yaml:"waf_block_body,omitempty"`
	RateLimitEnabled       bool                  `yaml:"rate_limit_enabled"`
	RateLimitRequests      int                   `yaml:"rate_limit_requests,omitempty"`
	RateLimitWindowSeconds int                   `yaml:"rate_limit_window_seconds,omitempty"`
	RateLimitKey           string                `yaml:"rate_limit_key,omitempty"`
	RateLimitHeaderName    string                `yaml:"rate_limit_header_name,omitempty"`
	RateLimitStatus        int                   `yaml:"rate_limit_status,omitempty"`
	Exclusions             []ExclusionExport     `yaml:"exclusions,omitempty"`
	CustomRules            []CustomRuleExport    `yaml:"custom_rules,omitempty"`
}

type ExclusionExport struct {
	CRSRuleID   int    `yaml:"crs_rule_id"`
	PathPattern string `yaml:"path_pattern,omitempty"`
	Reason      string `yaml:"reason,omitempty"`
	Enabled     bool   `yaml:"enabled"`
}

type CustomRuleExport struct {
	Name    string `yaml:"name"`
	SecRule string `yaml:"secrule"`
	Enabled bool   `yaml:"enabled"`
}

// ChannelExport redacts every secret field to the literal
// "__REDACTED__". The consumer of the YAML can fill the real values
// in before Apply, or accept the default (secret empty, enabled=false)
// when the import runs in replace mode.
type ChannelExport struct {
	Name               string                 `yaml:"name"`
	Type               string                 `yaml:"type"`
	Enabled            bool                   `yaml:"enabled"`
	Config             map[string]interface{} `yaml:"config"`
	Template           string                 `yaml:"template,omitempty"`
	RateLimitPerMinute int                    `yaml:"rate_limit_per_minute"`
}

type NotifRuleExport struct {
	Name                  string   `yaml:"name"`
	ChannelName           string   `yaml:"channel"`
	EventType             string   `yaml:"event_type"`
	FilterHostDomains     []string `yaml:"filter_hosts,omitempty"`
	FilterSeverities      []string `yaml:"filter_severities,omitempty"`
	Enabled               bool     `yaml:"enabled"`
	ThrottleWindowSeconds int      `yaml:"throttle_window_seconds,omitempty"`
}

// ImportPlan is the dry-run output of Validate: what Apply would do
// if called with the same bundle. Counts are cheap to render in the UI
// header; Warnings is the audible part (eg "3 channels need secret
// reconfiguration").
type ImportPlan struct {
	Mode        string         `json:"mode"` // replace | merge
	Counts      map[string]int `json:"counts"`
	Creates     []string       `json:"creates"`
	Updates     []string       `json:"updates"`
	Conflicts   []string       `json:"conflicts"`
	Warnings    []string       `json:"warnings"`
}

// exportableSettings is the whitelist of settings keys that leave the
// panel in YAML. Everything else (VAPID private, CF token, admin
// password, session secret) stays local only.
var exportableSettings = map[string]bool{
	"logs.retention_days":          true,
	"logs.max_entries":             true,
	"backup.schedule":              true,
	"backup.retention_days":        true,
	"backup.enabled":               true,
	"notifications.retention_days": true,
	"notifications.max_entries":    true,
	"notifications.vapid_contact_email": true,
}

// channelSecretFields mirrors the list in notifications/repo.go. The
// config package does not import notifications to avoid cycles.
func channelSecretFields(channelType string) []string {
	switch channelType {
	case "webhook":
		return []string{"headers"}
	case "email":
		return []string{"smtp_password"}
	case "telegram":
		return []string{"bot_token"}
	}
	return nil
}
