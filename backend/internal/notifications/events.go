package notifications

// EventType is the stringly-typed discriminator published with every
// Event. The ten constants below are the only event types phase 5
// supports; adding a new one requires editing this file.
type EventType string

const (
	EvtCertExpiringSoon      EventType = "cert_expiring_soon"
	EvtCertRenewalFailed     EventType = "cert_renewal_failed"
	EvtWAFAttackBurst        EventType = "waf_attack_burst"
	EvtTargetUnhealthy       EventType = "target_unhealthy"
	EvtTargetRecovered       EventType = "target_recovered"
	EvtWAFDetectModeReminder EventType = "waf_detect_mode_reminder"
	EvtConfigChange          EventType = "config_change"
	EvtRateLimitTriggered    EventType = "rate_limit_triggered"
	EvtLoginFailed           EventType = "login_failed"
	EvtHealthDegraded        EventType = "health_degraded"
	EvtBackupCompleted       EventType = "backup_completed"
	EvtBackupFailed          EventType = "backup_failed"
	EvtConfigRestored        EventType = "config_restored"
	EvtThreatIPBanned        EventType = "threat_ip_banned"
	EvtThreatIntelUpdated    EventType = "threat_intel_updated"
	EvtCrowdSecDown          EventType = "crowdsec_down"
)

// EventCatalogEntry is the schema description exposed via
// GET /api/notifications/event-types for the frontend dropdown.
type EventCatalogEntry struct {
	Type             EventType `json:"type"`
	Severity         Severity  `json:"severity"`
	Description      string    `json:"description"`
	TriggerCondition string    `json:"trigger_condition"`
	SampleEvent      Event     `json:"sample_event"`
}

// Catalog returns the hardcoded list exposed by the API. Order is
// roughly "deployment health" -> "security" -> "admin" for UI grouping.
func Catalog() []EventCatalogEntry {
	return []EventCatalogEntry{
		{
			Type:             EvtCertExpiringSoon,
			Severity:         SeverityWarning,
			Description:      "TLS certificate is about to expire",
			TriggerCondition: "Daily cron: cert not_after < now + 14 days",
			SampleEvent: Event{
				Type:       EvtCertExpiringSoon,
				Severity:   SeverityWarning,
				HostDomain: "example.com",
				Message:    "cert for example.com expires in 7 days",
				Data:       map[string]any{"days_left": 7, "not_after": "2026-05-01T00:00:00Z"},
			},
		},
		{
			Type:             EvtCertRenewalFailed,
			Severity:         SeverityError,
			Description:      "Let's Encrypt renewal failed",
			TriggerCondition: "Log ingestor: caddy_error matching 'obtain certificate'",
			SampleEvent: Event{
				Type:       EvtCertRenewalFailed,
				Severity:   SeverityError,
				HostDomain: "example.com",
				Message:    "ACME renewal failed",
				Data:       map[string]any{"error": "dns-01 propagation timeout"},
			},
		},
		{
			Type:             EvtWAFAttackBurst,
			Severity:         SeverityCritical,
			Description:      "Burst of WAF violations from a single IP",
			TriggerCondition: "Ingestor: >=10 waf_audit rows with severity CRITICAL from same IP in 60s",
			SampleEvent: Event{
				Type:       EvtWAFAttackBurst,
				Severity:   SeverityCritical,
				HostDomain: "example.com",
				Message:    "attack burst from 203.0.113.42",
				Data: map[string]any{
					"remote_ip": "203.0.113.42",
					"count":     14,
					"top_rules": []int{942100, 930120},
				},
			},
		},
		{
			Type:             EvtTargetUnhealthy,
			Severity:         SeverityError,
			Description:      "A backend target started failing health checks",
			TriggerCondition: "Ingestor: Caddy health-checker log 'host is down'",
			SampleEvent: Event{
				Type:       EvtTargetUnhealthy,
				Severity:   SeverityError,
				HostDomain: "example.com",
				Message:    "target 10.0.0.5:8080 is down",
				Data:       map[string]any{"host": "10.0.0.5", "port": 8080},
			},
		},
		{
			Type:             EvtTargetRecovered,
			Severity:         SeverityInfo,
			Description:      "A backend target recovered",
			TriggerCondition: "Ingestor: Caddy health-checker log 'host is up' after prior down",
			SampleEvent: Event{
				Type:       EvtTargetRecovered,
				Severity:   SeverityInfo,
				HostDomain: "example.com",
				Message:    "target 10.0.0.5:8080 is up",
				Data:       map[string]any{"host": "10.0.0.5", "port": 8080},
			},
		},
		{
			Type:             EvtWAFDetectModeReminder,
			Severity:         SeverityWarning,
			Description:      "Host still in WAF detect mode after 7 days",
			TriggerCondition: "Daily cron 09:00: waf_enabled AND waf_mode=detect AND updated_at < now-7d",
			SampleEvent: Event{
				Type:       EvtWAFDetectModeReminder,
				Severity:   SeverityWarning,
				HostDomain: "example.com",
				Message:    "example.com has been in detect mode for 10 days",
				Data:       map[string]any{"days_in_detect": 10},
			},
		},
		{
			Type:             EvtConfigChange,
			Severity:         SeverityInfo,
			Description:      "Any create/update/delete on hosts, TGs, rules, security, settings",
			TriggerCondition: "Audit recorder: action in (create,update,delete) excluding login/logout",
			SampleEvent: Event{
				Type:     EvtConfigChange,
				Severity: SeverityInfo,
				Message:  "user admin updated host 1",
				Data: map[string]any{
					"user":          "admin",
					"action":        "update",
					"resource_type": "host",
					"resource_id":   1,
				},
			},
		},
		{
			Type:             EvtRateLimitTriggered,
			Severity:         SeverityWarning,
			Description:      "Rate-limit rejection burst on a host",
			TriggerCondition: "Ingestor: >=5 status=429 responses on same host in 30s",
			SampleEvent: Event{
				Type:       EvtRateLimitTriggered,
				Severity:   SeverityWarning,
				HostDomain: "example.com",
				Message:    "rate limit hit 5 times in 30s on example.com",
				Data:       map[string]any{"count": 5, "window_seconds": 30},
			},
		},
		{
			Type:             EvtLoginFailed,
			Severity:         SeverityWarning,
			Description:      "Failed panel login attempt",
			TriggerCondition: "Audit recorder: action=failed_login",
			SampleEvent: Event{
				Type:     EvtLoginFailed,
				Severity: SeverityWarning,
				Message:  "login failed for user admin",
				Data:     map[string]any{"user": "admin", "remote_ip": "192.168.3.100"},
			},
		},
		{
			Type:             EvtHealthDegraded,
			Severity:         SeverityCritical,
			Description:      "Panel self-check or Caddy admin API down",
			TriggerCondition: "Internal cron every 30s: /healthz or caddy:2019 fails twice consecutively",
			SampleEvent: Event{
				Type:     EvtHealthDegraded,
				Severity: SeverityCritical,
				Message:  "caddy admin API unreachable",
				Data:     map[string]any{"component": "caddy_admin", "consecutive_failures": 2},
			},
		},
		{
			Type:             EvtBackupCompleted,
			Severity:         SeverityInfo,
			Description:      "Scheduled or manual backup finished successfully",
			TriggerCondition: "Backup manager after a successful Create()",
			SampleEvent: Event{
				Type:     EvtBackupCompleted,
				Severity: SeverityInfo,
				Message:  "backup argos-backup-20260419-020000.tar.gz (12.3 MiB) ok",
				Data: map[string]any{
					"filename":   "argos-backup-20260419-020000.tar.gz",
					"size_bytes": 12884901,
					"kind":       "scheduled",
				},
			},
		},
		{
			Type:             EvtBackupFailed,
			Severity:         SeverityError,
			Description:      "Backup creation failed mid-run",
			TriggerCondition: "Backup manager after Create() returned an error",
			SampleEvent: Event{
				Type:     EvtBackupFailed,
				Severity: SeverityError,
				Message:  "backup failed: vacuum into: disk full",
				Data:     map[string]any{"kind": "scheduled", "error": "disk full"},
			},
		},
		{
			Type:             EvtConfigRestored,
			Severity:         SeverityWarning,
			Description:      "Panel just finished applying a backup on boot",
			TriggerCondition: "main.go picked up /data/.restore_pending and restored argos.db",
			SampleEvent: Event{
				Type:     EvtConfigRestored,
				Severity: SeverityWarning,
				Message:  "restored from argos-backup-20260418-131500.tar.gz",
				Data: map[string]any{
					"from_backup": "argos-backup-20260418-131500.tar.gz",
				},
			},
		},
		{
			Type:             EvtThreatIPBanned,
			Severity:         SeverityInfo,
			Description:      "CrowdSec inserted a new decision (ban / captcha)",
			TriggerCondition: "Monitor poll: decision id present now but absent in the previous poll",
			SampleEvent: Event{
				Type:     EvtThreatIPBanned,
				Severity: SeverityInfo,
				Message:  "crowdsec banned 203.0.113.42",
				Data: map[string]any{
					"ip":       "203.0.113.42",
					"scope":    "Ip",
					"scenario": "crowdsecurity/http-probing",
					"duration": "4h",
					"origin":   "CAPI",
				},
			},
		},
		{
			Type:             EvtThreatIntelUpdated,
			Severity:         SeverityInfo,
			Description:      "Summary of the per-poll decisions diff",
			TriggerCondition: "Monitor poll: any row added or removed since the last tick",
			SampleEvent: Event{
				Type:     EvtThreatIntelUpdated,
				Severity: SeverityInfo,
				Message:  "threat intel updated",
				Data:     map[string]any{"added_count": 14, "removed_count": 3, "total": 248},
			},
		},
		{
			Type:             EvtCrowdSecDown,
			Severity:         SeverityError,
			Description:      "CrowdSec LAPI unreachable from the panel",
			TriggerCondition: "3 consecutive heartbeat failures (default interval 15s)",
			SampleEvent: Event{
				Type:     EvtCrowdSecDown,
				Severity: SeverityError,
				Message:  "crowdsec LAPI unreachable",
				Data:     map[string]any{"consecutive_failures": 3, "error": "dial tcp: connection refused"},
			},
		},
	}
}
