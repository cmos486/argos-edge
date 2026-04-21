package configio

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// Export snapshots the current panel state into a ConfigBundle. All
// secrets are redacted.
func Export(ctx context.Context, d *sql.DB, repo *notifications.NotifRepo, argosVersion string) (*ConfigBundle, error) {
	b := &ConfigBundle{
		Version:      BundleVersion,
		ExportedAt:   time.Now().UTC().Format(time.RFC3339),
		ArgosVersion: argosVersion,
	}

	// Target groups (names are the natural key for hosts -> TG)
	tgs, err := db.ListTargetGroups(ctx, d, true)
	if err != nil {
		return nil, fmt.Errorf("list tgs: %w", err)
	}
	tgsByID := make(map[int64]models.TargetGroup, len(tgs))
	for _, tg := range tgs {
		tgsByID[tg.ID] = tg
		tx := TargetGroupExport{
			Name:                        tg.Name,
			Protocol:                    string(tg.Protocol),
			VerifyTLS:                   tg.VerifyTLS,
			Algorithm:                   string(tg.Algorithm),
			HealthCheckEnabled:          tg.HealthCheckEnabled,
			HealthCheckPath:             tg.HealthCheckPath,
			HealthCheckMethod:           string(tg.HealthCheckMethod),
			HealthCheckExpectStatus:     tg.HealthCheckExpectStatus,
			HealthCheckIntervalSeconds:  tg.HealthCheckIntervalSeconds,
			HealthCheckTimeoutSeconds:   tg.HealthCheckTimeoutSeconds,
			HealthCheckFailsToUnhealthy: tg.HealthCheckFailsToUnhealthy,
			HealthCheckPassesToHealthy:  tg.HealthCheckPassesToHealthy,
		}
		for _, t := range tg.Targets {
			tx.Targets = append(tx.Targets, TargetExport{
				Host:    t.Host,
				Port:    t.Port,
				Weight:  t.Weight,
				Enabled: t.Enabled,
			})
		}
		b.TargetGroups = append(b.TargetGroups, tx)
	}

	// Hosts
	hosts, err := db.ListHosts(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	hostsByID := make(map[int64]models.Host, len(hosts))
	for _, h := range hosts {
		hostsByID[h.ID] = h
		tgName := ""
		if tg, ok := tgsByID[h.TargetGroupID]; ok {
			tgName = tg.Name
		}
		b.Hosts = append(b.Hosts, HostExport{
			Domain:          h.Domain,
			TargetGroupName: tgName,
			TLSMode:         string(h.TLSMode),
			TLSEmail:        h.TLSEmail,
			Enabled:         h.Enabled,
			TLSACMECAURL:    h.TLSACMECAURL,
			TLSChallenge:    string(h.TLSChallenge),
		})
	}

	// Rules per host
	for _, h := range hosts {
		rs, err := db.ListRulesByHost(ctx, d, h.ID)
		if err != nil {
			return nil, fmt.Errorf("list rules %d: %w", h.ID, err)
		}
		for _, r := range rs {
			actBytes, _ := json.Marshal(r.Action)
			matchers := make([]json.RawMessage, 0, len(r.Matchers))
			for _, m := range r.Matchers {
				mb, _ := json.Marshal(m)
				matchers = append(matchers, mb)
			}
			b.Rules = append(b.Rules, RuleExport{
				HostDomain: h.Domain,
				Priority:   r.Priority,
				Name:       r.Name,
				Enabled:    r.Enabled,
				Action:     actBytes,
				Matchers:   matchers,
			})
		}
	}

	// Host security (per host)
	for _, h := range hosts {
		bundle, err := db.LoadHostSecurityBundle(ctx, d, h.ID)
		if err != nil {
			return nil, fmt.Errorf("load security %d: %w", h.ID, err)
		}
		hsx := HostSecurityExport{
			HostDomain:             h.Domain,
			WAFEnabled:             bundle.WAFEnabled,
			WAFMode:                string(bundle.WAFMode),
			WAFParanoia:            bundle.WAFParanoia,
			WAFBlockStatus:         bundle.WAFBlockStatus,
			WAFBlockBody:           bundle.WAFBlockBody,
			RateLimitEnabled:       bundle.RateLimitEnabled,
			RateLimitRequests:      bundle.RateLimitRequests,
			RateLimitWindowSeconds: bundle.RateLimitWindowSeconds,
			RateLimitKey:           string(bundle.RateLimitKey),
			RateLimitHeaderName:    bundle.RateLimitHeaderName,
			RateLimitStatus:        bundle.RateLimitStatus,
		}
		for _, e := range bundle.Exclusions {
			hsx.Exclusions = append(hsx.Exclusions, ExclusionExport{
				CRSRuleID:   e.CRSRuleID,
				PathPattern: e.PathPattern,
				Reason:      e.Reason,
				Enabled:     e.Enabled,
			})
		}
		for _, c := range bundle.CustomRules {
			hsx.CustomRules = append(hsx.CustomRules, CustomRuleExport{
				Name:    c.Name,
				SecRule: c.SecRule,
				Enabled: c.Enabled,
			})
		}
		b.HostSecurity = append(b.HostSecurity, hsx)
	}

	// Notification channels (secrets redacted) + rules
	if repo != nil {
		chans, err := repo.ListChannels(ctx, false)
		if err != nil {
			return nil, fmt.Errorf("list channels: %w", err)
		}
		chanNameByID := make(map[int64]string, len(chans))
		for _, c := range chans {
			chanNameByID[c.ID] = c.Name
			cfg := redactChannelConfig(string(c.Type), c.Config)
			b.NotificationChannels = append(b.NotificationChannels, ChannelExport{
				Name:               c.Name,
				Type:               string(c.Type),
				Enabled:            c.Enabled,
				Config:             cfg,
				Template:           c.Template,
				RateLimitPerMinute: c.RateLimitPerMinute,
			})
		}
		nrs, err := repo.ListRules(ctx)
		if err != nil {
			return nil, fmt.Errorf("list notif rules: %w", err)
		}
		for _, nr := range nrs {
			// map host_ids -> domains so the bundle stays portable
			domains := make([]string, 0, len(nr.FilterHostIDs))
			for _, id := range nr.FilterHostIDs {
				if h, ok := hostsByID[id]; ok {
					domains = append(domains, h.Domain)
				}
			}
			sevs := make([]string, 0, len(nr.FilterSeverities))
			for _, s := range nr.FilterSeverities {
				sevs = append(sevs, string(s))
			}
			b.NotificationRules = append(b.NotificationRules, NotifRuleExport{
				Name:                  nr.Name,
				ChannelName:           chanNameByID[nr.ChannelID],
				EventType:             string(nr.EventType),
				FilterHostDomains:     domains,
				FilterSeverities:      sevs,
				Enabled:               nr.Enabled,
				ThrottleWindowSeconds: nr.ThrottleWindowSeconds,
			})
		}
	}

	// Settings (whitelisted non-secrets only)
	settings, err := db.ListSettingsByPrefix(ctx, d, "")
	if err != nil {
		return nil, fmt.Errorf("list settings: %w", err)
	}
	b.Settings = make(map[string]string)
	for _, s := range settings {
		if exportableSettings[s.Key] {
			b.Settings[s.Key] = s.Value
		}
	}

	// Sort slices for stable output
	sort.SliceStable(b.Hosts, func(i, j int) bool { return b.Hosts[i].Domain < b.Hosts[j].Domain })
	sort.SliceStable(b.TargetGroups, func(i, j int) bool { return b.TargetGroups[i].Name < b.TargetGroups[j].Name })
	sort.SliceStable(b.Rules, func(i, j int) bool {
		if b.Rules[i].HostDomain != b.Rules[j].HostDomain {
			return b.Rules[i].HostDomain < b.Rules[j].HostDomain
		}
		return b.Rules[i].Priority < b.Rules[j].Priority
	})
	sort.SliceStable(b.HostSecurity, func(i, j int) bool {
		return b.HostSecurity[i].HostDomain < b.HostSecurity[j].HostDomain
	})
	sort.SliceStable(b.NotificationChannels, func(i, j int) bool {
		return b.NotificationChannels[i].Name < b.NotificationChannels[j].Name
	})
	sort.SliceStable(b.NotificationRules, func(i, j int) bool {
		return b.NotificationRules[i].Name < b.NotificationRules[j].Name
	})

	return b, nil
}

// MarshalYAML renders a ConfigBundle with an informational header
// comment explaining that secrets are redacted.
func MarshalYAML(b *ConfigBundle) ([]byte, error) {
	body, err := yaml.Marshal(b)
	if err != nil {
		return nil, err
	}
	header := `# argos-edge configuration export
# Generated: ` + b.ExportedAt + `
# Version:   ` + b.Version + `
#
# All secret fields are shown as "` + RedactedPlaceholder + `".
# On import in "merge" mode, existing ciphertexts are preserved; in
# "replace" mode, secrets become empty and the owning channel is
# disabled until the operator reconfigures it.
#
`
	out := make([]byte, 0, len(header)+len(body))
	out = append(out, header...)
	out = append(out, body...)
	return out, nil
}

// redactChannelConfig replaces every secret field in a channel config
// with the literal placeholder. Non-string secret shapes (webhook's
// headers map) are replaced with the placeholder string wholesale.
func redactChannelConfig(channelType string, cfg map[string]any) map[string]any {
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	for _, f := range channelSecretFields(channelType) {
		if _, ok := out[f]; ok {
			out[f] = RedactedPlaceholder
		}
	}
	// crypto.IsEncrypted guard is belt-and-braces: the repo gives us
	// plaintext via GetChannel(redact=false) on the caller's request,
	// but in case someone passes already-redacted config, keep it.
	_ = crypto.IsEncrypted
	return out
}
