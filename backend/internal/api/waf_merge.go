package api

import (
	"context"
	"database/sql"
	"sort"

	"github.com/cmos486/argos-edge/backend/internal/appsec"
	"github.com/cmos486/argos-edge/backend/internal/dashboard"
)

// corazaHostCounts returns how many hosts have the per-host Coraza WAF
// enabled and how many hosts exist. Two indexed counts.
func corazaHostCounts(ctx context.Context, d *sql.DB) (enabled, total int) {
	if d == nil {
		return 0, 0
	}
	_ = d.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_security WHERE waf_enabled = 1`).Scan(&enabled)
	_ = d.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts`).Scan(&total)
	return enabled, total
}

// mergeAppSecIntoSecurity folds an AppSec summary into the Coraza-only
// SecurityMetrics the dashboard query produced: per-engine block,
// the appsec series of the chart, and the top attack types / IPs /
// paths tables (sorted by count, same caps as before: 10 / 20 / 10).
// Returns the AppSec per-IP counts so the caller can fold them into
// the by_country map with the same GeoIP pass. Pure: unit-tested.
func mergeAppSecIntoSecurity(s *dashboard.SecurityMetrics, sum appsec.Summary, mode string, corazaEnabled, totalHosts int) map[string]int64 {
	corazaEvents := 0
	for i := range s.WafTimeseries {
		corazaEvents += s.WafTimeseries[i].Detected
		if o, ok := sum.Buckets[s.WafTimeseries[i].Time.Unix()]; ok {
			s.WafTimeseries[i].AppSec = o.Blocked + o.Detected
		}
	}
	s.WafEngines = &dashboard.WafEngines{
		Coraza: dashboard.WafEngineCoraza{EnabledHosts: corazaEnabled, TotalHosts: totalHosts, Events: corazaEvents},
		AppSec: dashboard.WafEngineAppSec{
			Mode: mode, Hits: sum.Hits, Bans: sum.Bans, Events: sum.Hits + sum.Bans,
			Blocked: sum.Blocked, Logged: sum.Logged,
		},
		EventsTotal: corazaEvents + sum.Hits + sum.Bans,
	}

	for i := range s.TopAttackTypes {
		s.TopAttackTypes[i].Engine = "coraza"
	}
	for rule, n := range sum.ByRule {
		s.TopAttackTypes = append(s.TopAttackTypes, dashboard.AttackType{
			Rule: rule, Engine: "appsec", Message: sum.RuleMsg[rule], Count: int64(n),
		})
	}
	sort.SliceStable(s.TopAttackTypes, func(i, j int) bool { return s.TopAttackTypes[i].Count > s.TopAttackTypes[j].Count })
	if len(s.TopAttackTypes) > 10 {
		s.TopAttackTypes = s.TopAttackTypes[:10]
	}

	ipIndex := map[string]int{}
	for i := range s.TopAttackIPs {
		ipIndex[s.TopAttackIPs[i].RemoteIP] = i
	}
	appsecIPs := make(map[string]int64, len(sum.ByIP))
	for ip, n := range sum.ByIP {
		appsecIPs[ip] = int64(n)
		if i, ok := ipIndex[ip]; ok {
			s.TopAttackIPs[i].Count += int64(n)
			if len(sum.HostsByIP[ip]) > s.TopAttackIPs[i].DistinctHosts {
				s.TopAttackIPs[i].DistinctHosts = len(sum.HostsByIP[ip])
			}
			if sum.LastByIP[ip].After(s.TopAttackIPs[i].LastSeen) {
				s.TopAttackIPs[i].LastSeen = sum.LastByIP[ip]
			}
			continue
		}
		s.TopAttackIPs = append(s.TopAttackIPs, dashboard.AttackIP{
			RemoteIP: ip, Count: int64(n), DistinctHosts: len(sum.HostsByIP[ip]), LastSeen: sum.LastByIP[ip],
		})
	}
	sort.SliceStable(s.TopAttackIPs, func(i, j int) bool { return s.TopAttackIPs[i].Count > s.TopAttackIPs[j].Count })
	if len(s.TopAttackIPs) > 20 {
		s.TopAttackIPs = s.TopAttackIPs[:20]
	}

	pathIndex := map[[2]string]int{}
	for i := range s.TopAttackedPaths {
		pathIndex[[2]string{s.TopAttackedPaths[i].HostDomain, s.TopAttackedPaths[i].Path}] = i
	}
	for k, n := range sum.ByPath {
		if i, ok := pathIndex[k]; ok {
			s.TopAttackedPaths[i].Count += int64(n)
			continue
		}
		s.TopAttackedPaths = append(s.TopAttackedPaths, dashboard.AttackPath{HostDomain: k[0], Path: k[1], Count: int64(n)})
	}
	sort.SliceStable(s.TopAttackedPaths, func(i, j int) bool { return s.TopAttackedPaths[i].Count > s.TopAttackedPaths[j].Count })
	if len(s.TopAttackedPaths) > 10 {
		s.TopAttackedPaths = s.TopAttackedPaths[:10]
	}
	return appsecIPs
}
