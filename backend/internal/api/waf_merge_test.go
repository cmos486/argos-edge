package api

import (
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/appsec"
	"github.com/cmos486/argos-edge/backend/internal/dashboard"
)

func TestMergeAppSecIntoSecurity(t *testing.T) {
	t0 := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	s := &dashboard.SecurityMetrics{
		WafTimeseries:    []dashboard.WafBucket{{Time: t0, Detected: 2, Blocked: 40}, {Time: t0.Add(time.Hour), Detected: 0, Blocked: 10}},
		TopAttackTypes:   []dashboard.AttackType{{RuleID: 942100, Message: "SQLi", Count: 3}},
		TopAttackIPs:     []dashboard.AttackIP{{RemoteIP: "203.0.113.1", Count: 2, DistinctHosts: 1, LastSeen: t0}},
		TopAttackedPaths: []dashboard.AttackPath{{HostDomain: "a.example.com", Path: "/.env", Count: 2}},
	}
	sum := appsec.Summary{
		Hits: 5, Bans: 1, Blocked: 6, Logged: 0,
		ByIP:      map[string]int{"203.0.113.1": 4, "203.0.113.2": 2},
		LastByIP:  map[string]time.Time{"203.0.113.1": t0.Add(30 * time.Minute), "203.0.113.2": t0},
		HostsByIP: map[string]map[string]struct{}{"203.0.113.1": {"a.example.com": {}, "b.example.com": {}}},
		ByRule:    map[string]int{"crowdsecurity/vpatch-env-access": 5, "crowdsecurity/appsec-native": 1},
		RuleMsg:   map[string]string{"crowdsecurity/vpatch-env-access": "env access"},
		ByPath:    map[[2]string]int{{"a.example.com", "/.env"}: 3, {"b.example.com", "/wp-login.php"}: 2},
		Buckets:   map[int64]appsec.Outcome{t0.Unix(): {Blocked: 4}, t0.Add(time.Hour).Unix(): {Blocked: 2}},
	}
	ips := mergeAppSecIntoSecurity(s, sum, "block", 0, 19)

	e := s.WafEngines
	if e == nil || e.AppSec.Hits != 5 || e.AppSec.Bans != 1 || e.AppSec.Events != 6 || e.AppSec.Mode != "block" {
		t.Fatalf("appsec engine: %+v", e)
	}
	if e.Coraza.Events != 2 || e.Coraza.EnabledHosts != 0 || e.Coraza.TotalHosts != 19 || e.EventsTotal != 8 {
		t.Fatalf("coraza engine / total: %+v", e)
	}
	if s.WafTimeseries[0].AppSec != 4 || s.WafTimeseries[1].AppSec != 2 || s.WafTimeseries[0].Blocked != 40 {
		t.Fatalf("appsec series must not touch the 403 series: %+v", s.WafTimeseries)
	}
	if len(s.TopAttackTypes) != 3 || s.TopAttackTypes[0].Rule != "crowdsecurity/vpatch-env-access" || s.TopAttackTypes[0].Engine != "appsec" || s.TopAttackTypes[1].Engine != "coraza" {
		t.Fatalf("top attack types: %+v", s.TopAttackTypes)
	}
	if len(s.TopAttackIPs) != 2 || s.TopAttackIPs[0].RemoteIP != "203.0.113.1" || s.TopAttackIPs[0].Count != 6 || s.TopAttackIPs[0].DistinctHosts != 2 || !s.TopAttackIPs[0].LastSeen.Equal(t0.Add(30*time.Minute)) {
		t.Fatalf("top ips merged: %+v", s.TopAttackIPs)
	}
	if len(s.TopAttackedPaths) != 2 || s.TopAttackedPaths[0].Count != 5 {
		t.Fatalf("top paths merged: %+v", s.TopAttackedPaths)
	}
	if ips["203.0.113.1"] != 4 || ips["203.0.113.2"] != 2 {
		t.Fatalf("appsec ip counts for the country fold: %v", ips)
	}
}

func TestHostEngine(t *testing.T) {
	cases := []struct {
		coraza bool
		mode   string
		want   string
	}{
		{false, "block", "appsec"}, {false, "detect", "appsec"}, {true, "block", "coraza+appsec"},
		{true, "disabled", "coraza"}, {false, "disabled", "none"}, {false, "", "none"},
	}
	for _, c := range cases {
		if got := hostEngine(c.coraza, c.mode); got != c.want {
			t.Fatalf("hostEngine(%v,%q)=%q want %q", c.coraza, c.mode, got, c.want)
		}
	}
}
