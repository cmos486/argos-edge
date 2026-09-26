package logs

import (
	"context"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

func TestParseRulesAndDefaults(t *testing.T) {
	rules := ParseRules(DefaultDropLoggers, DefaultDropUserAgents, DefaultDropPaths)
	if len(rules) != 3 {
		t.Fatalf("default rules: %+v", rules)
	}
	if rules[0].Kind != "logger" || rules[0].Match != "http.handlers.reverse_proxy.health_checker.active" || rules[0].MsgPrefix != "HTTP request failed" {
		t.Fatalf("logger rule: %+v", rules[0])
	}
	if rules[1].Key() != "user_agent:Uptime-Kuma/" || rules[2].Key() != "user_agent:UptimeRobot/" {
		t.Fatalf("ua rules: %+v", rules[1:])
	}
	if err := ValidateRuleList("a|b, c ,,"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRuleList("|no logger"); err == nil {
		t.Fatal("bare '|' item must be rejected")
	}
}

func TestIngestFilterKeepsTransitionsAndAuditDropsRoutine(t *testing.T) {
	f := &IngestFilter{byRule: map[string]int64{}, day: utcDay(time.Now())}
	f.rules = ParseRules(DefaultDropLoggers, DefaultDropUserAgents, "/api/camera_proxy/")
	now := time.Now().UTC()
	cases := []struct {
		name string
		e    models.LogEntry
		keep bool
		rule string
	}{
		{"health checker routine", models.LogEntry{Source: models.LogCaddyError, Timestamp: now, Message: "http.handlers.reverse_proxy.health_checker.active: HTTP request failed -- dial tcp: connect: connection refused"}, false, "logger:http.handlers.reverse_proxy.health_checker.active|HTTP request failed"},
		{"health checker transition kept", models.LogEntry{Source: models.LogCaddyError, Timestamp: now, Message: "http.handlers.reverse_proxy.health_checker.active: host is unhealthy"}, true, ""},
		{"other error kept", models.LogEntry{Source: models.LogCaddyError, Timestamp: now, Message: "crowdsec.appsec: appsec component unavailable -- context deadline exceeded"}, true, ""},
		{"uptime kuma dropped", models.LogEntry{Source: models.LogCaddyAccess, Timestamp: now, UserAgent: "Uptime-Kuma/2.5.0", Path: "/"}, false, "user_agent:Uptime-Kuma/"},
		{"browser kept", models.LogEntry{Source: models.LogCaddyAccess, Timestamp: now, UserAgent: "Mozilla/5.0", Path: "/"}, true, ""},
		{"path rule", models.LogEntry{Source: models.LogCaddyAccess, Timestamp: now, UserAgent: "Mozilla/5.0", Path: "/api/camera_proxy/camera.x"}, false, "path:/api/camera_proxy/"},
		{"audit never dropped", models.LogEntry{Source: models.LogAudit, Timestamp: now, UserAgent: "Uptime-Kuma/2.5.0", Message: "login user"}, true, ""},
		{"waf never dropped", models.LogEntry{Source: models.LogWAFAudit, Timestamp: now, UserAgent: "Uptime-Kuma/2.5.0"}, true, ""},
	}
	for _, c := range cases {
		if got := f.Keep(c.e); got != c.keep {
			t.Fatalf("%s: keep=%v want %v", c.name, got, c.keep)
		}
	}
	st := f.Stats()
	if st.Total != 3 || st.ByRule["user_agent:Uptime-Kuma/"] != 1 || st.ByRule["logger:http.handlers.reverse_proxy.health_checker.active|HTTP request failed"] != 1 || st.ByRule["path:/api/camera_proxy/"] != 1 {
		t.Fatalf("counters: %+v", st)
	}
	// A new UTC day resets the day's counters; since_boot keeps counting.
	f.Keep(models.LogEntry{Source: models.LogCaddyAccess, Timestamp: now.Add(48 * time.Hour), UserAgent: "Uptime-Kuma/2.5.0"})
	st = f.Stats()
	if st.Total != 1 || st.SinceBoot != 4 || st.Date != utcDay(now.Add(48*time.Hour)) {
		t.Fatalf("day rollover: %+v", st)
	}
	// A nil filter keeps everything (panels without the wiring).
	var nilF *IngestFilter
	if !nilF.Keep(cases[0].e) {
		t.Fatal("nil filter must keep")
	}
}

func TestIngestFilterLoadPersistRestore(t *testing.T) {
	d := dbtest.Open(t)
	if _, err := d.Exec(`INSERT INTO settings(key,value) VALUES (?,?)`, SettingDropUserAgents, "Probe/"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f := NewIngestFilter(d)
	if err := f.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if rs := f.Rules(); len(rs) != 2 || rs[1].Match != "Probe/" {
		t.Fatalf("rules from settings: %+v", rs)
	}
	f.Keep(models.LogEntry{Source: models.LogCaddyAccess, Timestamp: time.Now(), UserAgent: "Probe/1"})
	f.lastPersist = time.Time{}
	f.MaybePersist(ctx)
	g := NewIngestFilter(d)
	if err := g.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if st := g.Stats(); st.Total != 1 || st.ByRule["user_agent:Probe/"] != 1 {
		t.Fatalf("counters not restored after reload: %+v", st)
	}
}
