package logs

import (
	"encoding/json"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

func fillErrorFrom(t *testing.T, line string) models.LogEntry {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		t.Fatal(err)
	}
	var e models.LogEntry
	fillError(&e, raw)
	return e
}

func TestFillErrorHostDomainAttribution(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"acme identifier", `{"level":"error","logger":"tls.obtain","msg":"could not get certificate","identifier":"App.Example.com"}`, "app.example.com"},
		{"identifiers list", `{"level":"info","logger":"tls","msg":"renewing","identifiers":["b.example.com","c.example.com"]}`, "b.example.com"},
		{"request host with port", `{"level":"error","logger":"http.log.error","msg":"no upstreams available","request":{"host":"Site.Example.com:443","uri":"/"}}`, "site.example.com"},
		{"health checker: upstream only, unattributed", `{"level":"info","logger":"http.handlers.reverse_proxy.health_checker.active","msg":"HTTP request failed","host":"192.0.2.10:3001"}`, ""},
		{"tls housekeeping, unattributed", `{"level":"info","logger":"tls","msg":"finished cleaning storage units"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := fillErrorFrom(t, c.line)
			if e.HostDomain != c.want {
				t.Errorf("host_domain: want %q, got %q", c.want, e.HostDomain)
			}
		})
	}
}

func TestFillErrorMessageShapeUnchanged(t *testing.T) {
	e := fillErrorFrom(t, `{"level":"error","logger":"tls.obtain","msg":"could not get certificate","error":"boom","identifier":"a.example.com"}`)
	if e.Message != "tls.obtain: could not get certificate -- boom" || e.Level != "error" {
		t.Fatalf("message/level shape changed: %q / %q", e.Message, e.Level)
	}
}
