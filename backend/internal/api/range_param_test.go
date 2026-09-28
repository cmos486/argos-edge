package api

import (
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestParseRangeParam(t *testing.T) {
	for s, want := range map[string]time.Duration{"15m": 15 * time.Minute, "24h": 24 * time.Hour, " 7D ": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour} {
		if d, ok := parseRangeParam(s); !ok || d != want {
			t.Errorf("parseRangeParam(%q) = %v %v, want %v", s, d, ok, want)
		}
	}
	for _, s := range []string{"", "2h", "junk", "1w"} {
		if _, ok := parseRangeParam(s); ok {
			t.Errorf("parseRangeParam(%q) accepted", s)
		}
	}
}

// TestParseLogFilterRange (v1.3.42.3): `range` sets From when from is
// absent; an explicit from wins.
func TestParseLogFilterRange(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/logs/stats?range=6h", nil)
	f := parseLogFilter(r)
	if d := time.Since(f.From); d < 6*time.Hour-time.Minute || d > 6*time.Hour+time.Minute {
		t.Fatalf("range=6h gave From %v ago", d)
	}
	r = httptest.NewRequest("GET", "/api/logs/stats?range=6h&from=2026-09-01T00:00:00Z", nil)
	if f := parseLogFilter(r); !f.From.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("explicit from must win: %v", f.From)
	}
	if f := parseLogFilter(httptest.NewRequest("GET", "/api/logs/stats?range=junk", nil)); !f.From.IsZero() {
		t.Fatalf("unknown range must be ignored: %v", f.From)
	}
}

// TestParseThreatsFilterQAlias (v1.3.42.3): `q` is `search`.
func TestParseThreatsFilterQAlias(t *testing.T) {
	if f := parseThreatsFilter(url.Values{"q": {"Probing"}}); f.Search != "probing" {
		t.Fatalf("q alias: %+v", f)
	}
	if f := parseThreatsFilter(url.Values{"q": {"a"}, "search": {"b"}}); f.Search != "b" {
		t.Fatalf("search must win over q: %+v", f)
	}
}
