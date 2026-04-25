package crowdsec

import (
	"encoding/json"
	"testing"
)

// v1.3.12: Alert.WasBlocked is the canonical signal for the panel's
// AppSec metrics counters (blocked vs logged). It must answer per
// the CrowdSec alert payload, NOT the panel's current `appsec.mode`
// setting -- because that setting can change between when the alert
// fired and when the UI queries it, retroactively misclassifying
// historical hits otherwise.
func TestWasBlockedReflectsDecisionsArray(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "block-mode hit emits a ban decision",
			body: `{"id": 1, "kind": "waf", "scenario": "anomaly score block",
			        "decisions": [{"type": "ban", "duration": "4h"}]}`,
			want: true,
		},
		{
			name: "detect-mode hit emits zero decisions",
			body: `{"id": 2, "kind": "waf", "scenario": "anomaly score block",
			        "decisions": []}`,
			want: false,
		},
		{
			name: "missing decisions field defaults to logged",
			body: `{"id": 3, "kind": "waf", "scenario": "anomaly score block"}`,
			want: false,
		},
		{
			name: "captcha decision still counts as blocked",
			body: `{"id": 4, "kind": "waf", "scenario": "x",
			        "decisions": [{"type": "captcha", "duration": "1h"}]}`,
			want: true,
		},
		{
			name: "multiple decisions are still blocked",
			body: `{"id": 5, "kind": "waf", "scenario": "x",
			        "decisions": [
			          {"type": "ban", "duration": "4h"},
			          {"type": "ban", "duration": "1d"}
			        ]}`,
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var a Alert
			if err := json.Unmarshal([]byte(tc.body), &a); err != nil {
				t.Fatal(err)
			}
			if got := a.WasBlocked(); got != tc.want {
				t.Errorf("WasBlocked = %v, want %v", got, tc.want)
			}
		})
	}
}

// Decisions JSON shape from real CrowdSec /v1/alerts response must
// round-trip cleanly through the AlertDecision struct -- if the
// upstream payload changes shape we want a noisy unmarshal failure
// here, not a silent zero-value WasBlocked() that re-classifies
// blocks as logs.
func TestAlertDecisionUnmarshalRealPayload(t *testing.T) {
	body := `{
	  "id": 42, "kind": "waf", "scenario": "anomaly score block",
	  "decisions": [{
	    "id": 99,
	    "type": "ban",
	    "origin": "crowdsec",
	    "scope": "Ip",
	    "value": "203.0.113.7",
	    "duration": "4h"
	  }]
	}`
	var a Alert
	if err := json.Unmarshal([]byte(body), &a); err != nil {
		t.Fatal(err)
	}
	if len(a.Decisions) != 1 {
		t.Fatalf("decisions len=%d want 1", len(a.Decisions))
	}
	d := a.Decisions[0]
	if d.Type != "ban" || d.Scope != "Ip" || d.Value != "203.0.113.7" || d.Duration != "4h" {
		t.Errorf("decision parsed wrong: %+v", d)
	}
	if !a.WasBlocked() {
		t.Error("WasBlocked must be true for a ban decision")
	}
}
