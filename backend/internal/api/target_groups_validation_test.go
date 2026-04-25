package api

import (
	"strings"
	"testing"
)

// v1.3.13: the SpansMultipleClasses rejection now ships actionable
// guidance instead of just "cannot mix different status classes".
// Operators reading the toast should see the three legal shapes
// plus at least the per-backend workaround hint without leaving
// the page.
func TestExpectStatusMixedClassesMessageHasGuidance(t *testing.T) {
	req := &targetGroupRequest{
		Name:                    "tg",
		Protocol:                "http",
		HealthCheckExpectStatus: "200,401",
	}
	_, _, msg := req.toTargetGroup(0)
	if msg == "" {
		t.Fatal("expected a validation message for mixed-class expect_status")
	}
	mustContain := []string{
		"different status classes",
		"single code",
		"comma list within ONE class",
		"numeric range within ONE class",
		"Plex",
		"Jellyfin",
		"disable active checks",
		"troubleshooting.md",
	}
	for _, s := range mustContain {
		if !strings.Contains(msg, s) {
			t.Errorf("message missing actionable hint %q\n--- full message ---\n%s", s, msg)
		}
	}
}

// Single-class inputs still parse cleanly. Smoke tests for the
// happy path so the v1.3.13 message change does not regress
// non-mixed-class validation.
func TestExpectStatusSingleClassAccepted(t *testing.T) {
	cases := []string{"200", "401", "200,204", "200-299", "400-403"}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			req := &targetGroupRequest{
				Name:                    "tg",
				Protocol:                "http",
				HealthCheckExpectStatus: in,
			}
			_, _, msg := req.toTargetGroup(0)
			if msg != "" {
				t.Errorf("input %q rejected unexpectedly: %s", in, msg)
			}
		})
	}
}
