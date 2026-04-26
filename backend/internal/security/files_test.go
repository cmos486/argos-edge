package security

import (
	"strings"
	"testing"
)

// formatProfilesYAML is the pure-string formatter wrapped by
// WriteProfilesYAML; testing it directly avoids needing SharedDir
// on the test host. The DB query + file write paths in
// WriteProfilesYAML are exercised by scripts/smoke/true-detect-
// mode.sh against the live stack.

func TestFormatProfilesYAML_zeroHosts_writesPlaceholder(t *testing.T) {
	body := formatProfilesYAML(nil)
	if !strings.Contains(body, "no hosts with true_detect_mode=true") {
		t.Fatalf("placeholder missing: %s", body)
	}
	if strings.Contains(body, "name: argos_true_detect_mode") {
		t.Fatalf("zero-hosts file should not emit a profile entry: %s", body)
	}
}

func TestFormatProfilesYAML_oneHost_emitsFilter(t *testing.T) {
	body := formatProfilesYAML([]string{"detect.example.com"})
	expected := []string{
		"name: argos_true_detect_mode",
		// Both meta keys are checked: inband WAF alerts use
		// target_fqdn while outofband-scenario alerts use
		// target_host. v1.3.29 smoke surfaced the divergence.
		`(.Key == "target_host" || .Key == "target_fqdn")`,
		`.Value in ["detect.example.com"]`,
		"decisions: []",
		"on_success: break",
	}
	for _, s := range expected {
		if !strings.Contains(body, s) {
			t.Fatalf("expected substring %q in output:\n%s", s, body)
		}
	}
}

func TestFormatProfilesYAML_filterDoesNotGateOnScenarioName(t *testing.T) {
	// v1.3.29 mid-impl finding: gating on
	// Alert.GetScenario() contains "appsec" missed inband WAF
	// alerts whose scenario string is the human-readable
	// "anomaly score block: ...". Pin that this gate stays
	// removed.
	body := formatProfilesYAML([]string{"foo.example"})
	if strings.Contains(body, `Alert.GetScenario()`) {
		t.Fatalf("scenario-name gate must NOT be present:\n%s", body)
	}
}

func TestFormatProfilesYAML_multipleHostsInListJoined(t *testing.T) {
	// Caller guarantees sort (SQL ORDER BY); formatter just joins.
	body := formatProfilesYAML([]string{"alpha.example", "mid.example", "zebra.example"})
	if !strings.Contains(body,
		`["alpha.example", "mid.example", "zebra.example"]`) {
		t.Fatalf("expected sorted in-list:\n%s", body)
	}
}

func TestFormatProfilesYAML_idempotent(t *testing.T) {
	a := formatProfilesYAML([]string{"foo.example"})
	b := formatProfilesYAML([]string{"foo.example"})
	if a != b {
		t.Fatalf("formatter not deterministic between calls")
	}
}

func TestFormatProfilesYAML_quoteEscape(t *testing.T) {
	// RFC 1035 hostnames cannot contain double quotes, but the
	// escape path still runs to defend against a future schema
	// change that loosens the column type.
	body := formatProfilesYAML([]string{`weird"host`})
	if !strings.Contains(body, `"weird\"host"`) {
		t.Fatalf("quote not escaped:\n%s", body)
	}
}
