package appsec

import (
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
)

// alert is a tiny constructor for the test cases. We only set the
// fields classifyOutcome reads.
func alertAt(ts time.Time, decisions ...crowdsec.AlertDecision) crowdsec.Alert {
	return crowdsec.Alert{
		Kind:          "waf",
		Scenario:      "anomaly score block",
		CreatedAtText: ts.UTC().Format(time.RFC3339),
		Decisions:     decisions,
	}
}

func TestClassifyOutcomeDecisionWins(t *testing.T) {
	// An alert with a decision is always blocked, regardless of
	// mode / boundary -- decision is the ground truth signal.
	a := alertAt(time.Now(), crowdsec.AlertDecision{Type: "ban"})
	if !classifyOutcome(a, "detect", "block", time.Now().Add(-1*time.Hour)) {
		t.Error("alert with decision must be blocked even when current mode is detect")
	}
}

func TestClassifyOutcomeNoBoundaryUsesCurrentMode(t *testing.T) {
	a := alertAt(time.Now())
	if !classifyOutcome(a, "block", "", time.Time{}) {
		t.Error("no boundary + mode=block should be blocked")
	}
	if classifyOutcome(a, "detect", "", time.Time{}) {
		t.Error("no boundary + mode=detect should be logged")
	}
}

// The exact bug this release fixes: detect window of historical
// alerts must NOT be reclassified as blocked after a detect->block
// swap.
func TestClassifyOutcomeHistoricalDetectStaysLogged(t *testing.T) {
	swap := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	old := alertAt(swap.Add(-30 * time.Minute)) // pre-swap, detect mode
	if classifyOutcome(old, "block", "detect", swap) {
		t.Error("alert from before the swap (detect mode) must NOT be reclassified as blocked")
	}
}

// Conversely, post-swap alerts in block mode count as blocked even
// without a decision in the alert payload (CRS hits typically don't
// emit one).
func TestClassifyOutcomePostSwapBlocked(t *testing.T) {
	swap := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	fresh := alertAt(swap.Add(5 * time.Minute))
	if !classifyOutcome(fresh, "block", "detect", swap) {
		t.Error("alert AFTER the swap into block mode must count as blocked")
	}
}

// Reverse swap: block -> detect. Pre-swap block hits stay blocked,
// post-swap detect hits become logged.
func TestClassifyOutcomeBlockToDetectSwap(t *testing.T) {
	swap := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	preBlock := alertAt(swap.Add(-1 * time.Hour))
	postDetect := alertAt(swap.Add(1 * time.Hour))

	if !classifyOutcome(preBlock, "detect", "block", swap) {
		t.Error("pre-swap block-mode hit must remain blocked after swap to detect")
	}
	if classifyOutcome(postDetect, "detect", "block", swap) {
		t.Error("post-swap detect-mode hit must be logged")
	}
}

func TestClassifyOutcomeDisabledIsAlwaysLogged(t *testing.T) {
	a := alertAt(time.Now())
	if classifyOutcome(a, "disabled", "", time.Time{}) {
		t.Error("mode=disabled must be logged")
	}
}

// At-the-boundary timestamp uses CURRENT mode (not prevMode). The
// swap moment defines "from now on, current mode applies".
func TestClassifyOutcomeBoundaryEqualUsesCurrentMode(t *testing.T) {
	swap := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)
	atSwap := alertAt(swap)
	if !classifyOutcome(atSwap, "block", "detect", swap) {
		t.Error("alert exactly at the swap timestamp should attribute to the current mode (block)")
	}
}

// Unparseable CreatedAt falls back to current mode -- defensive
// behaviour; the panel never silently misclassifies an alert it
// can't read the timestamp of.
func TestClassifyOutcomeUnparseableTimestampUsesCurrentMode(t *testing.T) {
	a := crowdsec.Alert{Kind: "waf", CreatedAtText: "not-a-timestamp"}
	if !classifyOutcome(a, "block", "detect", time.Now()) {
		t.Error("unparseable timestamp + current mode block should still attribute as blocked")
	}
}
