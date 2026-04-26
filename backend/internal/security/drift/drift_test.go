package drift

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/security/scenarios"
)

// memDB returns a fresh in-memory sqlite with the settings table
// schema present. The db package's UpsertSetting / GetSettingValue
// rely on `settings(key TEXT PRIMARY KEY, value TEXT)`.
func memDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.Exec(`
		CREATE TABLE settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return d
}

func TestReadActualThreshold_parsesSecAction(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "appsec-rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `appsec_rules:
  - SecAction "id:900110,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=22"
  - SecAction "id:900111,phase:1,pass,nolog,setvar:tx.outbound_anomaly_score_threshold=7"
`
	if err := os.WriteFile(filepath.Join(rulesDir, "argos-tuning.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Detector{mountPath: dir}
	in, out, ok := d.readActualThreshold()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if in != 22 || out != 7 {
		t.Fatalf("parsed wrong values: in=%d out=%d", in, out)
	}
}

func TestReadActualThreshold_missingFileReturnsNotOk(t *testing.T) {
	d := &Detector{mountPath: t.TempDir()}
	if _, _, ok := d.readActualThreshold(); ok {
		t.Fatal("expected ok=false when file missing")
	}
}

func TestReadActualThreshold_partialFileReturnsNotOk(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "appsec-rules")
	_ = os.MkdirAll(rulesDir, 0o755)
	body := `# only inbound, outbound missing
- SecAction "id:900110,setvar:tx.inbound_anomaly_score_threshold=15"
`
	_ = os.WriteFile(filepath.Join(rulesDir, "argos-tuning.yaml"), []byte(body), 0o644)
	d := &Detector{mountPath: dir}
	if _, _, ok := d.readActualThreshold(); ok {
		t.Fatal("expected ok=false when one threshold missing -- caller treats as no-evidence")
	}
}

func TestComputeScenarioDrift_emptyExpectedNoDrift(t *testing.T) {
	d := &Detector{
		db: memDB(t),
		// scenariosFn intentionally returns "available with one
		// scenario installed". With no panel-disabled set, drift
		// must be false even though a scenario is present.
		scenariosFn: func(_ string) scenarios.ReadResult {
			return scenarios.ReadResult{
				IsAvailable: true,
				Scenarios: []scenarios.Scenario{
					{ShortName: "http-bad-user-agent", CanonicalName: "crowdsecurity/http-bad-user-agent"},
				},
			}
		},
	}
	got := d.computeScenarioDrift(context.Background())
	if got.DriftDetected {
		t.Fatal("expected no drift with empty expected set")
	}
}

func TestComputeScenarioDrift_diskStillHasDisabledScenario(t *testing.T) {
	dbConn := memDB(t)
	if err := db.UpsertSetting(context.Background(), dbConn, "appsec.disabled_scenarios",
		"crowdsecurity/http-bad-user-agent"); err != nil {
		t.Fatal(err)
	}
	d := &Detector{
		db: dbConn,
		scenariosFn: func(_ string) scenarios.ReadResult {
			return scenarios.ReadResult{
				IsAvailable: true,
				Scenarios: []scenarios.Scenario{
					{ShortName: "http-bad-user-agent", CanonicalName: "crowdsecurity/http-bad-user-agent"},
					{ShortName: "http-crawl-non_statics", CanonicalName: "crowdsecurity/http-crawl-non_statics"},
				},
			}
		},
	}
	got := d.computeScenarioDrift(context.Background())
	if !got.DriftDetected {
		t.Fatal("expected drift: panel disabled, fs still has it")
	}
	if len(got.ActuallyEnabled) != 1 || got.ActuallyEnabled[0] != "crowdsecurity/http-bad-user-agent" {
		t.Fatalf("unexpected actually_enabled: %+v", got.ActuallyEnabled)
	}
}

func TestComputeScenarioDrift_diskRemovedNoDrift(t *testing.T) {
	dbConn := memDB(t)
	_ = db.UpsertSetting(context.Background(), dbConn, "appsec.disabled_scenarios",
		"crowdsecurity/http-bad-user-agent")
	d := &Detector{
		db: dbConn,
		scenariosFn: func(_ string) scenarios.ReadResult {
			// Scenario is no longer installed -> setup-appsec.sh
			// has consumed the sentinel, drift cleared.
			return scenarios.ReadResult{
				IsAvailable: true,
				Scenarios: []scenarios.Scenario{
					{ShortName: "http-crawl-non_statics", CanonicalName: "crowdsecurity/http-crawl-non_statics"},
				},
			}
		},
	}
	got := d.computeScenarioDrift(context.Background())
	if got.DriftDetected {
		t.Fatalf("expected no drift after fs sync, got %+v", got)
	}
}

func TestComputeScenarioDrift_mountMissingNoDrift(t *testing.T) {
	dbConn := memDB(t)
	_ = db.UpsertSetting(context.Background(), dbConn, "appsec.disabled_scenarios",
		"crowdsecurity/foo")
	d := &Detector{
		db: dbConn,
		scenariosFn: func(_ string) scenarios.ReadResult {
			return scenarios.ReadResult{IsAvailable: false}
		},
	}
	got := d.computeScenarioDrift(context.Background())
	if got.DriftDetected {
		t.Fatal("mount-missing must not surface as drift -- no evidence either way")
	}
}

func TestComputeTuningDrift_panelDefaultsAndNoFile(t *testing.T) {
	dbConn := memDB(t)
	d := &Detector{db: dbConn, mountPath: t.TempDir()}
	got := d.computeTuningDrift(context.Background())
	if got.DriftDetected {
		t.Fatal("default panel + missing tuning file must not surface drift")
	}
	if got.ExpectedInbound != 15 || got.ExpectedOutbound != 4 {
		t.Fatalf("expected v1.3.19 defaults, got %+v", got)
	}
}

func TestComputeTuningDrift_panelChangedFileNotYet(t *testing.T) {
	dbConn := memDB(t)
	_ = db.UpsertSetting(context.Background(), dbConn, "appsec.inbound_threshold", "22")
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "appsec-rules")
	_ = os.MkdirAll(rulesDir, 0o755)
	body := `- SecAction "setvar:tx.inbound_anomaly_score_threshold=15"
- SecAction "setvar:tx.outbound_anomaly_score_threshold=4"
`
	_ = os.WriteFile(filepath.Join(rulesDir, "argos-tuning.yaml"), []byte(body), 0o644)
	d := &Detector{db: dbConn, mountPath: dir}
	got := d.computeTuningDrift(context.Background())
	if !got.DriftDetected {
		t.Fatalf("expected drift: panel=22, fs=15; got %+v", got)
	}
	if got.ExpectedInbound != 22 || got.ActualInbound != 15 {
		t.Fatalf("wrong values: %+v", got)
	}
}

func TestComputeTuningDrift_synced(t *testing.T) {
	dbConn := memDB(t)
	_ = db.UpsertSetting(context.Background(), dbConn, "appsec.inbound_threshold", "22")
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "appsec-rules")
	_ = os.MkdirAll(rulesDir, 0o755)
	body := `- SecAction "setvar:tx.inbound_anomaly_score_threshold=22"
- SecAction "setvar:tx.outbound_anomaly_score_threshold=4"
`
	_ = os.WriteFile(filepath.Join(rulesDir, "argos-tuning.yaml"), []byte(body), 0o644)
	d := &Detector{db: dbConn, mountPath: dir}
	got := d.computeTuningDrift(context.Background())
	if got.DriftDetected {
		t.Fatalf("synced state must not report drift: %+v", got)
	}
}

func TestCheckOnce_persistsAndLoadStateRoundTrip(t *testing.T) {
	dbConn := memDB(t)
	_ = db.UpsertSetting(context.Background(), dbConn, "appsec.disabled_scenarios",
		"crowdsecurity/http-bad-user-agent")
	d := &Detector{
		db:        dbConn,
		mountPath: t.TempDir(),
		scenariosFn: func(_ string) scenarios.ReadResult {
			return scenarios.ReadResult{
				IsAvailable: true,
				Scenarios: []scenarios.Scenario{
					{ShortName: "http-bad-user-agent", CanonicalName: "crowdsecurity/http-bad-user-agent"},
				},
			}
		},
	}
	d.CheckOnce(context.Background())

	scn, tn := LoadState(context.Background(), dbConn)
	if !scn.DriftDetected {
		t.Fatal("scenarios drift not persisted")
	}
	if scn.LastCheckAt == "" {
		t.Fatal("scenarios last_check_at empty")
	}
	if tn.LastCheckAt == "" {
		t.Fatal("tuning last_check_at empty")
	}

	// LoadState's JSON round-trip must preserve the lists.
	var roundtrip ScenarioDrift
	raw := db.GetSettingValue(context.Background(), dbConn, SettingScenariosDrift, "")
	if err := json.Unmarshal([]byte(raw), &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if roundtrip.ActuallyEnabled[0] != "crowdsecurity/http-bad-user-agent" {
		t.Fatalf("round-trip lost data: %+v", roundtrip)
	}
}

func TestLastCheckAt_picksLatest(t *testing.T) {
	a := ScenarioDrift{LastCheckAt: "2026-04-26T12:00:00Z"}
	b := TuningDrift{LastCheckAt: "2026-04-26T12:01:00Z"}
	if got := LastCheckAt(a, b); got != b.LastCheckAt {
		t.Fatalf("expected later, got %s", got)
	}
	c := ScenarioDrift{LastCheckAt: "2026-04-26T12:02:00Z"}
	if got := LastCheckAt(c, b); got != c.LastCheckAt {
		t.Fatalf("expected later, got %s", got)
	}
	if got := LastCheckAt(ScenarioDrift{}, b); got != b.LastCheckAt {
		t.Fatalf("expected fallback to non-empty, got %s", got)
	}
}
