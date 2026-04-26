package publicip

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"
)

// newDetectorWithURL spins up an in-memory settings table and seeds
// the detect-URL setting. Helper kept private so production code
// always goes through New() + Start().
func newDetectorWithURL(t *testing.T, url string) *Detector {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec(`
		CREATE TABLE settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)`,
		SettingDetectURL, url); err != nil {
		t.Fatal(err)
	}
	return New(d)
}

func TestDetectorParsesIpifyJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"203.0.113.7"}`))
	}))
	defer srv.Close()

	d := newDetectorWithURL(t, srv.URL)
	if err := d.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := d.Get(); got != "203.0.113.7" {
		t.Fatalf("expected 203.0.113.7, got %q", got)
	}
}

func TestDetectorParsesPlaintext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("198.51.100.42\n"))
	}))
	defer srv.Close()
	d := newDetectorWithURL(t, srv.URL)
	if err := d.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := d.Get(); got != "198.51.100.42" {
		t.Fatalf("expected 198.51.100.42, got %q", got)
	}
}

func TestDetectorRejectsNonIPBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>not an ip</html>"))
	}))
	defer srv.Close()
	d := newDetectorWithURL(t, srv.URL)
	err := d.refreshOnce(context.Background())
	if err == nil {
		t.Fatal("expected error on non-IP body")
	}
	if d.Get() != "" {
		t.Fatalf("cache must stay empty after parse failure, got %q", d.Get())
	}
}

// TestDetectorEmptyURLDisablesPolling: setting the detect URL to
// "" leaves the cache untouched -- no HTTP, no error. Operators
// who want to disable detection set the setting to empty.
func TestDetectorEmptyURLDisablesPolling(t *testing.T) {
	d := newDetectorWithURL(t, "")
	if err := d.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.Get() != "" {
		t.Fatalf("expected empty cache when disabled, got %q", d.Get())
	}
}

func TestDetectorSurvivesUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := newDetectorWithURL(t, srv.URL)
	if err := d.refreshOnce(context.Background()); err == nil {
		t.Fatal("expected error on 500")
	}
	st := d.Status(context.Background())
	if st.LastError == "" {
		t.Fatal("expected LastError to be populated")
	}
}

// TestLoadCachedRehydratesFromSettings: a fresh boot should pick
// up the previously-detected IP from settings before the first
// poll runs, so /api readers see something during the warm-up
// window.
func TestLoadCachedRehydratesFromSettings(t *testing.T) {
	d := newDetectorWithURL(t, "")
	// Seed settings as if a prior poll had succeeded.
	if _, err := d.db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)`,
		SettingKey, "192.0.2.99"); err != nil {
		t.Fatal(err)
	}
	d.LoadCached(context.Background())
	if d.Get() != "192.0.2.99" {
		t.Fatalf("expected rehydrated 192.0.2.99, got %q", d.Get())
	}
}
