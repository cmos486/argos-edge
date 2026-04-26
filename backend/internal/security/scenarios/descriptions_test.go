package scenarios

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDescriptionsLoader_emptyWhenFileMissing(t *testing.T) {
	d := &DescriptionsLoader{Path: filepath.Join(t.TempDir(), "missing.json")}
	if got := d.Get("crowdsecurity/foo"); got != "" {
		t.Fatalf("expected empty for missing file, got %q", got)
	}
	if d.Len() != 0 {
		t.Fatalf("expected len 0 for missing file, got %d", d.Len())
	}
}

func TestDescriptionsLoader_returnsKnownDescription(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "argos-scenarios-index.json")
	body := `{"crowdsecurity/CVE-2017-9841":"Detect CVE-2017-9841 exploits","crowdsecurity/http-probing":"Detect HTTP probing"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &DescriptionsLoader{Path: path}
	if got := d.Get("crowdsecurity/CVE-2017-9841"); got != "Detect CVE-2017-9841 exploits" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := d.Get("crowdsecurity/http-probing"); got != "Detect HTTP probing" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := d.Get("crowdsecurity/unknown"); got != "" {
		t.Fatalf("expected empty for unknown name, got %q", got)
	}
	if d.Len() != 2 {
		t.Fatalf("len %d != 2", d.Len())
	}
}

func TestDescriptionsLoader_reloadsOnMtimeAdvance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idx.json")
	if err := os.WriteFile(path, []byte(`{"a":"first"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &DescriptionsLoader{Path: path}
	if got := d.Get("a"); got != "first" {
		t.Fatalf("unexpected initial: %q", got)
	}
	// Advance file mtime. Sleep long enough that the OS-level
	// mtime resolution (1s on some filesystems) registers the
	// change.
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(path, []byte(`{"a":"second","b":"new"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := d.Get("a"); got != "second" {
		t.Fatalf("did not reload on mtime advance: got %q", got)
	}
	if got := d.Get("b"); got != "new" {
		t.Fatalf("new key missing after reload: %q", got)
	}
}

func TestDescriptionsLoader_malformedFileLeavesPriorMapIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idx.json")
	if err := os.WriteFile(path, []byte(`{"a":"keep"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &DescriptionsLoader{Path: path}
	if got := d.Get("a"); got != "keep" {
		t.Fatalf("initial load: %q", got)
	}
	// Overwrite with invalid JSON. The reload error should be
	// logged, but the prior in-memory map should survive.
	time.Sleep(1100 * time.Millisecond)
	if err := os.WriteFile(path, []byte(`{not valid json`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := d.Get("a"); got != "keep" {
		t.Fatalf("malformed reload should not blank prior map: got %q", got)
	}
}

func TestDescriptionsLoader_nilSafe(t *testing.T) {
	var d *DescriptionsLoader
	if got := d.Get("anything"); got != "" {
		t.Fatalf("nil receiver Get should return empty, got %q", got)
	}
	if got := d.Len(); got != 0 {
		t.Fatalf("nil receiver Len should return 0, got %d", got)
	}
}

func TestReader_emitsDescriptionWhenDescriptionsSet(t *testing.T) {
	mountDir := t.TempDir()
	scenariosDir := filepath.Join(mountDir, "scenarios")
	if err := os.MkdirAll(scenariosDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create a fake symlink-ish file. Reader uses os.Readlink to
	// recover the owner; if Readlink fails (regular file), it
	// falls back to ShortName as CanonicalName.
	if err := os.WriteFile(filepath.Join(scenariosDir, "test-rule.yaml"), []byte("name: test"), 0o644); err != nil {
		t.Fatal(err)
	}

	descPath := filepath.Join(t.TempDir(), "idx.json")
	if err := os.WriteFile(descPath, []byte(`{"test-rule":"A test scenario"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Reader{
		MountPath:    mountDir,
		Descriptions: &DescriptionsLoader{Path: descPath},
	}
	res := r.Read("")
	if !res.IsAvailable {
		t.Fatal("expected scenarios to be available")
	}
	if len(res.Scenarios) != 1 {
		t.Fatalf("want 1 scenario, got %d", len(res.Scenarios))
	}
	if got := res.Scenarios[0].Description; got != "A test scenario" {
		t.Fatalf("description not enriched: got %q", got)
	}
}

func TestReader_emptyDescriptionWhenLoaderNil(t *testing.T) {
	mountDir := t.TempDir()
	scenariosDir := filepath.Join(mountDir, "scenarios")
	_ = os.MkdirAll(scenariosDir, 0o755)
	_ = os.WriteFile(filepath.Join(scenariosDir, "x.yaml"), []byte("name: x"), 0o644)
	r := &Reader{MountPath: mountDir, Descriptions: nil}
	res := r.Read("")
	if len(res.Scenarios) != 1 {
		t.Fatalf("want 1, got %d", len(res.Scenarios))
	}
	if res.Scenarios[0].Description != "" {
		t.Fatalf("expected empty description, got %q", res.Scenarios[0].Description)
	}
}
