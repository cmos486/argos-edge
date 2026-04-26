package scenarios

import (
	"os"
	"path/filepath"
	"testing"
)

// fixtureMount builds a temporary directory shaped like
// /crowdsec-state, including the symlink layout cscli writes:
//
//	<root>/scenarios/<short>.yaml -> ../hub/scenarios/<owner>/<short>.yaml
//
// Returns the root path the Reader should use.
func fixtureMount(t *testing.T, scenarios map[string]string) string {
	t.Helper()
	root := t.TempDir()
	scenariosDir := filepath.Join(root, "scenarios")
	hubDir := filepath.Join(root, "hub", "scenarios")
	if err := os.MkdirAll(scenariosDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for short, owner := range scenarios {
		// Create the hub source file.
		ownerDir := filepath.Join(hubDir, owner)
		if err := os.MkdirAll(ownerDir, 0o755); err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(ownerDir, short+".yaml")
		if err := os.WriteFile(src, []byte("name: "+owner+"/"+short+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// Symlink scenarios/<short>.yaml -> ../hub/scenarios/<owner>/<short>.yaml
		linkTarget := filepath.Join("..", "hub", "scenarios", owner, short+".yaml")
		linkPath := filepath.Join(scenariosDir, short+".yaml")
		if err := os.Symlink(linkTarget, linkPath); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestReadEmptyMountReturnsUnavailable(t *testing.T) {
	r := &Reader{MountPath: "/no-such-path-exists"}
	got := r.Read("")
	if got.IsAvailable {
		t.Fatalf("missing mount should not be available")
	}
	if len(got.Scenarios) != 0 {
		t.Fatalf("missing mount should yield empty list, got %d", len(got.Scenarios))
	}
}

func TestReadResolvesCanonicalNamesViaSymlink(t *testing.T) {
	root := fixtureMount(t, map[string]string{
		"http-bad-user-agent": "crowdsecurity",
		"http-probing":        "crowdsecurity",
		"argos-tuning":        "argos-edge",
	})
	r := &Reader{MountPath: root}
	got := r.Read("")
	if !got.IsAvailable {
		t.Fatalf("expected available, got %+v", got)
	}
	if len(got.Scenarios) != 3 {
		t.Fatalf("expected 3 scenarios, got %d", len(got.Scenarios))
	}
	// Sorted by canonical name; argos-edge/argos-tuning <
	// crowdsecurity/http-bad-user-agent < crowdsecurity/http-probing.
	if got.Scenarios[0].CanonicalName != "argos-edge/argos-tuning" {
		t.Fatalf("first = %q", got.Scenarios[0].CanonicalName)
	}
	if got.Scenarios[1].Source != "crowdsecurity" {
		t.Fatalf("second source = %q", got.Scenarios[1].Source)
	}
	if got.Scenarios[1].ShortName != "http-bad-user-agent" {
		t.Fatalf("second short = %q", got.Scenarios[1].ShortName)
	}
}

func TestReadAppliesDisabledSet(t *testing.T) {
	root := fixtureMount(t, map[string]string{
		"http-bad-user-agent": "crowdsecurity",
		"http-probing":        "crowdsecurity",
	})
	r := &Reader{MountPath: root}
	csv := "crowdsecurity/http-bad-user-agent"
	got := r.Read(csv)
	for _, s := range got.Scenarios {
		want := s.CanonicalName == "crowdsecurity/http-bad-user-agent"
		if s.Disabled != want {
			t.Fatalf("disabled mismatch for %q: got %v want %v",
				s.CanonicalName, s.Disabled, want)
		}
	}
}

// TestReadAcceptsShortNameInDisabledCSV: operators tend to type
// "appsec-native" rather than the canonical
// "crowdsecurity/appsec-native". The reader tolerates both forms
// against the same scenario.
func TestReadAcceptsShortNameInDisabledCSV(t *testing.T) {
	root := fixtureMount(t, map[string]string{
		"appsec-native": "crowdsecurity",
	})
	r := &Reader{MountPath: root}
	got := r.Read("appsec-native") // bare, not canonical
	if len(got.Scenarios) != 1 {
		t.Fatalf("expected 1 scenario, got %d", len(got.Scenarios))
	}
	if !got.Scenarios[0].Disabled {
		t.Fatalf("bare short-name in CSV should still mark disabled")
	}
}

// TestReadIgnoresNonYAMLFiles: .index.json, .DS_Store, etc. live
// in the mount sometimes; we only enumerate .yaml/.yml.
func TestReadIgnoresNonYAMLFiles(t *testing.T) {
	root := fixtureMount(t, map[string]string{
		"http-probing": "crowdsecurity",
	})
	scenariosDir := filepath.Join(root, "scenarios")
	if err := os.WriteFile(
		filepath.Join(scenariosDir, ".index.json"),
		[]byte("{}"), 0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(scenariosDir, "README.md"),
		[]byte("# notes"), 0o644,
	); err != nil {
		t.Fatal(err)
	}
	r := &Reader{MountPath: root}
	got := r.Read("")
	if len(got.Scenarios) != 1 {
		t.Fatalf("expected 1 yaml scenario only, got %d: %+v",
			len(got.Scenarios), got.Scenarios)
	}
}

func TestFormatDisabledCSVDedupesAndSorts(t *testing.T) {
	got := FormatDisabledCSV([]string{
		"  crowdsecurity/foo  ",
		"crowdsecurity/foo",
		"argos/bar",
		"",
		"crowdsecurity/baz",
	})
	want := "argos/bar,crowdsecurity/baz,crowdsecurity/foo"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
