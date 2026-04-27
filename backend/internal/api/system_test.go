package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSystemVersionReturnsAllFieldsWhenPopulated(t *testing.T) {
	h := &Handlers{
		ArgosVersion: "1.3.34.3",
		ArgosCommit:  "abc1234",
		ArgosBuiltAt: "2026-04-27T18:00:00Z",
	}
	req := httptest.NewRequest(http.MethodGet, "/api/system/version", nil)
	w := httptest.NewRecorder()
	h.SystemVersion(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}
	if got["version"] != "1.3.34.3" {
		t.Errorf("version=%q", got["version"])
	}
	if got["commit"] != "abc1234" {
		t.Errorf("commit=%q", got["commit"])
	}
	if got["built_at"] != "2026-04-27T18:00:00Z" {
		t.Errorf("built_at=%q", got["built_at"])
	}
}

// TestSystemVersionOmitsEmptyOptionals covers the dev-build path where
// the binary was compiled with `go build ./...` (no ldflags), so commit
// and built_at are empty strings. The omitempty JSON tag should drop
// them from the response entirely.
func TestSystemVersionOmitsEmptyOptionals(t *testing.T) {
	h := &Handlers{
		ArgosVersion: "1.3.34.3",
		// ArgosCommit + ArgosBuiltAt deliberately empty
	}
	req := httptest.NewRequest(http.MethodGet, "/api/system/version", nil)
	w := httptest.NewRecorder()
	h.SystemVersion(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"version":"1.3.34.3"`) {
		t.Errorf("version field missing: %s", body)
	}
	if strings.Contains(body, "commit") {
		t.Errorf("expected commit to be omitted, got: %s", body)
	}
	if strings.Contains(body, "built_at") {
		t.Errorf("expected built_at to be omitted, got: %s", body)
	}
}
