package notifications

import (
	"strings"
	"testing"
	"time"
)

// sampleEvent returns an event whose Type, HostDomain, and Message all
// carry characters that MarkdownV2 / HTML treat as syntax. The
// underscore in `config_change` is the v1.3.34.1 root-cause regression
// case: MarkdownV2 reads it as "begin italic" and the LAPI bot returns
// 400 byte-offset errors.
func sampleEvent() *Event {
	return &Event{
		Type:       EvtConfigChange,
		Severity:   SeverityInfo,
		HostDomain: "host_with_under.example.com",
		Timestamp:  time.Date(2026, 4, 27, 18, 0, 0, 0, time.UTC),
		Message:    "rate < 100 & body_size > 4kb (panel update)",
	}
}

// TestTelegramDefaultTemplateRendersValidHTML asserts the v1.3.34.1
// default produces well-formed HTML with <b>/<code> tags and dynamic
// fields routed through escapeHTML.
func TestTelegramDefaultTemplateRendersValidHTML(t *testing.T) {
	out, err := Render("", TypeTelegram, sampleEvent())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Tags present
	if !strings.Contains(out, "<b>config_change</b>") {
		t.Errorf("expected <b>config_change</b>, got: %q", out)
	}
	if !strings.Contains(out, "<code>host_with_under.example.com</code>") {
		t.Errorf("expected <code>host_with_under.example.com</code>, got: %q", out)
	}
	// Underscore stays literal (HTML doesn't treat it as syntax)
	if strings.Contains(out, `\_`) {
		t.Errorf("HTML output should NOT contain MarkdownV2 backslash-escape, got: %q", out)
	}
	// Dynamic field with < > & is HTML-escaped
	for _, want := range []string{"&lt;", "&gt;", "&amp;"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in escaped Message, got: %q", want, out)
		}
	}
	// Severity emoji prefix preserved
	if !strings.HasPrefix(out, "[INFO]") {
		t.Errorf("expected severityEmoji prefix, got: %q", out)
	}
}

// TestEscapeHTMLOnDynamicFields asserts the escapeHTML pipeline rewrites
// every HTML-special char in a value passed through it, so operator-
// supplied event payloads cannot inject markup.
func TestEscapeHTMLOnDynamicFields(t *testing.T) {
	ev := &Event{
		Type:       "test",
		Severity:   SeverityInfo,
		HostDomain: "<script>alert(1)</script>",
		Message:    "a & b < c > d",
		Timestamp:  time.Now(),
	}
	out, err := Render("", TypeTelegram, ev)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "<script>") {
		t.Errorf("escapeHTML failed: raw <script> tag in output: %q", out)
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("expected escaped <script> in HostDomain, got: %q", out)
	}
	if !strings.Contains(out, "a &amp; b &lt; c &gt; d") {
		t.Errorf("expected fully-escaped Message, got: %q", out)
	}
}

// TestEscapeMDStillWorks regression-checks the existing escapeMD
// pipeline so operators with custom MarkdownV2 templates pinned via
// {{ ... | escapeMD }} keep working after v1.3.34.1.
func TestEscapeMDStillWorks(t *testing.T) {
	custom := `*{{ .Type | escapeMD }}* {{ .Message | escapeMD }}`
	out, err := Render(custom, TypeTelegram, sampleEvent())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Underscore IS escaped in MarkdownV2
	if !strings.Contains(out, `config\_change`) {
		t.Errorf("expected MarkdownV2 backslash-escape on underscore, got: %q", out)
	}
	// Paren and greater-than are in the MarkdownV2 escape set
	for _, want := range []string{`\(`, `\)`, `\>`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected MarkdownV2 escape %q, got: %q", want, out)
		}
	}
}
