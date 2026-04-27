package notifications

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"text/template"
	"time"
)

// LegacyTelegramDefaultTemplate is the byte-exact string that the
// pre-v1.3.34.1 DefaultTemplate(TypeTelegram) returned. Stored
// verbatim in notification_channels.template for any operator who
// hit "Save" with the default visible in the UI textarea, or who
// created a channel via direct API with the default body. The
// v1.3.34.2 boot migration uses this literal as the EXACT match
// for clearing the column -- a one-byte deviation means the
// operator customised it and we MUST leave it alone.
const LegacyTelegramDefaultTemplate = `{{ .Severity | severityEmoji }} *{{ .Type }}*
{{ if .HostDomain }}host: ` + "`{{ .HostDomain }}`" + `{{ end }}
{{ .Message | escapeMD }}`

// DefaultTemplate returns the fallback template for a channel type.
// Used when a channel has no custom template set. Defaults are kept
// short and obviously formatted so the recipient can recognise the
// message even if the operator never customises them.
func DefaultTemplate(ct ChannelType) string {
	switch ct {
	case TypeWebhook:
		return `{"type":"{{ .Type }}","severity":"{{ .Severity }}","host":"{{ .HostDomain }}","message":"{{ .Message | jsonEscape }}","timestamp":"{{ .Timestamp | iso8601 }}","data":{{ .Data | json }}}`
	case TypeEmail:
		return `[argos] {{ .Severity | upper }}: {{ .Message }}

Host: {{ .HostDomain }}
Time: {{ .Timestamp | iso8601 }}
Type: {{ .Type }}

{{ .Data | jsonIndent }}
`
	case TypeTelegram:
		// HTML parse_mode is the default since v1.3.34.1: it has 3
		// special chars to escape (<, >, &) vs MarkdownV2's 18, so
		// event types like "config_change" don't trip the parser on
		// the underscore. Pair this with parse_mode=HTML in the
		// sender (see senders/telegram.go).
		return `{{ .Severity | severityEmoji }} <b>{{ .Type | escapeHTML }}</b>
{{ if .HostDomain }}host: <code>{{ .HostDomain | escapeHTML }}</code>{{ end }}
{{ .Message | escapeHTML }}`
	case TypeBrowserPush:
		// Browser push payloads are always JSON: title + body +
		// optional data. The service worker parses it and calls
		// showNotification.
		return `{"title":"argos: {{ .Type }}","body":"{{ .Message | jsonEscape }}","severity":"{{ .Severity }}","host":"{{ .HostDomain }}"}`
	}
	return `{{ .Type }}: {{ .Message }}`
}

// templateFuncs returns the function map every template compiles with.
// Kept minimal -- we want templates to stay readable, not to become
// a second DSL.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"title": func(s string) string {
			if s == "" {
				return s
			}
			return strings.ToUpper(s[:1]) + s[1:]
		},
		"iso8601": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.UTC().Format(time.RFC3339)
		},
		"date": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.UTC().Format("2006-01-02")
		},
		"severityEmoji": func(s Severity) string {
			switch s {
			case SeverityCritical:
				return "[CRIT]"
			case SeverityError:
				return "[ERR]"
			case SeverityWarning:
				return "[WARN]"
			case SeverityInfo:
				return "[INFO]"
			}
			return ""
		},
		"truncate": func(n int, s string) string {
			if n <= 0 || len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"json": func(v any) string {
			b, err := json.Marshal(v)
			if err != nil {
				return `""`
			}
			return string(b)
		},
		"jsonIndent": func(v any) string {
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return ""
			}
			return string(b)
		},
		"jsonEscape": func(s string) string {
			// minimal JSON string escape for embedding inside manual
			// "..." literals in a template
			b, _ := json.Marshal(s)
			if len(b) >= 2 {
				return string(b[1 : len(b)-1])
			}
			return s
		},
		"escapeMD": func(v any) string {
			// Telegram MarkdownV2 requires escaping a specific char set.
			// Accepts any so callers can pipe string-typed aliases like
			// EventType through it without printf coercion in templates.
			s := fmt.Sprintf("%v", v)
			replacer := strings.NewReplacer(
				`_`, `\_`, `*`, `\*`, `[`, `\[`, `]`, `\]`,
				`(`, `\(`, `)`, `\)`, `~`, `\~`, "`", "\\`",
				`>`, `\>`, `#`, `\#`, `+`, `\+`, `-`, `\-`,
				`=`, `\=`, `|`, `\|`, `{`, `\{`, `}`, `\}`,
				`.`, `\.`, `!`, `\!`,
			)
			return replacer.Replace(s)
		},
		"escapeHTML": func(v any) string {
			// Telegram HTML parse_mode only requires <, >, & to be
			// escaped (https://core.telegram.org/bots/api#html-style).
			// stdlib html.EscapeString covers all three plus quotes.
			return html.EscapeString(fmt.Sprintf("%v", v))
		},
	}
}

// Render compiles and executes a template against an event. Falls back
// to the type's default template when tmpl is empty.
func Render(tmpl string, ct ChannelType, ev *Event) (string, error) {
	if tmpl == "" {
		tmpl = DefaultTemplate(ct)
	}
	t, err := template.New("tmpl").Funcs(templateFuncs()).Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, ev); err != nil {
		return "", fmt.Errorf("execute template: %w", err)
	}
	return buf.String(), nil
}
