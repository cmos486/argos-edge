package senders

import (
	"context"
	"fmt"
	"strings"

	mail "github.com/wneessen/go-mail"

	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// Email dispatches via SMTP using github.com/wneessen/go-mail. We pick
// port defaults pragmatically: 465 -> implicit TLS, 587 -> STARTTLS,
// anything else -> user-selected toggle or NoTLS fallback (MailHog).
type Email struct{}

// NewEmail returns a stateless sender. go-mail builds a fresh Client
// per send, which is fine at phase-5 volumes.
func NewEmail() *Email { return &Email{} }

// Send implements notifications.Sender.
func (e *Email) Send(ctx context.Context, ch *notifications.Channel, ev *notifications.Event, rendered string) error {
	host, _ := ch.Config["smtp_host"].(string)
	if host == "" {
		return fmt.Errorf("email: smtp_host required")
	}
	port := intFromConfig(ch.Config, "smtp_port", 587)
	username, _ := ch.Config["smtp_username"].(string)
	password, _ := ch.Config["smtp_password"].(string)
	from, _ := ch.Config["from"].(string)
	toCSV, _ := ch.Config["to"].(string)
	subjectTmpl, _ := ch.Config["subject"].(string)
	useTLS := boolFromConfig(ch.Config, "use_tls", false)
	useSTARTTLS := boolFromConfig(ch.Config, "use_starttls", port == 587)

	if from == "" {
		return fmt.Errorf("email: from required")
	}
	recipients := splitCSV(toCSV)
	if len(recipients) == 0 {
		return fmt.Errorf("email: at least one recipient required")
	}

	// Build the message. Subject is a static string (we don't re-run
	// the template on it to keep the model simple -- templates already
	// cover body).
	subject := subjectTmpl
	if subject == "" {
		subject = fmt.Sprintf("[argos] %s: %s", ev.Severity, ev.Type)
	}

	msg := mail.NewMsg()
	if err := msg.From(from); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	if err := msg.To(recipients...); err != nil {
		return fmt.Errorf("to: %w", err)
	}
	msg.Subject(subject)
	contentType := mail.TypeTextPlain
	if strings.Contains(strings.ToLower(rendered), "<html") || strings.Contains(strings.ToLower(rendered), "<body") {
		contentType = mail.TypeTextHTML
	}
	msg.SetBodyString(contentType, rendered)

	opts := []mail.Option{mail.WithPort(port)}
	switch {
	case useTLS || port == 465:
		opts = append(opts, mail.WithSSL())
	case useSTARTTLS:
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	default:
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	}
	if username != "" {
		// Default to PLAIN; LOGIN also commonly accepted. go-mail
		// negotiates only the requested type so pick PLAIN as the
		// widest-compatible default and allow a channel-level hint.
		authType := mail.SMTPAuthPlain
		if s, _ := ch.Config["smtp_auth"].(string); strings.EqualFold(s, "LOGIN") {
			authType = mail.SMTPAuthLogin
		}
		opts = append(opts,
			mail.WithSMTPAuth(authType),
			mail.WithUsername(username),
			mail.WithPassword(password),
		)
	}

	client, err := mail.NewClient(host, opts...)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func intFromConfig(cfg map[string]any, key string, fallback int) int {
	if cfg == nil {
		return fallback
	}
	switch v := cfg[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return fallback
}

func boolFromConfig(cfg map[string]any, key string, fallback bool) bool {
	if cfg == nil {
		return fallback
	}
	if v, ok := cfg[key].(bool); ok {
		return v
	}
	return fallback
}
