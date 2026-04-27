package senders

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// telegramRoundTrip routes every Telegram-sender request to the given
// handler instead of api.telegram.org. The Telegram struct doesn't
// expose an endpoint override, so we install a custom RoundTripper on
// the embedded *http.Client.
type interceptTransport struct {
	server *httptest.Server
}

func (it *interceptTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rerouted := *req
	u, err := url.Parse(it.server.URL)
	if err != nil {
		return nil, err
	}
	rerouted.URL.Scheme = u.Scheme
	rerouted.URL.Host = u.Host
	return it.server.Client().Transport.RoundTrip(&rerouted)
}

// TestTelegramSenderDefaultsToHTMLParseMode asserts the v1.3.34.1
// fallback (when Channel.Config.parse_mode is unset) sends
// parse_mode=HTML on the wire.
func TestTelegramSenderDefaultsToHTMLParseMode(t *testing.T) {
	var captured url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured, _ = url.ParseQuery(string(body))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	tg := NewTelegram()
	tg.Client.Transport = &interceptTransport{server: srv}

	ch := &notifications.Channel{
		Type: notifications.TypeTelegram,
		Config: map[string]any{
			"bot_token": "fake",
			"chat_id":   "12345",
		},
	}
	if err := tg.Send(context.Background(), ch, &notifications.Event{}, "<b>hi</b>"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := captured.Get("parse_mode"); got != "HTML" {
		t.Errorf("expected parse_mode=HTML, got %q", got)
	}
	if got := captured.Get("text"); got != "<b>hi</b>" {
		t.Errorf("expected text body to be passed through, got %q", got)
	}
}

// TestTelegramSenderHonoursExplicitMarkdownV2 asserts an operator who
// pinned parse_mode=MarkdownV2 on a channel keeps that mode after
// v1.3.34.1 (no forced migration).
func TestTelegramSenderHonoursExplicitMarkdownV2(t *testing.T) {
	var captured url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured, _ = url.ParseQuery(string(body))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	tg := NewTelegram()
	tg.Client.Transport = &interceptTransport{server: srv}

	ch := &notifications.Channel{
		Type: notifications.TypeTelegram,
		Config: map[string]any{
			"bot_token":  "fake",
			"chat_id":    "12345",
			"parse_mode": "MarkdownV2",
		},
	}
	if err := tg.Send(context.Background(), ch, &notifications.Event{}, `*hi*`); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := captured.Get("parse_mode"); got != "MarkdownV2" {
		t.Errorf("expected parse_mode=MarkdownV2 to be honoured, got %q", got)
	}
}

// TestTelegramSenderSurfacesAPIError asserts the wrapping of Telegram's
// JSON error description (the v1.3.34.1 root-cause symptom: HTTP 400
// with "can't parse entities..." byte-offset message).
func TestTelegramSenderSurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"can't parse entities: Character '_' is reserved"}`))
	}))
	defer srv.Close()

	tg := NewTelegram()
	tg.Client.Transport = &interceptTransport{server: srv}

	ch := &notifications.Channel{
		Type: notifications.TypeTelegram,
		Config: map[string]any{
			"bot_token": "fake",
			"chat_id":   "12345",
		},
	}
	err := tg.Send(context.Background(), ch, &notifications.Event{}, "raw")
	if err == nil {
		t.Fatal("expected error from 400 response")
	}
	if !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "Character '_' is reserved") {
		t.Errorf("expected wrapped Telegram description, got: %v", err)
	}
}
