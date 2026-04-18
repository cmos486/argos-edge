// Package senders implements the four channel backends phase 5 ships.
// Each sender is instantiated once at startup and registered in a
// SenderRegistry consumed by the worker.
package senders

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// Webhook POSTs the rendered payload to an HTTP endpoint. Headers are
// decrypted upstream by the repo so at this point they are a plain
// map[string]string.
type Webhook struct {
	Client *http.Client
}

// NewWebhook returns a sender with a 10s timeout.
func NewWebhook() *Webhook {
	return &Webhook{
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Send implements notifications.Sender.
func (w *Webhook) Send(ctx context.Context, ch *notifications.Channel, ev *notifications.Event, rendered string) error {
	url, _ := ch.Config["url"].(string)
	if url == "" {
		return fmt.Errorf("webhook: missing url in channel config")
	}
	method, _ := ch.Config["method"].(string)
	if method == "" {
		method = http.MethodPost
	}
	method = strings.ToUpper(method)
	ct, _ := ch.Config["content_type"].(string)
	if ct == "" {
		ct = "application/json"
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBufferString(rendered))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", ct)
	req.Header.Set("User-Agent", "argos-edge/notifications")

	// headers was decrypted upstream; it may be nil, a map[string]any
	// (from JSON round-trip) or map[string]string.
	if raw, ok := ch.Config["headers"]; ok {
		switch m := raw.(type) {
		case map[string]any:
			for k, v := range m {
				if s, ok := v.(string); ok {
					req.Header.Set(k, s)
				}
			}
		case map[string]string:
			for k, v := range m {
				req.Header.Set(k, v)
			}
		}
	}

	resp, err := w.Client.Do(req)
	if err != nil {
		return fmt.Errorf("http send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// drain body so the connection can be reused
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("webhook responded %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}
