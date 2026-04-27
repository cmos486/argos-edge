package senders

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// Telegram uses the HTTP Bot API directly. One request per message via
// sendMessage. For 3-attempt retry semantics, per-call timeout is kept
// tight at 10s so a dead bot doesn't stall the worker.
type Telegram struct {
	Client *http.Client
}

// NewTelegram returns a sender with a 10s client timeout.
func NewTelegram() *Telegram {
	return &Telegram{Client: &http.Client{Timeout: 10 * time.Second}}
}

// Send implements notifications.Sender.
func (t *Telegram) Send(ctx context.Context, ch *notifications.Channel, ev *notifications.Event, rendered string) error {
	token, _ := ch.Config["bot_token"].(string)
	if token == "" {
		return fmt.Errorf("telegram: bot_token required")
	}
	chatID, _ := ch.Config["chat_id"].(string)
	if chatID == "" {
		return fmt.Errorf("telegram: chat_id required")
	}
	parseMode, _ := ch.Config["parse_mode"].(string)
	if parseMode == "" {
		// HTML default since v1.3.34.1 (3 escape chars vs MarkdownV2's
		// 18). Operators that explicitly set parse_mode=MarkdownV2 in
		// the channel config keep working with the escapeMD-using
		// custom templates they already have.
		parseMode = "HTML"
	}

	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	form := url.Values{}
	form.Set("chat_id", chatID)
	form.Set("text", rendered)
	form.Set("parse_mode", parseMode)
	form.Set("disable_web_page_preview", "true")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.Client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram http: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	// Telegram returns {"ok":false,"error_code":N,"description":"..."}
	var apiErr struct {
		Description string `json:"description"`
		ErrorCode   int    `json:"error_code"`
	}
	_ = json.Unmarshal(body, &apiErr)
	if apiErr.Description != "" {
		return fmt.Errorf("telegram %d: %s", apiErr.ErrorCode, apiErr.Description)
	}
	return fmt.Errorf("telegram responded %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}
