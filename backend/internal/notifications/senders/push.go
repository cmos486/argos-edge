package senders

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// SubFetcher lists the Web Push subscriptions the sender should fan out
// to. In phase 5 this is "every subscription in the DB" because the
// panel is single-tenant admin-only, but we keep the fetcher abstract
// so a future phase can scope by user/role.
type SubFetcher interface {
	ListAllPushSubs(ctx context.Context) ([]notifications.PushSubscription, error)
	DeletePushSubByEndpoint(ctx context.Context, endpoint string) error
}

// BrowserPush fans a message out to every registered subscription.
// Terminal failures per-sub are logged but do not abort the send; the
// overall send is considered successful if at least one subscription
// accepts the push OR the subscription table is empty (no targets =
// no-op success, so an operator who hasn't enabled push yet isn't
// penalised).
type BrowserPush struct {
	Subs SubFetcher
	// Keys are loaded once at startup via EnsureVAPID and passed in
	// here; the sender does not re-read the settings table on every
	// call.
	Keys *notifications.VAPIDKeys
}

// NewBrowserPush wires the sub fetcher + vapid keys.
func NewBrowserPush(subs SubFetcher, keys *notifications.VAPIDKeys) *BrowserPush {
	return &BrowserPush{Subs: subs, Keys: keys}
}

// Send implements notifications.Sender.
func (b *BrowserPush) Send(ctx context.Context, ch *notifications.Channel, ev *notifications.Event, rendered string) error {
	if b.Keys == nil || b.Keys.Public == "" || b.Keys.Private == "" {
		return errors.New("browser_push: VAPID keys not configured")
	}
	subs, err := b.Subs.ListAllPushSubs(ctx)
	if err != nil {
		return fmt.Errorf("list subs: %w", err)
	}
	if len(subs) == 0 {
		// no-op success: operator enabled the channel but no browser
		// has registered a subscription yet. Avoids noisy retries.
		slog.Info("browser_push: no subscriptions, skipping")
		return nil
	}
	contact := b.Keys.Contact
	if contact == "" {
		contact = "admin@example.com"
	}
	subject := "mailto:" + contact

	var sent, failed int
	var lastErr error
	for _, s := range subs {
		wp := &webpush.Subscription{
			Endpoint: s.Endpoint,
			Keys: webpush.Keys{
				P256dh: s.P256dhKey,
				Auth:   s.AuthKey,
			},
		}
		resp, err := webpush.SendNotificationWithContext(ctx, []byte(rendered), wp, &webpush.Options{
			Subscriber:      subject,
			VAPIDPublicKey:  b.Keys.Public,
			VAPIDPrivateKey: b.Keys.Private,
			TTL:             86400,
		})
		if err != nil {
			failed++
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		switch {
		case resp.StatusCode == 404 || resp.StatusCode == 410:
			// endpoint gone -> clean up the dead subscription
			if err := b.Subs.DeletePushSubByEndpoint(ctx, s.Endpoint); err != nil {
				slog.Warn("browser_push: failed to prune gone endpoint", "error", err)
			}
			failed++
			lastErr = fmt.Errorf("endpoint gone: %d", resp.StatusCode)
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			sent++
		default:
			failed++
			lastErr = fmt.Errorf("push %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
	}
	if sent == 0 && failed > 0 {
		return fmt.Errorf("all %d pushes failed: %w", failed, lastErr)
	}
	return nil
}
