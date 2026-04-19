package totp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrChallengeNotFound is returned when a challenge_id is unknown,
// already consumed, or has expired.
var ErrChallengeNotFound = errors.New("challenge not found or expired")

// DefaultChallengeTTL is the window a user has to complete a TOTP
// challenge after the first /api/auth/login call. Shorter than a
// session TTL but long enough to unlock a phone and type a code.
const DefaultChallengeTTL = 5 * time.Minute

// Challenge is the pre-session state between /login and /totp/verify.
// We hold the user id + username + client IP so the verify handler
// can fetch user state and emit audit events without re-running the
// password path.
type Challenge struct {
	ID        string
	UserID    int64
	Username  string
	RemoteIP  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ChallengeStore is a thread-safe in-memory registry of pending TOTP
// challenges. Entries expire after TTL; a background sweeper drops
// anything past expiry.
//
// Kept in-memory (not in SQLite) on purpose: challenges live <5 min,
// cost one map insert per login, and a container restart invalidates
// them by definition -- which is the right behavior for a half-
// completed auth, not a regression.
type ChallengeStore struct {
	TTL time.Duration

	mu    sync.Mutex
	items map[string]Challenge
}

// NewChallengeStore returns an empty store with the default TTL.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{
		TTL:   DefaultChallengeTTL,
		items: make(map[string]Challenge),
	}
}

// Create registers a new challenge for the given user. Returns the
// opaque challenge_id the client must echo back to /verify or
// /recovery.
func (s *ChallengeStore) Create(userID int64, username, ip string) (Challenge, error) {
	id, err := newChallengeID()
	if err != nil {
		return Challenge{}, err
	}
	now := time.Now().UTC()
	c := Challenge{
		ID:        id,
		UserID:    userID,
		Username:  username,
		RemoteIP:  ip,
		CreatedAt: now,
		ExpiresAt: now.Add(s.TTL),
	}
	s.mu.Lock()
	s.items[id] = c
	s.mu.Unlock()
	return c, nil
}

// Get looks up a challenge. Returns ErrChallengeNotFound for unknown
// or expired ids. Does NOT delete the entry; callers delete on
// successful auth (so wrong codes can be retried within the window).
func (s *ChallengeStore) Get(id string) (Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.items[id]
	if !ok {
		return Challenge{}, ErrChallengeNotFound
	}
	if time.Now().UTC().After(c.ExpiresAt) {
		delete(s.items, id)
		return Challenge{}, ErrChallengeNotFound
	}
	return c, nil
}

// Consume deletes a challenge. Called after a successful TOTP verify
// or recovery code redemption so the id cannot be replayed.
func (s *ChallengeStore) Consume(id string) {
	s.mu.Lock()
	delete(s.items, id)
	s.mu.Unlock()
}

// Sweep drops expired entries. Called by the background sweeper; the
// Get path also drops on read so users never see stale entries.
// Returns the number of entries removed (for logging / metrics).
func (s *ChallengeStore) Sweep() int {
	now := time.Now().UTC()
	n := 0
	s.mu.Lock()
	for id, c := range s.items {
		if now.After(c.ExpiresAt) {
			delete(s.items, id)
			n++
		}
	}
	s.mu.Unlock()
	return n
}

// Size returns the current number of tracked challenges. Useful for
// smoke tests and /system/health.
func (s *ChallengeStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// StartSweeper runs Sweep on a ticker until ctx is cancelled. The
// caller is responsible for cancelling; typical usage is to pass the
// main server context so shutdown stops the goroutine cleanly.
func (s *ChallengeStore) StartSweeper(ctx context.Context) {
	interval := s.TTL / 2
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = s.Sweep()
			}
		}
	}()
}

// newChallengeID returns 16 bytes of crypto/rand, hex-encoded. 32-char
// opaque id. Overlap with session tokens (32 hex = 16 bytes) is fine;
// they live in different namespaces and are never swapped.
func newChallengeID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}
