package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// PendingTTL is how long a started /login flow may sit before its
// state is swept out. 10 minutes covers a user who clicks "Sign in
// with SSO", walks to the kitchen, comes back, and completes the
// IdP challenge.
const PendingTTL = 10 * time.Minute

// pending holds the server-side half of one in-flight login. State
// + nonce are what the IdP returns; CodeVerifier is the PKCE secret
// we hold until callback time. ReturnTo is the post-auth redirect
// target (validated against the open-redirect allowlist at
// callback time by the api layer, NOT here).
type pending struct {
	State        string
	Nonce        string
	CodeVerifier string
	ReturnTo     string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// PendingStore is a thread-safe in-memory registry of in-flight
// login flows. Lives in-process rather than in SQLite on purpose:
// each entry is <256 bytes, expires in 10 min, and a container
// restart should invalidate half-completed auths by definition.
type PendingStore struct {
	TTL time.Duration

	mu    sync.Mutex
	items map[string]pending
}

// NewPendingStore returns an empty store with the default TTL.
func NewPendingStore() *PendingStore {
	return &PendingStore{TTL: PendingTTL, items: make(map[string]pending)}
}

// StartAuth builds everything an authZ URL needs + records the
// server-side state the callback will verify against. Returns the
// URL the browser should navigate to (302 target of /oidc/login).
//
// PKCE S256 is mandatory -- argos never issues non-PKCE flows even
// to IdPs that would accept them, so a compromised client_secret
// alone cannot mint tokens for arbitrary users.
func (s *PendingStore) StartAuth(p *Provider, returnTo string) (string, error) {
	if p == nil {
		return "", ErrNotConfigured
	}
	stateBytes, err := randBytes(32)
	if err != nil {
		return "", err
	}
	nonceBytes, err := randBytes(32)
	if err != nil {
		return "", err
	}
	verifierBytes, err := randBytes(64) // 512 bits → 86 base64url chars
	if err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challenge := s256Challenge(verifier)

	now := time.Now().UTC()
	s.mu.Lock()
	s.items[state] = pending{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		ReturnTo:     returnTo,
		CreatedAt:    now,
		ExpiresAt:    now.Add(s.TTL),
	}
	s.mu.Unlock()

	authURL := p.OAuth.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	return authURL, nil
}

// ErrStateNotFound means the callback state cookie / query does not
// match any pending entry. Either replay of a consumed state, or an
// expired one, or an outright CSRF attempt.
var ErrStateNotFound = errors.New("oidc: state not found or expired")

// HandleCallback validates state, exchanges the code for tokens,
// verifies the ID token (signature + issuer + audience + nonce +
// expiry), parses the claims we care about, and returns them plus
// the ReturnTo the original /login call requested.
//
// On success the pending entry is consumed (single-use). On any
// failure it is LEFT in place so a genuine retry from a slow IdP
// can succeed without a second /login round-trip; the sweeper
// eventually drops it when PendingTTL elapses.
func (s *PendingStore) HandleCallback(
	ctx context.Context, p *Provider, code, state string,
) (Claims, string, error) {
	if p == nil {
		return Claims{}, "", ErrNotConfigured
	}
	if state == "" || code == "" {
		return Claims{}, "", fmt.Errorf("oidc callback: missing code or state")
	}

	s.mu.Lock()
	pend, ok := s.items[state]
	s.mu.Unlock()
	if !ok {
		return Claims{}, "", ErrStateNotFound
	}
	if time.Now().UTC().After(pend.ExpiresAt) {
		s.mu.Lock()
		delete(s.items, state)
		s.mu.Unlock()
		return Claims{}, "", ErrStateNotFound
	}

	token, err := p.OAuth.Exchange(
		ctx, code,
		oauth2.SetAuthURLParam("code_verifier", pend.CodeVerifier),
	)
	if err != nil {
		return Claims{}, "", fmt.Errorf("token exchange: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Claims{}, "", fmt.Errorf("oidc: token response missing id_token")
	}
	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, "", fmt.Errorf("verify id_token: %w", err)
	}
	if idToken.Nonce != pend.Nonce {
		return Claims{}, "", fmt.Errorf("oidc: nonce mismatch (replay attempt?)")
	}

	var cl Claims
	if err := idToken.Claims(&cl); err != nil {
		return Claims{}, "", fmt.Errorf("parse id_token claims: %w", err)
	}
	cl.Subject = idToken.Subject // always trust the verifier-extracted sub
	if cl.Subject == "" {
		return Claims{}, "", fmt.Errorf("oidc: id_token has no sub claim")
	}

	// Consume the pending entry -- single-use.
	s.mu.Lock()
	delete(s.items, state)
	s.mu.Unlock()

	return cl, pend.ReturnTo, nil
}

// Sweep drops every pending entry past its ExpiresAt. Returns the
// number dropped. Called by StartSweeper on a timer; safe to invoke
// manually from tests.
func (s *PendingStore) Sweep() int {
	now := time.Now().UTC()
	n := 0
	s.mu.Lock()
	for k, v := range s.items {
		if now.After(v.ExpiresAt) {
			delete(s.items, k)
			n++
		}
	}
	s.mu.Unlock()
	return n
}

// Size is the count of pending entries. Useful for tests + a
// potential /system/health metric.
func (s *PendingStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// StartSweeper runs Sweep on a ticker until ctx is cancelled.
// Interval is TTL/2 (5 min default).
func (s *PendingStore) StartSweeper(ctx context.Context) {
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

// --- helpers ---

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("read rand: %w", err)
	}
	return b, nil
}

// s256Challenge returns base64url(sha256(verifier)) without padding,
// per RFC 7636 section 4.2.
func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// compile-time assertion that the coreoidc package we imported has
// the Verifier + IDToken surfaces we rely on. If a future update
// renames these, the package fails to build instead of silently
// reverting to an older token-validation contract.
var _ = func() *coreoidc.IDTokenVerifier { return (*coreoidc.IDTokenVerifier)(nil) }
