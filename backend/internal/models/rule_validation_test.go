package models

import (
	"strings"
	"testing"
)

func mustMatcher(t *testing.T, kind MatcherType, cfg any) MatcherEnv {
	t.Helper()
	m, err := NewMatcher(kind, cfg)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	return m
}

func mustAction(t *testing.T, v any) ActionEnv {
	t.Helper()
	a, err := NewAction(v)
	if err != nil {
		t.Fatalf("NewAction: %v", err)
	}
	return a
}

func TestRuleValidatePriorityBounds(t *testing.T) {
	mk := func(p int) Rule {
		return Rule{
			Priority: p,
			Matchers: []MatcherEnv{mustMatcher(t, MatcherPath, PathMatcherConfig{Patterns: []string{"/a"}})},
			Action:   mustAction(t, BlockAction{}),
		}
	}
	cases := []struct {
		p       int
		wantErr bool
	}{
		{0, true},
		{1, false},
		{50000, false},
		{50001, true},
	}
	for _, tc := range cases {
		r := mk(tc.p)
		err := r.Validate(nil)
		if tc.wantErr && err == nil {
			t.Errorf("priority=%d expected error", tc.p)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("priority=%d unexpected error: %v", tc.p, err)
		}
	}
}

func TestRuleValidateRequiresMatcher(t *testing.T) {
	r := Rule{Priority: 10, Action: mustAction(t, BlockAction{})}
	err := r.Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "matcher") {
		t.Errorf("expected matcher-required error, got %v", err)
	}
}

func TestMatcherPathValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  PathMatcherConfig
		err  bool
	}{
		{"glob ok", PathMatcherConfig{Patterns: []string{"/api/*"}}, false},
		{"exact ok", PathMatcherConfig{Patterns: []string{"/healthz"}}, false},
		{"missing slash", PathMatcherConfig{Patterns: []string{"api/*"}}, true},
		{"empty", PathMatcherConfig{Patterns: nil}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := mustMatcher(t, MatcherPath, tc.cfg)
			err := m.Validate()
			if tc.err && err == nil {
				t.Errorf("expected error")
			}
			if !tc.err && err != nil {
				t.Errorf("unexpected: %v", err)
			}
		})
	}
}

func TestMatcherPathExactRejectsGlob(t *testing.T) {
	m := mustMatcher(t, MatcherPathExact, PathExactMatcherConfig{Values: []string{"/foo/*"}})
	if err := m.Validate(); err == nil {
		t.Error("expected glob-in-exact error")
	}
}

func TestMatcherMethodValidation(t *testing.T) {
	good := mustMatcher(t, MatcherMethod, MethodMatcherConfig{Methods: []string{"GET", "POST"}})
	if err := good.Validate(); err != nil {
		t.Errorf("valid methods errored: %v", err)
	}
	bad := mustMatcher(t, MatcherMethod, MethodMatcherConfig{Methods: []string{"FOOBAR"}})
	if err := bad.Validate(); err == nil {
		t.Error("expected invalid method error")
	}
}

func TestMatcherHeaderRegex(t *testing.T) {
	m := mustMatcher(t, MatcherHeader, HeaderMatcherConfig{Name: "X-Foo", Value: "[a-", Mode: HeaderModeRegex})
	if err := m.Validate(); err == nil {
		t.Error("expected regex compile error")
	}
	m2 := mustMatcher(t, MatcherHeader, HeaderMatcherConfig{Name: "X-Foo", Value: ".*", Mode: HeaderModeRegex})
	if err := m2.Validate(); err != nil {
		t.Errorf("valid regex errored: %v", err)
	}
}

func TestMatcherRemoteIPValidation(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		err  bool
	}{
		{"cidr", []string{"192.168.0.0/16"}, false},
		{"ip", []string{"10.0.0.1"}, false},
		{"mixed", []string{"10.0.0.1", "172.16.0.0/12"}, false},
		{"bad", []string{"notanip"}, true},
		{"empty", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := mustMatcher(t, MatcherRemoteIP, RemoteIPMatcherConfig{Ranges: tc.in})
			err := m.Validate()
			if tc.err && err == nil {
				t.Error("expected error")
			}
			if !tc.err && err != nil {
				t.Errorf("unexpected: %v", err)
			}
		})
	}
}

func TestActionRedirectCodes(t *testing.T) {
	cases := []struct {
		code int
		err  bool
	}{
		{301, false},
		{302, false},
		{307, false},
		{308, false},
		{200, true},
		{303, true},
	}
	for _, tc := range cases {
		a := mustAction(t, RedirectAction{StatusCode: tc.code, Target: "https://x/"})
		err := a.Validate(nil)
		if tc.err && err == nil {
			t.Errorf("code %d: expected error", tc.code)
		}
		if !tc.err && err != nil {
			t.Errorf("code %d: unexpected: %v", tc.code, err)
		}
	}
}

func TestActionFixedResponseBounds(t *testing.T) {
	ok := mustAction(t, FixedResponseAction{StatusCode: 503, Body: "down"})
	if err := ok.Validate(nil); err != nil {
		t.Errorf("valid fixed_response errored: %v", err)
	}
	bad := mustAction(t, FixedResponseAction{StatusCode: 999, Body: ""})
	if err := bad.Validate(nil); err == nil {
		t.Error("expected out-of-range error")
	}
}

func TestActionRewriteRequiresOneField(t *testing.T) {
	bad := mustAction(t, RewriteAction{})
	if err := bad.Validate(nil); err == nil {
		t.Error("expected at-least-one error")
	}
	ok := mustAction(t, RewriteAction{StripPrefix: "/v1"})
	if err := ok.Validate(nil); err != nil {
		t.Errorf("valid rewrite errored: %v", err)
	}
	badPath := mustAction(t, RewriteAction{Path: "no-slash"})
	if err := badPath.Validate(nil); err == nil {
		t.Error("expected path-slash error")
	}
}

func TestActionForwardChecksExistence(t *testing.T) {
	a := mustAction(t, ForwardAction{TargetGroupID: 42})
	called := 0
	exists := func(id int64) (bool, error) {
		called++
		return id == 42, nil
	}
	if err := a.Validate(exists); err != nil {
		t.Errorf("existing tg errored: %v", err)
	}
	if called != 1 {
		t.Errorf("expected exactly one existence check, got %d", called)
	}

	b := mustAction(t, ForwardAction{TargetGroupID: 99})
	if err := b.Validate(exists); err == nil {
		t.Error("expected nonexistent tg error")
	}
}
