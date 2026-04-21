package api

import "testing"

func TestClassifyCertStatus(t *testing.T) {
	cases := []struct {
		days int
		want string
	}{
		{-5, "expired"},
		{0, "expired"},
		{1, "critical"},
		{6, "critical"},
		{7, "warning"},
		{30, "warning"},
		{31, "ok"},
		{365, "ok"},
	}
	for _, tc := range cases {
		if got := classifyCertStatus(tc.days); got != tc.want {
			t.Errorf("classifyCertStatus(%d) = %q, want %q", tc.days, got, tc.want)
		}
	}
}

func TestLooksLikeFailure(t *testing.T) {
	fails := []string{
		"unable to renew certificate",
		"ACME error: connection refused",
		"challenge failed: invalid authorization",
		"FAIL: dns propagation check",
	}
	for _, s := range fails {
		if !looksLikeFailure(s) {
			t.Errorf("looksLikeFailure(%q) = false, want true", s)
		}
	}

	successes := []string{
		"obtained certificate for example.com",
		"certificate renewed",
		"activated issuer",
	}
	for _, s := range successes {
		if looksLikeFailure(s) {
			t.Errorf("looksLikeFailure(%q) = true, want false", s)
		}
	}
}
