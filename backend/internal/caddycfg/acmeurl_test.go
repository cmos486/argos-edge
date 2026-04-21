package caddycfg

import "testing"

func TestResolveACMECAURL(t *testing.T) {
	cases := []struct {
		name     string
		env      string
		perHost  string
		global   string
		expected string
	}{
		{"all empty", "", "", "", ""},
		{"only global", "", "", LEStagingCAURL, LEStagingCAURL},
		{"per-host beats global", "", "https://per.example/dir", LEStagingCAURL, "https://per.example/dir"},
		{"env beats everything", "https://env.example/dir", "https://per.example/dir", LEStagingCAURL, "https://env.example/dir"},
		{"whitespace only treated as empty", "   ", "", LEProductionCAURL, LEProductionCAURL},
		{"trim preserved URL", "  https://env.example/dir  ", "", "", "https://env.example/dir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveACMECAURL(tc.env, tc.perHost, tc.global)
			if got != tc.expected {
				t.Fatalf("got %q want %q", got, tc.expected)
			}
		})
	}
}

func TestValidateACMECAURL(t *testing.T) {
	ok := []string{
		"",
		"   ",
		LEProductionCAURL,
		LEStagingCAURL,
		"https://acme.internal.example.org/directory",
	}
	for _, s := range ok {
		if err := ValidateACMECAURL(s); err != nil {
			t.Errorf("ValidateACMECAURL(%q) unexpected err %v", s, err)
		}
	}

	bad := []string{
		"not a url",
		"http://plain.example/dir",
		"ftp://weird.example/dir",
		"https://",
		"://missing-scheme",
	}
	for _, s := range bad {
		if err := ValidateACMECAURL(s); err == nil {
			t.Errorf("ValidateACMECAURL(%q) expected err, got nil", s)
		}
	}
}
