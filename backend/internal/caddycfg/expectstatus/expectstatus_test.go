package expectstatus

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    []int
		wantErr bool
	}{
		{"single", "200", []int{200}, false},
		{"csv", "200,301,302", []int{200, 301, 302}, false},
		{"range", "200-204", []int{200, 201, 202, 203, 204}, false},
		{"mixed", "200-204,301", []int{200, 201, 202, 203, 204, 301}, false},
		{"whitespace", " 200 , 301 ", []int{200, 301}, false},
		{"dedup across csv", "200,200,201", []int{200, 201}, false},
		{"dedup across range and csv", "200-202,201,300", []int{200, 201, 202, 300}, false},
		{"empty", "", nil, true},
		{"just whitespace", "   ", nil, true},
		{"empty token", "200,,301", nil, true},
		{"not a number", "abc", nil, true},
		{"too low", "99", nil, true},
		{"too high", "600", nil, true},
		{"range start too low", "99-200", nil, true},
		{"range end too high", "200-700", nil, true},
		{"range reversed", "299-200", nil, true},
		{"malformed range", "200-", nil, true},
		{"bare dash", "-", nil, true},
		{"float", "200.5", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) expected error, got codes=%v", tc.in, got.Codes())
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tc.in, err)
			}
			if !reflect.DeepEqual(got.Codes(), tc.want) {
				t.Fatalf("Parse(%q) = %v, want %v", tc.in, got.Codes(), tc.want)
			}
		})
	}
}

func TestCaddyExpectStatus(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantCode int
		wantNote bool
	}{
		{"exact single", "200", 200, false},
		{"full class 2xx", "200-299", 2, false},
		{"full class 5xx", "500-599", 5, false},
		{"subset of 2xx", "200,204", 2, true},
		{"partial 2xx range", "200-204", 2, true},
		{"multi class 2xx+3xx", "200,301", 0, true},
		{"multi class csv", "200,301,302", 0, true},
		{"multi class range", "200-399", 0, true},
		{"range that partial class after full", "200-300", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tc.in, err)
			}
			code, note := s.CaddyExpectStatus()
			if code != tc.wantCode {
				t.Errorf("CaddyExpectStatus(%q) code=%d, want %d (note=%q)", tc.in, code, tc.wantCode, note)
			}
			if tc.wantNote && note == "" {
				t.Errorf("CaddyExpectStatus(%q) expected note, got empty", tc.in)
			}
			if !tc.wantNote && note != "" {
				t.Errorf("CaddyExpectStatus(%q) expected no note, got %q", tc.in, note)
			}
		})
	}
}

func TestSpansMultipleClasses(t *testing.T) {
	cases := []struct {
		in    string
		spans bool
	}{
		{"200", false},
		{"200,201", false},
		{"200-299", false},
		{"500-504", false},
		{"200,301", true},
		{"200,301,302", true},
		{"200-399", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			s, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := s.SpansMultipleClasses(); got != tc.spans {
				t.Errorf("SpansMultipleClasses(%q) = %v, want %v", tc.in, got, tc.spans)
			}
		})
	}
}

func TestString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"200", "200"},
		{"200,201,202", "200-202"},
		{"200-204,301", "200-204,301"},
		{"300,200,201", "200-201,300"},
		{"200,200,200", "200"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			s, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := s.String(); got != tc.want {
				t.Errorf("String(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
