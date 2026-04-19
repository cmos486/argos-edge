package geoip

import (
	"net"
	"testing"
)

func TestIsPrivate(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		// public: must be false
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.42", false},
		{"2606:4700:4700::1111", false}, // Cloudflare IPv6
		// private
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true}, // link-local IPv4
		{"100.64.0.1", true},  // CGNAT
		{"100.127.255.255", true},
		// IPv6
		{"::1", true},     // loopback
		{"fe80::1", true}, // link-local
		{"fc00::1", true}, // ULA
		{"fd00::1", true}, // ULA
		{"::", true},      // unspecified
		// 100.128.0.1 is the first address OUTSIDE CGNAT and should
		// be treated as public
		{"100.128.0.1", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("parse %s", c.ip)
		}
		got := IsPrivate(ip)
		if got != c.want {
			t.Errorf("IsPrivate(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestIsPrivateNil(t *testing.T) {
	if !IsPrivate(nil) {
		t.Error("nil IP should be considered private (skip lookup)")
	}
}
