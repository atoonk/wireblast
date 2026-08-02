package config

import (
	"net/netip"
	"testing"
)

func TestParsePPS(t *testing.T) {
	tests := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{"1000000", 1_000_000, false},
		{"1M", 1_000_000, false},
		{"1m", 1_000_000, false},
		{"14.88M", 14_880_000, false},
		{"100k", 100_000, false},
		{"2G", 2_000_000_000, false},
		{"500", 500, false},
		{"1Mpps", 1_000_000, false},
		{" 1M ", 1_000_000, false},
		{"0", 0, false},
		{"unlimited", 0, false},
		{"line-rate", 0, false},
		{"max", 0, false},
		{"none", 0, false},
		{"", 0, true},
		{"fast", 0, true},
		{"1X", 0, true},
		{"-5", 0, true},
		// Overflow must error, not wrap to a garbage rate: the integer path
		// where n fits uint64 but n*mult does not, and the raw-integer path.
		{"18446744073t", 0, true},         // 1.8e10 * 1e12 > 2^64
		{"99999999999999999999", 0, true}, // 20 digits, exceeds uint64 on its own
		{"1e40", 0, true},                 // float path overflow
	}
	for _, tt := range tests {
		got, err := ParsePPS(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParsePPS(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("ParsePPS(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseBPS(t *testing.T) {
	tests := []struct {
		in      string
		want    uint64
		wantErr bool
	}{
		{"1000000000", 1e9, false},
		{"1G", 1e9, false},
		{"10G", 1e10, false},
		{"2.5Gbps", 2.5e9, false},
		{"100Mbit/s", 1e8, false},
		{"100Mbits", 1e8, false},
		{"1Tbps", 1e12, false},
		{"512k", 512_000, false},
		{"unlimited", 0, false},
		{"", 0, true},
		{"lots", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseBPS(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseBPS(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != tt.want {
			t.Errorf("ParseBPS(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestFormatRates(t *testing.T) {
	tests := []struct {
		pps  uint64
		want string
	}{
		{0, "unlimited"},
		{500, "500pps"},
		{100_000, "100kpps"},
		{1_000_000, "1Mpps"},
		{14_880_000, "14.88Mpps"},
		{2_000_000_000, "2Gpps"},
	}
	for _, tt := range tests {
		if got := FormatPPS(tt.pps); got != tt.want {
			t.Errorf("FormatPPS(%d) = %q, want %q", tt.pps, got, tt.want)
		}
	}
	if got := FormatBPS(10e9); got != "10Gbps" {
		t.Errorf("FormatBPS(10e9) = %q, want 10Gbps", got)
	}
	if got := FormatBPS(0); got != "unlimited" {
		t.Errorf("FormatBPS(0) = %q, want unlimited", got)
	}
}

func TestParseDst(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"192.0.2.10", "192.0.2.10/32", false},
		{"10.0.0.0/24", "10.0.0.0/24", false},
		{"10.0.0.5/24", "10.0.0.0/24", false}, // masked
		{"10.0.0.1/32", "10.0.0.1/32", false},
		{"2001:db8::1", "2001:db8::1/128", false},
		{"2001:db8::/32", "2001:db8::/32", false},
		{"2001:db8::5/64", "2001:db8::/64", false}, // masked
		{"", "", true},
		{"nope", "", true},
		{"10.0.0.0/33", "", true},
		// A v4-mapped v6 address collapses to plain v4, so a prefix length past
		// /32 is nonsense and must be rejected, not silently turned into the zero
		// prefix (which used to slip past validation as "addresses must be set").
		{"::ffff:10.0.0.0", "10.0.0.0/32", false},
		{"::ffff:10.0.0.0/24", "10.0.0.0/24", false},
		{"::ffff:10.0.0.0/104", "", true},
		{"::ffff:1.2.3.4/120", "", true},
	}
	for _, tt := range tests {
		got, err := ParseDst(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseDst(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err == nil && got != netip.MustParsePrefix(tt.want) {
			t.Errorf("ParseDst(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseMAC(t *testing.T) {
	if _, err := ParseMAC("3c:ec:ef:b4:c2:dc"); err != nil {
		t.Errorf("valid MAC rejected: %v", err)
	}
	if _, err := ParseMAC(" 3c-ec-ef-b4-c2-dc "); err != nil {
		t.Errorf("dashed MAC rejected: %v", err)
	}
	if _, err := ParseMAC("01:02:03:04:05:06:07:08"); err == nil {
		t.Error("8-byte address should be rejected as non-Ethernet")
	}
	if _, err := ParseMAC("garbage"); err == nil {
		t.Error("garbage MAC should be rejected")
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("53, 5353,80")
	if err != nil {
		t.Fatalf("ParsePorts: %v", err)
	}
	want := []uint16{53, 5353, 80}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, bad := range []string{"", "0", "70000", "http"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("ParsePorts(%q) should fail", bad)
		}
	}
}
