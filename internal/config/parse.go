package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ParseDst parses a destination given as either a bare IPv4 address or an IPv4
// CIDR, and returns it as a prefix. A bare address becomes a /32.
func ParseDst(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, errors.New("empty destination")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		// Unmap a v4-mapped v6 prefix (::ffff:a.b.c.d/N) down to plain v4. The
		// prefix length must then fit the unmapped address: ::ffff:10.0.0.0/104
		// is nonsense because a v4 prefix is /0 to /32. Without this check
		// PrefixFrom would build an invalid prefix and Masked would silently
		// return the zero prefix, which slips past validation and only surfaces
		// later as a baffling "addresses must be set".
		addr := p.Addr().Unmap()
		if p.Bits() > addr.BitLen() {
			return netip.Prefix{}, fmt.Errorf(
				"%s is not a valid prefix: a v4-mapped address takes /0 to /%d, not /%d",
				s, addr.BitLen(), p.Bits())
		}
		return netip.PrefixFrom(addr, p.Bits()).Masked(), nil
	}
	a, err := parseHostIP(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil // /32 for v4, /128 for v6
}

// parseHostIP parses a bare IPv4 or IPv6 address, normalising a v4-mapped v6
// address to plain v4.
func parseHostIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

// ParseHostIP parses a bare IPv4 or IPv6 address.
func ParseHostIP(s string) (netip.Addr, error) { return parseHostIP(s) }

// ParseMAC parses a 6-byte Ethernet hardware address.
func ParseMAC(s string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(mac) != 6 {
		return nil, fmt.Errorf("%s is not a 6-byte Ethernet address", s)
	}
	return mac, nil
}

func isBroadcast(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return len(mac) == 6
}

// unlimitedWords are the spellings that explicitly select "no limit".
var unlimitedWords = map[string]bool{
	"0": true, "unlimited": true, "none": true, "line-rate": true,
	"linerate": true, "max": true, "off": true,
}

// ParsePPS parses a packets-per-second rate. It accepts a plain number and the
// decimal SI suffixes k/K, m/M and g/G (1e3, 1e6, 1e9 — not powers of two,
// because packet rates are quoted in decimal), optionally followed by "pps".
// "0", "unlimited", "line-rate", "none", "max" and "off" all mean no limit,
// returned as 0.
//
//	ParsePPS("1000000") == 1000000
//	ParsePPS("1M")      == 1000000
//	ParsePPS("14.88M")  == 14880000
//	ParsePPS("unlimited") == 0
func ParsePPS(s string) (uint64, error) {
	return parseRate(s, "pps", []string{"pps", "packets/s", "p/s"})
}

// ParseBPS parses a bit-rate. It accepts a plain number of bits per second and
// the decimal SI suffixes k/K, m/M, g/G and t/T, optionally followed by any of
// "bps", "bit", "bits", "b/s" or "bit/s". The same words as ParsePPS mean
// unlimited.
//
//	ParseBPS("1000000000") == 1e9
//	ParseBPS("1G")         == 1e9
//	ParseBPS("2.5Gbps")    == 2.5e9
//	ParseBPS("100Mbit/s")  == 1e8
//
// The rate is measured in on-the-wire bits: each frame costs
// (PacketSize + 20) * 8 bits, so "10G" really does mean 10G line rate.
func ParseBPS(s string) (uint64, error) {
	return parseRate(s, "bps", []string{"bits/s", "bit/s", "bits", "bit", "bps", "b/s"})
}

func parseRate(s, kind string, units []string) (uint64, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return 0, fmt.Errorf("empty %s value", kind)
	}
	if unlimitedWords[t] {
		return 0, nil
	}
	// Strip a trailing unit, longest match first so "bits/s" wins over "bit".
	for _, u := range units {
		if strings.HasSuffix(t, u) {
			t = strings.TrimSpace(strings.TrimSuffix(t, u))
			break
		}
	}
	mult := uint64(1)
	if t != "" {
		switch t[len(t)-1] {
		case 'k':
			mult, t = 1e3, t[:len(t)-1]
		case 'm':
			mult, t = 1e6, t[:len(t)-1]
		case 'g':
			mult, t = 1e9, t[:len(t)-1]
		case 't':
			mult, t = 1e12, t[:len(t)-1]
		}
	}
	t = strings.TrimSpace(t)
	if t == "" {
		return 0, fmt.Errorf("%q is not a %s rate", s, kind)
	}
	// Integers exactly; anything with a decimal point via float.
	if !strings.ContainsAny(t, ".eE") {
		n, err := strconv.ParseUint(t, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a %s rate", s, kind)
		}
		if n > math.MaxUint64/mult { // mult is >= 1, so no divide-by-zero
			return 0, fmt.Errorf("%q is too large a %s rate", s, kind)
		}
		return n * mult, nil
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a %s rate", s, kind)
	}
	if f < 0 {
		return 0, fmt.Errorf("%q is negative", s)
	}
	// Converting a float that exceeds uint64 range is implementation-defined, so
	// reject it rather than wrap to a garbage rate.
	if prod := f * float64(mult); prod > float64(math.MaxUint64) {
		return 0, fmt.Errorf("%q is too large a %s rate", s, kind)
	}
	return uint64(f * float64(mult)), nil
}

// FormatPPS renders a packet rate the way a human would say it.
func FormatPPS(pps uint64) string {
	if pps == 0 {
		return "unlimited"
	}
	return formatSI(float64(pps)) + "pps"
}

// FormatBPS renders a bit rate the way a human would say it.
func FormatBPS(bps uint64) string {
	if bps == 0 {
		return "unlimited"
	}
	return formatSI(float64(bps)) + "bps"
}

func formatSI(v float64) string {
	switch {
	case v >= 1e9:
		return trimZeros(strconv.FormatFloat(v/1e9, 'f', 2, 64)) + "G"
	case v >= 1e6:
		return trimZeros(strconv.FormatFloat(v/1e6, 'f', 2, 64)) + "M"
	case v >= 1e3:
		return trimZeros(strconv.FormatFloat(v/1e3, 'f', 2, 64)) + "k"
	default:
		return trimZeros(strconv.FormatFloat(v, 'f', 2, 64))
	}
}

func trimZeros(s string) string {
	if !strings.Contains(s, ".") {
		return s
	}
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// ParsePorts parses a comma-separated port list, e.g. "53,5353".
func ParsePorts(s string) ([]uint16, error) {
	var out []uint16
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.ParseUint(f, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("%q is not a port number", f)
		}
		out = append(out, uint16(n))
	}
	if len(out) == 0 {
		return nil, errors.New("no ports given")
	}
	return out, nil
}
