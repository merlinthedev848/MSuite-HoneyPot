package attrib

import (
	"fmt"
	"net"
	"strings"
)

// Record is the owner and network extracted from a WHOIS reply.
// It is not a raw dump: abuse contacts and comments are ignored.
type Record struct {
	Org     string
	NetName string
	Country string
	CIDR    string
	ASN     string
}

// Owner is the organisation when WHOIS has one, otherwise the netname.
func (r Record) Owner() string {
	if r.Org != "" {
		return r.Org
	}
	return r.NetName
}

// ParseWHOIS reads org, netname, country, the most specific prefix that
// contains ip, and the ASN from a WHOIS reply.
func ParseWHOIS(body, ip string) Record {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	fields := whoisFields(body)
	rec := Record{
		Org:     whoisOrg(fields),
		NetName: firstValue(fields, "netname"),
		Country: cleanCountry(firstValue(fields, "country")),
		ASN:     cleanASN(firstValue(fields, "originas", "origin", "aut-num")),
	}
	rec.CIDR = mostSpecificPrefix(parsed, append(fields["cidr"], fields["route"]...))
	if rec.CIDR == "" {
		rec.CIDR = mostSpecificPrefix(parsed, fields["route6"])
	}
	if rec.CIDR == "" {
		rec.CIDR = rangeLabel(parsed, append(fields["inetnum"], fields["inet6num"]...))
	}
	if rec.CIDR == "" {
		rec.CIDR = rangeLabel(parsed, fields["netrange"])
	}
	return rec
}

func whoisFields(body string) map[string][]string {
	out := make(map[string][]string)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if key == "" || val == "" {
			continue
		}
		out[key] = append(out[key], val)
	}
	return out
}

func whoisOrg(fields map[string][]string) string {
	for _, key := range []string{"orgname", "org-name", "organization", "owner", "descr"} {
		if org := cleanOrg(firstValue(fields, key)); org != "" {
			return org
		}
	}
	org := cleanOrg(firstValue(fields, "organisation"))
	if org == "" || strings.HasPrefix(strings.ToUpper(org), "ORG-") || strings.HasPrefix(strings.ToLower(org), "administered by ") {
		return ""
	}
	return org
}

func firstValue(fields map[string][]string, keys ...string) string {
	for _, key := range keys {
		if len(fields[key]) > 0 {
			return fields[key][0]
		}
	}
	return ""
}

func cleanOrg(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, " ("); i > 0 && strings.HasSuffix(s, ")") {
		handle := s[i+2 : len(s)-1]
		if handle != "" && !strings.Contains(handle, " ") {
			s = strings.TrimSpace(s[:i])
		}
	}
	return s
}

func cleanCountry(s string) string {
	s = strings.TrimSpace(s)
	if len(s) == 2 {
		return strings.ToUpper(s)
	}
	return s
}

func cleanASN(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	tok := strings.Trim(strings.Fields(s)[0], ",;")
	up := strings.ToUpper(tok)
	if strings.HasPrefix(up, "AS") {
		up = strings.TrimPrefix(up, "AS")
	}
	if up == "" || !digitsOnly(up) {
		return ""
	}
	return "AS" + up
}

func digitsOnly(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func mostSpecificPrefix(ip net.IP, vals []string) string {
	if ip == nil {
		return ""
	}
	bestLen := -1
	best := ""
	for _, raw := range vals {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			_, network, err := net.ParseCIDR(part)
			if err != nil || !prefixContains(network, ip) {
				continue
			}
			ones, _ := network.Mask.Size()
			if ones > bestLen {
				bestLen = ones
				best = network.String()
			}
		}
	}
	return best
}

func prefixContains(network *net.IPNet, ip net.IP) bool {
	if network.IP.To4() != nil {
		if v4 := ip.To4(); v4 != nil {
			return network.Contains(v4)
		}
	}
	return network.Contains(ip)
}

func rangeLabel(ip net.IP, vals []string) string {
	if ip == nil {
		return ""
	}
	for _, raw := range vals {
		start, end, ok := parseIPRange(raw)
		if !ok || !ipInRange(start, end, ip) {
			continue
		}
		if cidr, ok := onePrefix(start, end); ok {
			return cidr
		}
		return start.String() + "-" + end.String()
	}
	return ""
}

func parseIPRange(raw string) (net.IP, net.IP, bool) {
	parts := strings.Split(raw, "-")
	if len(parts) != 2 {
		return nil, nil, false
	}
	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil {
		return nil, nil, false
	}
	return start, end, true
}

func ipInRange(start, end, ip net.IP) bool {
	s, e, p := alignIP(start, end, ip)
	if s == nil {
		return false
	}
	return bytesCompare(p, s) >= 0 && bytesCompare(p, e) <= 0
}

func alignIP(start, end, ip net.IP) (net.IP, net.IP, net.IP) {
	if start.To4() != nil && end.To4() != nil && ip.To4() != nil {
		return start.To4(), end.To4(), ip.To4()
	}
	if start.To16() == nil || end.To16() == nil || ip.To16() == nil {
		return nil, nil, nil
	}
	return start.To16(), end.To16(), ip.To16()
}

func onePrefix(start, end net.IP) (string, bool) {
	bits := 128
	if start.To4() != nil && end.To4() != nil {
		start, end = start.To4(), end.To4()
		bits = 32
	} else {
		start, end = start.To16(), end.To16()
	}
	if start == nil || end == nil || len(start) != len(end) {
		return "", false
	}
	for n := bits; n >= 0; n-- {
		mask := net.CIDRMask(n, bits)
		network := start.Mask(mask)
		if !network.Equal(start) {
			continue
		}
		last := make(net.IP, len(start))
		for i := range start {
			last[i] = network[i] | ^mask[i]
		}
		if last.Equal(end) {
			return fmt.Sprintf("%s/%d", network.String(), n), true
		}
	}
	return "", false
}

func bytesCompare(a, b net.IP) int {
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
