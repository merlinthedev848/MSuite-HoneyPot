package attrib

import (
	"context"
	"net"
	"strings"
)

// Info is what the dashboard shows for one attacker address.
type Info struct {
	IP      string
	PTR     string
	Org     string
	NetName string
	Country string
	CIDR    string
	ASN     string
}

// Owner is the organisation, or the netname when WHOIS has no org.
func (i Info) Owner() string {
	if i.Org != "" {
		return i.Org
	}
	return i.NetName
}

// Lookup resolves PTR and WHOIS for ip. A failure leaves the missing fields
// blank and does not return an error.
func Lookup(ctx context.Context, ip string) Info {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return Info{}
	}
	info := Info{IP: parsed.String()}
	info.PTR = lookupPTR(ctx, parsed)
	if !whoisWorthQuerying(parsed) {
		return info
	}
	body, err := fetchWHOIS(ctx, parsed.String())
	if err != nil || strings.TrimSpace(body) == "" {
		return info
	}
	rec := ParseWHOIS(body, parsed.String())
	info.Org = rec.Org
	info.NetName = rec.NetName
	info.Country = rec.Country
	info.CIDR = rec.CIDR
	info.ASN = rec.ASN
	return info
}

func lookupPTR(ctx context.Context, ip net.IP) string {
	resolver := &net.Resolver{PreferGo: true}
	names, err := resolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func whoisWorthQuerying(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}
