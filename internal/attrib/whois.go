package attrib

import (
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// referralLine is the RIR pointer in an IANA or thin WHOIS reply.
var referralLine = regexp.MustCompile(`(?im)^(?:whois|refer|referralserver):\s*(?:r?whois://)?([a-z0-9.-]+)`)

func fetchWHOIS(ctx context.Context, ip string) (string, error) {
	server := "whois.iana.org"
	seen := map[string]bool{}
	var last string
	for i := 0; i < 4; i++ {
		host := strings.ToLower(strings.TrimSuffix(server, "."))
		if host == "" || seen[host] {
			break
		}
		seen[host] = true
		body, err := whoisQuery(ctx, host, ip)
		if err != nil {
			if last != "" {
				return last, nil
			}
			return "", err
		}
		next := referralHost(body)
		if host == "whois.iana.org" {
			if next == "" || strings.EqualFold(next, host) {
				return "", fmt.Errorf("whois: no RIR referral for %s", ip)
			}
			server = next
			continue
		}
		last = body
		parsed := ParseWHOIS(body, ip)
		if next == "" || strings.EqualFold(next, host) || (parsed.Org != "" && parsed.CIDR != "") {
			return body, nil
		}
		server = next
	}
	if last == "" {
		return "", fmt.Errorf("whois: no record for %s", ip)
	}
	return last, nil
}

func referralHost(body string) string {
	m := referralLine.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(m[1]), ".")
}

func whoisQuery(ctx context.Context, server, query string) (string, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(3 * time.Second)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(conn, 64*1024))
	if len(body) == 0 {
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("whois: empty reply from %s", server)
	}
	return string(body), nil
}
