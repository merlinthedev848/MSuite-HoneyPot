package nginxlog

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"strings"
)

// Candidate is one scanner address worth adding to the blacklist.
type Candidate struct {
	IP     string
	Method string
	Path   string
	Agent  string
}

// Summary is the result of one pass over a log. It does not follow the file.
type Summary struct {
	Parsed           int
	Unparsed         int
	SkippedLocal     int
	SkippedOwn       int
	SkippedWhitelist int
	SkippedNormal    int
	Candidates       []Candidate
}

var (
	// combined matches the common nginx combined access line.
	combined = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"([A-Z]+)\s+(\S+)(?:\s+[^"]*)?"\s+(\d{3})(?:\s+\S+\s+"[^"]*"\s+"([^"]*)")?`)
	lanNet   *net.IPNet
	probes   = []string{
		"wp-login", "wp-admin", "xmlrpc.php", "wp-config",
		".env", ".git", ".svn", ".aws", ".htaccess", ".htpasswd",
		"phpmyadmin", "/pma", "cgi-bin", "boaform", "hnap1",
		"phpunit", "/actuator", "/solr", "manager/html",
		"phpinfo", "etc/passwd", "eval-stdin", "shell.php",
		"/../", "%00", "thinkphp", "invokefunction",
		"/telescope", "/debug/default",
	}
)

func init() {
	_, lanNet, _ = net.ParseCIDR("10.0.0.0/24")
}

// Summarize reads an nginx access log once. 10.0.0.0/24 is always skipped.
// own addresses and whitelist nets are skipped as well. Lines that look like
// ordinary requests to a real site are not imported.
func Summarize(r io.Reader, own []string, whitelist []*net.IPNet) Summary {
	ownSet := map[string]struct{}{}
	for _, addr := range own {
		if ip := net.ParseIP(strings.TrimSpace(addr)); ip != nil {
			ownSet[ip.String()] = struct{}{}
		}
	}
	var sum Summary
	seen := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ip, method, path, agent, ok := parseLine(line)
		if !ok {
			sum.Unparsed++
			continue
		}
		sum.Parsed++
		parsed := net.ParseIP(ip)
		if parsed == nil {
			sum.Unparsed++
			sum.Parsed--
			continue
		}
		ip = parsed.String()
		switch {
		case lanNet != nil && lanNet.Contains(parsed):
			sum.SkippedLocal++
			continue
		case containsIP(ownSet, ip):
			sum.SkippedOwn++
			continue
		case listed(whitelist, parsed):
			sum.SkippedWhitelist++
			continue
		case !isProbe(method, path):
			sum.SkippedNormal++
			continue
		}
		if idx, ok := seen[ip]; ok {
			sum.Candidates[idx].Method = method
			sum.Candidates[idx].Path = path
			if agent != "" {
				sum.Candidates[idx].Agent = agent
			}
			continue
		}
		seen[ip] = len(sum.Candidates)
		sum.Candidates = append(sum.Candidates, Candidate{
			IP:     ip,
			Method: method,
			Path:   path,
			Agent:  agent,
		})
	}
	return sum
}

func parseLine(line string) (ip, method, path, agent string, ok bool) {
	m := combined.FindStringSubmatch(line)
	if m == nil {
		return "", "", "", "", false
	}
	target := m[3]
	if i := strings.IndexByte(target, '?'); i >= 0 {
		target = target[:i]
	}
	if target == "" {
		target = "/"
	}
	return m[1], m[2], target, m[5], true
}

func isProbe(method, path string) bool {
	switch method {
	case "GET", "HEAD", "POST", "OPTIONS":
	default:
		return true
	}
	p := strings.ToLower(path)
	for _, token := range probes {
		if strings.Contains(p, token) {
			return true
		}
	}
	return false
}

func containsIP(set map[string]struct{}, ip string) bool {
	_, ok := set[ip]
	return ok
}

func listed(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
