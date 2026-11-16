package nginxlog

import (
	"net"
	"strings"
	"testing"
)

func TestSummarizeSkipsLANOwnAndNormalTraffic(t *testing.T) {
	log := strings.Join([]string{
		`10.0.0.50 - - [16/Nov/2026:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 100 "-" "lan"`,
		`10.0.0.194 - - [16/Nov/2026:12:00:01 +0000] "GET /.env HTTP/1.1" 200 20 "-" "honeypot"`,
		`192.0.2.50 - - [16/Nov/2026:12:00:02 +0000] "GET /wp-admin/ HTTP/1.1" 404 20 "-" "own"`,
		`192.168.1.10 - - [16/Nov/2026:12:00:03 +0000] "GET /wp-login.php HTTP/1.1" 404 20 "-" "rfc1918"`,
		`198.51.100.8 - - [16/Nov/2026:12:00:04 +0000] "GET / HTTP/1.1" 200 500 "-" "browser"`,
		`198.51.100.8 - - [16/Nov/2026:12:00:05 +0000] "GET /favicon.ico HTTP/1.1" 404 0 "-" "browser"`,
		`203.0.113.10 - - [16/Nov/2026:12:00:06 +0000] "GET /wp-login.php HTTP/1.1" 200 100 "-" "scanner"`,
		`203.0.113.10 - - [16/Nov/2026:12:00:07 +0000] "GET /.env HTTP/1.1" 404 20 "-" "scanner"`,
		`203.0.113.20 - - [16/Nov/2026:12:00:08 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 20 "-" "scanner"`,
		`this is not a log line`,
	}, "\n")
	_, lan, _ := net.ParseCIDR("192.168.0.0/16")
	sum := Summarize(strings.NewReader(log), []string{"192.0.2.50", "10.0.0.194"}, []*net.IPNet{lan})
	if sum.SkippedLocal != 2 {
		t.Fatalf("local skips = %d, want 2 (10.0.0.0/24)", sum.SkippedLocal)
	}
	if sum.SkippedOwn != 1 {
		t.Fatalf("own skips = %d", sum.SkippedOwn)
	}
	if sum.SkippedWhitelist != 1 {
		t.Fatalf("whitelist skips = %d", sum.SkippedWhitelist)
	}
	if sum.SkippedNormal != 2 {
		t.Fatalf("normal skips = %d", sum.SkippedNormal)
	}
	if sum.Unparsed != 1 {
		t.Fatalf("unparsed = %d", sum.Unparsed)
	}
	if len(sum.Candidates) != 2 {
		t.Fatalf("candidates = %+v", sum.Candidates)
	}
	if sum.Candidates[0].IP != "203.0.113.10" || sum.Candidates[0].Path != "/.env" {
		t.Fatalf("first candidate = %+v, want the later probe path for that IP", sum.Candidates[0])
	}
	if sum.Candidates[1].IP != "203.0.113.20" || sum.Candidates[1].Path != "/phpmyadmin/" {
		t.Fatalf("second candidate = %+v", sum.Candidates[1])
	}
}

func TestApplyCountsBlockFailures(t *testing.T) {
	sum := Summary{Candidates: []Candidate{{IP: "203.0.113.10", Method: "GET", Path: "/.env"}}}
	res := Apply(sum, failBlock{}, nil)
	if res.Imported != 0 || res.Failed != 1 {
		t.Fatalf("result = %+v", res)
	}
}

type failBlock struct{}

func (failBlock) BlockIP(ip, reason string) error { return errBlock }

type errBlockT string

func (e errBlockT) Error() string { return string(e) }

const errBlock errBlockT = "router down"
