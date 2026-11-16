package mikrotik

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/merlinthedev848/msuite-honeypot/internal/config"
)

func TestClientURLDefaultsToPort8728(t *testing.T) {
	c := NewClient(&config.Config{
		MikroTikEnabled: true,
		MikroTikHost:    "10.0.0.1",
	})

	if c.URL() != "10.0.0.1:8728" {
		t.Fatalf("URL = %q, want 10.0.0.1:8728", c.URL())
	}
	_, port, err := net.SplitHostPort(c.URL())
	if err != nil {
		t.Fatal(err)
	}
	if port != "8728" {
		t.Fatalf("port = %s, want 8728", port)
	}
	if port == "443" || port == "80" {
		t.Fatalf("default port must not be www/www-ssl, got %s", port)
	}
	if strings.Contains(c.URL(), "/rest") || strings.Contains(c.URL(), "https://") || strings.Contains(c.URL(), "http://") {
		t.Fatalf("URL still looks like the REST client: %s", c.URL())
	}
	if c.useTLS {
		t.Fatal("plaintext api is the default; api-ssl must be explicit")
	}
	if c.tlsConfig != nil && c.tlsConfig.InsecureSkipVerify {
		t.Fatal("default client must not skip TLS verification")
	}

	ssl := NewClient(&config.Config{
		MikroTikHost:   "10.0.0.1",
		MikroTikUseSSL: true,
	})
	if ssl.URL() != "10.0.0.1:8729" || !ssl.useTLS {
		t.Fatalf("unset port with api-ssl = %s tls=%v, want 10.0.0.1:8729", ssl.URL(), ssl.useTLS)
	}
	if ssl.tlsConfig == nil || ssl.tlsConfig.InsecureSkipVerify {
		t.Fatal("api-ssl must verify TLS unless skip_tls is set")
	}

	explicit := NewClient(&config.Config{
		MikroTikHost:    "10.0.0.1",
		MikroTikPort:    8729,
		MikroTikUseSSL:  true,
		MikroTikSkipTLS: true,
	})
	if explicit.URL() != "10.0.0.1:8729" || !explicit.useTLS || explicit.tlsConfig == nil || !explicit.tlsConfig.InsecureSkipVerify {
		t.Fatalf("explicit api-ssl = %s tls=%v skip=%v", explicit.URL(), explicit.useTLS, explicit.tlsConfig != nil && explicit.tlsConfig.InsecureSkipVerify)
	}
}

func TestLengthPrefixRoundTrip(t *testing.T) {
	lengths := []int{0, 1, 127, 128, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 0x0FFFFFFF, 0x10000000}
	for _, n := range lengths {
		got, err := readLen(bytes.NewReader(encodeLength(n)))
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		if got != n {
			t.Fatalf("len %d decoded as %d", n, got)
		}
	}
}

func TestSentenceRoundTrip(t *testing.T) {
	words := []string{"/ip/firewall/address-list/add", "=list=MSuite-Blacklist", "=address=203.0.113.10", "=timeout=7d"}
	var buf bytes.Buffer
	if err := writeSentence(&buf, words); err != nil {
		t.Fatal(err)
	}
	got, err := readSentence(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, "\n") != strings.Join(words, "\n") {
		t.Fatalf("sentence = %#v", got)
	}
}

func TestBinaryAPIBlockAndResource(t *testing.T) {
	router := startFakeRouter(t, "admin", "secret", false)
	defer router.close()

	cfg := &config.Config{
		MikroTikEnabled:  true,
		MikroTikHost:     "10.0.0.1",
		MikroTikUser:     "admin",
		MikroTikPassword: "secret",
		MikroTikList:     "MSuite-Blacklist",
		MikroTikTimeout:  "7d",
	}
	c := NewClient(cfg)
	if c.URL() != "10.0.0.1:8728" {
		t.Fatalf("URL = %s", c.URL())
	}
	c.dial = router.dial

	res, err := c.TestConnection()
	if err != nil {
		t.Fatal(err)
	}
	if res.Board != "RB5009" || res.BoardName != "RB5009" || res.Uptime != "4d1h" || res.CPULoad != "3" || res.Version != "7.16.2" || res.Platform != "MikroTik" {
		t.Fatalf("resource = %+v", res)
	}

	if err := c.BlockIP("203.0.113.10", "GET /.env"); err != nil {
		t.Fatal(err)
	}
	if err := c.BlockIP("203.0.113.10", "GET /.env"); err != nil {
		t.Fatal(err)
	}
	adds := router.commandsWithPrefix("/ip/firewall/address-list/add")
	if len(adds) != 1 {
		t.Fatalf("add commands = %d, want 1 (second call is cached)", len(adds))
	}
	joined := strings.Join(adds[0], " ")
	for _, want := range []string{"=list=MSuite-Blacklist", "=address=203.0.113.10", "=timeout=7d", "=comment=MSuite Honeypot: GET /.env"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("add sentence %q missing %q", joined, want)
		}
	}

	if err := c.BlockIP("203.0.113.99", "duplicate"); err != nil {
		t.Fatalf("already-present trap should be success: %v", err)
	}

	entries, err := c.ListBlocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Address != "203.0.113.10" || entries[0].List != "MSuite-Blacklist" {
		t.Fatalf("entries = %+v", entries)
	}

	if err := c.UnblockIP("203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	entries, err = c.ListBlocked()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries after unblock = %+v", entries)
	}

	cmds := router.snapshot()
	sawResource := false
	for _, cmd := range cmds {
		if len(cmd) > 0 && cmd[0] == "/system/resource/print" {
			sawResource = true
		}
		for _, w := range cmd {
			if strings.Contains(w, "/rest") || strings.Contains(w, "www-ssl") {
				t.Fatalf("binary API command looks like REST: %v", cmd)
			}
		}
	}
	if !sawResource {
		t.Fatal("health check did not send /system/resource/print")
	}
}

func TestLegacyLoginChallenge(t *testing.T) {
	router := startFakeRouter(t, "admin", "secret", true)
	defer router.close()

	c := NewClient(&config.Config{
		MikroTikEnabled:  true,
		MikroTikHost:     "10.0.0.1",
		MikroTikPort:     DefaultPort,
		MikroTikUser:     "admin",
		MikroTikPassword: "secret",
		MikroTikList:     "MSuite-Blacklist",
		MikroTikTimeout:  "7d",
	})
	c.dial = router.dial
	if _, err := c.TestConnection(); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionErrorUsesAPIPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	c := NewClient(&config.Config{
		MikroTikEnabled:  true,
		MikroTikHost:     "10.0.0.1",
		MikroTikUser:     "admin",
		MikroTikPassword: "secret",
	})
	c.dial = func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	_, err = c.TestConnection()
	if err == nil {
		t.Fatal("expected dial error")
	}
	if !strings.Contains(err.Error(), "10.0.0.1:8728") {
		t.Fatalf("error %q does not name the api endpoint", err)
	}
	if strings.Contains(err.Error(), ":443") || strings.Contains(err.Error(), "/rest") {
		t.Fatalf("error still describes REST: %v", err)
	}
}

type fakeRouter struct {
	t        *testing.T
	user     string
	pass     string
	legacy   bool
	ln       net.Listener
	mu       sync.Mutex
	entries  map[string]map[string]string
	commands [][]string
	nextID   int
}

func startFakeRouter(t *testing.T, user, pass string, legacy bool) *fakeRouter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRouter{
		t:       t,
		user:    user,
		pass:    pass,
		legacy:  legacy,
		ln:      ln,
		entries: make(map[string]map[string]string),
	}
	go f.serve()
	return f
}

func (f *fakeRouter) close() {
	_ = f.ln.Close()
}

func (f *fakeRouter) dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", f.ln.Addr().String())
}

func (f *fakeRouter) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeRouter) handle(conn net.Conn) {
	defer conn.Close()
	if f.legacy {
		if err := f.loginLegacy(conn); err != nil {
			return
		}
	} else if err := f.loginModern(conn); err != nil {
		return
	}
	for {
		words, err := readSentence(conn)
		if err != nil {
			return
		}
		if len(words) == 0 {
			continue
		}
		f.mu.Lock()
		f.commands = append(f.commands, append([]string(nil), words...))
		f.mu.Unlock()
		if err := f.dispatch(conn, words); err != nil {
			return
		}
	}
}

func (f *fakeRouter) loginModern(conn net.Conn) error {
	words, err := readSentence(conn)
	if err != nil {
		return err
	}
	if len(words) == 0 || words[0] != "/login" {
		_ = writeSentence(conn, []string{"!trap", "=message=expected /login"})
		_ = writeSentence(conn, []string{"!done"})
		return io.EOF
	}
	gotUser, gotPass := "", ""
	for _, w := range words[1:] {
		if k, v, ok := parseAttribute(w); ok {
			switch k {
			case "name":
				gotUser = v
			case "password":
				gotPass = v
			}
		}
	}
	if gotUser != f.user || gotPass != f.pass {
		_ = writeSentence(conn, []string{"!trap", "=message=invalid user name or password"})
		_ = writeSentence(conn, []string{"!done"})
		return io.EOF
	}
	return writeSentence(conn, []string{"!done"})
}

func (f *fakeRouter) loginLegacy(conn net.Conn) error {
	words, err := readSentence(conn)
	if err != nil {
		return err
	}
	if len(words) == 0 || words[0] != "/login" {
		return io.EOF
	}
	const challenge = "aabbccddeeff00112233445566778899"
	if err := writeSentence(conn, []string{"!done", "=ret=" + challenge}); err != nil {
		return err
	}
	words, err = readSentence(conn)
	if err != nil {
		return err
	}
	raw, _ := hex.DecodeString(challenge)
	sum := md5.Sum(append(append([]byte{0}, []byte(f.pass)...), raw...))
	want := "00" + hex.EncodeToString(sum[:])
	var got string
	for _, w := range words {
		if k, v, ok := parseAttribute(w); ok && k == "response" {
			got = v
		}
	}
	if got != want {
		_ = writeSentence(conn, []string{"!trap", "=message=invalid legacy response"})
		_ = writeSentence(conn, []string{"!done"})
		return io.EOF
	}
	if want != "00a8bfd49490a32a90532cbac11691aae2" {
		f.t.Errorf("legacy vector drifted: %s", want)
	}
	return writeSentence(conn, []string{"!done"})
}

func (f *fakeRouter) dispatch(conn net.Conn, words []string) error {
	switch words[0] {
	case "/system/resource/print":
		if err := writeSentence(conn, []string{
			"!re",
			"=uptime=4d1h",
			"=version=7.16.2",
			"=platform=MikroTik",
			"=board-name=RB5009",
			"=cpu=ARM64",
			"=cpu-load=3",
		}); err != nil {
			return err
		}
		return writeSentence(conn, []string{"!done"})
	case "/ip/firewall/address-list/add":
		attrs := sentenceAttrs(words)
		if attrs["address"] == "203.0.113.99" {
			if err := writeSentence(conn, []string{"!trap", "=message=failure: already have such entry"}); err != nil {
				return err
			}
			return writeSentence(conn, []string{"!done"})
		}
		f.mu.Lock()
		f.nextID++
		id := "*" + hex.EncodeToString([]byte{byte(f.nextID)})
		attrs[".id"] = id
		if attrs["list"] == "" {
			attrs["list"] = "MSuite-Blacklist"
		}
		f.entries[attrs["address"]] = attrs
		f.mu.Unlock()
		return writeSentence(conn, []string{"!done", "=ret=" + id})
	case "/ip/firewall/address-list/print":
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, rec := range f.entries {
			if !matchQuery(rec, words) {
				continue
			}
			reply := []string{"!re", "=.id=" + rec[".id"], "=list=" + rec["list"], "=address=" + rec["address"]}
			if rec["timeout"] != "" {
				reply = append(reply, "=timeout="+rec["timeout"])
			}
			if rec["comment"] != "" {
				reply = append(reply, "=comment="+rec["comment"])
			}
			if err := writeSentence(conn, reply); err != nil {
				return err
			}
		}
		return writeSentence(conn, []string{"!done"})
	case "/ip/firewall/address-list/remove":
		attrs := sentenceAttrs(words)
		f.mu.Lock()
		for addr, rec := range f.entries {
			if rec[".id"] == attrs[".id"] {
				delete(f.entries, addr)
			}
		}
		f.mu.Unlock()
		return writeSentence(conn, []string{"!done"})
	default:
		if err := writeSentence(conn, []string{"!trap", "=message=unknown command " + words[0]}); err != nil {
			return err
		}
		return writeSentence(conn, []string{"!done"})
	}
}

func sentenceAttrs(words []string) map[string]string {
	out := make(map[string]string)
	for _, w := range words[1:] {
		if k, v, ok := parseAttribute(w); ok {
			out[k] = v
		}
	}
	return out
}

func matchQuery(rec map[string]string, words []string) bool {
	for _, w := range words[1:] {
		if !strings.HasPrefix(w, "?") || strings.HasPrefix(w, "?=") {
			continue
		}
		body := strings.TrimPrefix(w, "?")
		k, v, ok := strings.Cut(body, "=")
		if !ok {
			continue
		}
		if rec[k] != v {
			return false
		}
	}
	return true
}

func (f *fakeRouter) snapshot() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.commands))
	copy(out, f.commands)
	return out
}

func (f *fakeRouter) commandsWithPrefix(prefix string) [][]string {
	var out [][]string
	for _, cmd := range f.snapshot() {
		if len(cmd) > 0 && cmd[0] == prefix {
			out = append(out, cmd)
		}
	}
	return out
}
