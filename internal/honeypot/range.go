package honeypot

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

func (e *Engine) considerPrefix(cidr string, whitelisted bool) {
	if whitelisted || cidr == "" || e.mtClient == nil || e.store == nil || e.cfg == nil {
		return
	}
	window := e.cfg.RangeWindow()
	distinct := e.store.DistinctIPsSince(cidr, time.Now().Add(-window))
	prefix, ok := PrefixToBlock(cidr, distinct, e.cfg.RangeMinIPs())
	if !ok {
		return
	}
	reason := fmt.Sprintf("%d distinct addresses in %s", distinct, window)
	if err := e.mtClient.BlockIP(prefix, reason); err != nil {
		log.Printf("[MikroTik Error] Could not block prefix %s: %v", prefix, err)
		return
	}
	log.Printf("[MikroTik] Range floor reached for %s (%s)", prefix, reason)
}

// lanNet is the site LAN. A prefix block must never cover it.
var lanNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("10.0.0.0/24")
	return n
}()

// PrefixToBlock decides whether a WHOIS prefix may be nullrouted.
// One address is never enough. 10.0.0.0/24 is never blocked, nor is any
// prefix that contains it. Prefixes broader than an IPv4 /24 or an IPv6 /64
// are left alone so a handful of hits cannot blackhole a huge network.
func PrefixToBlock(cidr string, distinct, min int) (string, bool) {
	if min < 2 {
		min = 2
	}
	if distinct < min {
		return "", false
	}
	ip, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ip == nil || network == nil {
		return "", false
	}
	ones, bits := network.Mask.Size()
	if bits != 32 && bits != 128 {
		return "", false
	}
	if bits == 32 && (ones < 24 || ones >= 32) {
		return "", false
	}
	if bits == 128 && (ones < 64 || ones >= 128) {
		return "", false
	}
	if lanNet != nil && (network.Contains(lanNet.IP) || lanNet.Contains(network.IP)) {
		return "", false
	}
	return network.String(), true
}
