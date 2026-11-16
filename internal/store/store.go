package store

import (
	"sync"
	"time"
)

type AttackEvent struct {
	ID        int64             `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	ClientIP  string            `json:"client_ip"`
	Method    string            `json:"method"`
	Host      string            `json:"host"`
	Path      string            `json:"path"`
	Query     string            `json:"query,omitempty"`
	UserAgent string            `json:"user_agent"`
	Headers   map[string]string `json:"headers,omitempty"`
	Payload   string            `json:"payload,omitempty"`
	Blocked   bool              `json:"blocked"`
	Reason    string            `json:"reason"`

	// Attribution. Empty when the lookup failed.
	Owner   string `json:"owner,omitempty"`
	PTR     string `json:"ptr,omitempty"`
	Org     string `json:"org,omitempty"`
	NetName string `json:"netname,omitempty"`
	Country string `json:"country,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	ASN     string `json:"asn,omitempty"`
}

// NetworkRange groups attackers that share one WHOIS prefix.
type NetworkRange struct {
	CIDR       string    `json:"cidr"`
	Org        string    `json:"org"`
	ASN        string    `json:"asn,omitempty"`
	Country    string    `json:"country,omitempty"`
	Hits       int64     `json:"hits"`
	IPCount    int       `json:"ip_count"`
	LatestHost string    `json:"latest_host"`
	LatestPath string    `json:"latest_path"`
	Latest     time.Time `json:"latest"`
}

// RouterBlock is one address still present on the MikroTik list.
type RouterBlock struct {
	Address string `json:"address"`
	Timeout string `json:"timeout,omitempty"`
	Comment string `json:"comment,omitempty"`
}

type Stats struct {
	TotalAttacks    int64            `json:"total_attacks"`
	BlockedIPsCount int              `json:"blocked_ips_count"`
	RouterBlocks    []RouterBlock    `json:"router_blocks"`
	TopPaths        map[string]int64 `json:"top_paths"`
	TopUserAgents   map[string]int64 `json:"top_user_agents"`
	TopIPs          map[string]int64 `json:"top_ips"`
	LastAttackTime  time.Time        `json:"last_attack_time"`
}

type Store struct {
	lock         sync.RWMutex
	maxEvents    int
	events       []AttackEvent
	nextID       int64
	uniqueIPs    map[string]int64
	pathStats    map[string]int64
	uaStats      map[string]int64
	subscribers  map[chan AttackEvent]struct{}
	subsLock     sync.Mutex
	ranges       map[string]*rangeAccum
	routerBlocks []RouterBlock
}

type rangeAccum struct {
	org        string
	asn        string
	country    string
	hits       int64
	ips        map[string]struct{}
	latestHost string
	latestPath string
	latest     time.Time
}

func NewStore(maxEvents int) *Store {
	if maxEvents <= 0 {
		maxEvents = 1000
	}
	return &Store{
		maxEvents:   maxEvents,
		events:      make([]AttackEvent, 0, maxEvents),
		uniqueIPs:   make(map[string]int64),
		pathStats:   make(map[string]int64),
		uaStats:     make(map[string]int64),
		subscribers: make(map[chan AttackEvent]struct{}),
		ranges:      make(map[string]*rangeAccum),
	}
}

func (s *Store) AddEvent(event AttackEvent) AttackEvent {
	s.lock.Lock()
	s.nextID++
	event.ID = s.nextID
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Update stats
	s.uniqueIPs[event.ClientIP]++
	s.pathStats[event.Path]++
	if event.UserAgent != "" {
		s.uaStats[event.UserAgent]++
	}

	// Append to slice with cap
	if len(s.events) >= s.maxEvents {
		s.events = s.events[1:]
	}
	s.events = append(s.events, event)
	s.noteRange(event)
	s.lock.Unlock()

	// Broadcast to SSE subscribers
	s.subsLock.Lock()
	for ch := range s.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
	s.subsLock.Unlock()

	return event
}

// SetRouterBlocks replaces the dashboard copy of the MikroTik address list.
// The attack log stays empty across a restart; this list is what remains on the router.
func (s *Store) SetRouterBlocks(blocks []RouterBlock) {
	s.lock.Lock()
	defer s.lock.Unlock()
	next := make([]RouterBlock, len(blocks))
	copy(next, blocks)
	s.routerBlocks = next
}

func (s *Store) noteRange(event AttackEvent) {
	if event.CIDR == "" {
		return
	}
	acc := s.ranges[event.CIDR]
	if acc == nil {
		acc = &rangeAccum{ips: make(map[string]struct{})}
		s.ranges[event.CIDR] = acc
	}
	acc.hits++
	if event.ClientIP != "" {
		acc.ips[event.ClientIP] = struct{}{}
	}
	if acc.org == "" {
		if event.Org != "" {
			acc.org = event.Org
		} else {
			acc.org = event.Owner
		}
	}
	if acc.asn == "" {
		acc.asn = event.ASN
	}
	if acc.country == "" {
		acc.country = event.Country
	}
	if acc.latest.IsZero() || !event.Timestamp.Before(acc.latest) {
		acc.latest = event.Timestamp
		acc.latestHost = event.Host
		acc.latestPath = event.Path
	}
}

// GetRanges returns WHOIS prefixes ordered by hit count.
func (s *Store) GetRanges() []NetworkRange {
	s.lock.RLock()
	defer s.lock.RUnlock()

	out := make([]NetworkRange, 0, len(s.ranges))
	for cidr, acc := range s.ranges {
		out = append(out, NetworkRange{
			CIDR:       cidr,
			Org:        acc.org,
			ASN:        acc.asn,
			Country:    acc.country,
			Hits:       acc.hits,
			IPCount:    len(acc.ips),
			LatestHost: acc.latestHost,
			LatestPath: acc.latestPath,
			Latest:     acc.latest,
		})
	}
	for i := 0; i < len(out); i++ {
		best := i
		for j := i + 1; j < len(out); j++ {
			if out[j].Hits > out[best].Hits || (out[j].Hits == out[best].Hits && out[j].CIDR < out[best].CIDR) {
				best = j
			}
		}
		out[i], out[best] = out[best], out[i]
	}
	return out
}

func (s *Store) GetRecentEvents(limit int) []AttackEvent {
	s.lock.RLock()
	defer s.lock.RUnlock()

	n := len(s.events)
	if limit <= 0 || limit > n {
		limit = n
	}

	result := make([]AttackEvent, limit)
	for i := 0; i < limit; i++ {
		result[i] = s.events[n-1-i]
	}
	return result
}

func (s *Store) GetStats() Stats {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var lastTime time.Time
	if len(s.events) > 0 {
		lastTime = s.events[len(s.events)-1].Timestamp
	}

	// Top 10 paths
	topPaths := getTopN(s.pathStats, 10)
	topUAs := getTopN(s.uaStats, 10)
	topIPs := getTopN(s.uniqueIPs, 10)
	blocks := make([]RouterBlock, len(s.routerBlocks))
	copy(blocks, s.routerBlocks)

	return Stats{
		TotalAttacks:    s.nextID,
		BlockedIPsCount: len(blocks),
		RouterBlocks:    blocks,
		TopPaths:        topPaths,
		TopUserAgents:   topUAs,
		TopIPs:          topIPs,
		LastAttackTime:  lastTime,
	}
}

func getTopN(m map[string]int64, n int) map[string]int64 {
	out := make(map[string]int64)
	type kv struct {
		k string
		v int64
	}
	var pairs []kv
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	// Simple bubble/selection for top N
	for i := 0; i < len(pairs) && i < n; i++ {
		maxIdx := i
		for j := i + 1; j < len(pairs); j++ {
			if pairs[j].v > pairs[maxIdx].v {
				maxIdx = j
			}
		}
		pairs[i], pairs[maxIdx] = pairs[maxIdx], pairs[i]
		out[pairs[i].k] = pairs[i].v
	}
	return out
}

func (s *Store) Subscribe() chan AttackEvent {
	s.subsLock.Lock()
	defer s.subsLock.Unlock()
	ch := make(chan AttackEvent, 50)
	s.subscribers[ch] = struct{}{}
	return ch
}

func (s *Store) Unsubscribe(ch chan AttackEvent) {
	s.subsLock.Lock()
	defer s.subsLock.Unlock()
	delete(s.subscribers, ch)
	close(ch)
}
