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
}

type Stats struct {
	TotalAttacks    int64            `json:"total_attacks"`
	BlockedIPsCount int              `json:"blocked_ips_count"`
	TopPaths        map[string]int64 `json:"top_paths"`
	TopUserAgents   map[string]int64 `json:"top_user_agents"`
	TopIPs          map[string]int64 `json:"top_ips"`
	LastAttackTime  time.Time        `json:"last_attack_time"`
}

type Store struct {
	lock          sync.RWMutex
	maxEvents     int
	events        []AttackEvent
	nextID        int64
	uniqueIPs     map[string]int64
	pathStats     map[string]int64
	uaStats       map[string]int64
	subscribers   map[chan AttackEvent]struct{}
	subsLock      sync.Mutex
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

	return Stats{
		TotalAttacks:    s.nextID,
		BlockedIPsCount: len(s.uniqueIPs),
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
