package store

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

type snapshot struct {
	Events   []AttackEvent `json:"events"`
	Reported []string      `json:"abuseipdb_reported,omitempty"`
}

// SetStatePath enables saving the attack feed. An empty path keeps it in memory only.
func (s *Store) SetStatePath(path string) {
	s.saveMu.Lock()
	s.statePath = path
	s.saveMu.Unlock()
}

// Load reads a previously saved attack feed. A missing file is not an error.
// The MikroTik address list is not stored here.
func (s *Store) Load(path string) error {
	s.SetStatePath(path)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.events = nil
	s.uniqueIPs = make(map[string]int64)
	s.pathStats = make(map[string]int64)
	s.uaStats = make(map[string]int64)
	s.ranges = make(map[string]*rangeAccum)
	s.reported = make(map[string]struct{})
	s.nextID = 0
	events := snap.Events
	if s.maxEvents > 0 && len(events) > s.maxEvents {
		events = events[len(events)-s.maxEvents:]
	}
	for _, ev := range events {
		if ev.ID > s.nextID {
			s.nextID = ev.ID
		}
		s.uniqueIPs[ev.ClientIP]++
		s.pathStats[ev.Path]++
		if ev.UserAgent != "" {
			s.uaStats[ev.UserAgent]++
		}
		s.events = append(s.events, ev)
		s.noteRange(ev)
	}
	for _, ip := range snap.Reported {
		if ip != "" {
			s.reported[ip] = struct{}{}
		}
	}
	return nil
}

func (s *Store) snapshotLocked() snapshot {
	events := make([]AttackEvent, len(s.events))
	copy(events, s.events)
	reported := make([]string, 0, len(s.reported))
	for ip := range s.reported {
		reported = append(reported, ip)
	}
	return snapshot{Events: events, Reported: reported}
}

func (s *Store) writeSnapshot(snap snapshot) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.statePath == "" {
		return
	}
	if err := writeSnapshotFile(s.statePath, snap); err != nil {
		log.Printf("[State] Could not save attack feed: %v", err)
	}
}

func writeSnapshotFile(path string, snap snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
