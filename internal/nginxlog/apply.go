package nginxlog

import (
	"fmt"
	"log"

	"github.com/merlinthedev848/msuite-honeypot/internal/store"
)

// Blocker adds one address to the MikroTik list.
type Blocker interface {
	BlockIP(ip, reason string) error
}

// Result is what a one-time import did.
type Result struct {
	Imported         int      `json:"imported"`
	Failed           int      `json:"failed"`
	SkippedLocal     int      `json:"skipped_local"`
	SkippedOwn       int      `json:"skipped_own"`
	SkippedWhitelist int      `json:"skipped_whitelist"`
	SkippedNormal    int      `json:"skipped_normal"`
	Unparsed         int      `json:"unparsed"`
	IPs              []string `json:"ips"`
}

// Apply nullroutes the probe addresses from one summary. It does not tail a log.
// A failed block is counted and does not stop the rest of the import.
func Apply(sum Summary, block Blocker, st *store.Store) Result {
	out := Result{
		SkippedLocal:     sum.SkippedLocal,
		SkippedOwn:       sum.SkippedOwn,
		SkippedWhitelist: sum.SkippedWhitelist,
		SkippedNormal:    sum.SkippedNormal,
		Unparsed:         sum.Unparsed,
		IPs:              []string{},
	}
	for _, c := range sum.Candidates {
		reason := fmt.Sprintf("nginx import %s %s", c.Method, c.Path)
		err := error(nil)
		if block != nil {
			err = block.BlockIP(c.IP, reason)
		}
		blocked := err == nil
		if err != nil {
			out.Failed++
			log.Printf("[Import] Could not block %s: %v", c.IP, err)
		} else {
			out.Imported++
			out.IPs = append(out.IPs, c.IP)
		}
		if st != nil {
			st.AddEvent(store.AttackEvent{
				ClientIP:  c.IP,
				Method:    c.Method,
				Path:      c.Path,
				UserAgent: c.Agent,
				Blocked:   blocked,
				Reason:    reason,
			})
		}
	}
	return out
}
