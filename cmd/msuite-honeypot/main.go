package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/merlinthedev848/msuite-honeypot/internal/attrib"
	"github.com/merlinthedev848/msuite-honeypot/internal/config"
	"github.com/merlinthedev848/msuite-honeypot/internal/honeypot"
	"github.com/merlinthedev848/msuite-honeypot/internal/mikrotik"
	"github.com/merlinthedev848/msuite-honeypot/internal/nginxlog"
	"github.com/merlinthedev848/msuite-honeypot/internal/store"
	"github.com/merlinthedev848/msuite-honeypot/internal/web"
)

const Banner = `
=====================================================
  __  __  _____       _ _         _    _             
 |  \/  |/ ____|     (_) |       | |  | |            
 | \  / | (___  _   _ _| |_ ___  | |__| | ___  _ __  
 | |\/| |\___ \| | | | | __/ _ \ |  __  |/ _ \| '_ \ 
 | |  | |____) | |_| | | ||  __/ | |  | | (_) | |_) |
 |_|  |_|_____/ \__,_|_|\__\___| |_|  |_|\___/| .__/ 
                                              | |    
      Lightweight HoneyPot & MikroTik Nullrouter  |_|    
=====================================================
`

func main() {
	fmt.Print(Banner)

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("[FATAL] Failed to load config: %v", err)
	}

	log.Printf("[Config] Honeypot Listen Port: :%d", cfg.ListenPort)
	log.Printf("[Config] Dashboard Listen Port: :%d", cfg.DashboardPort)
	log.Printf("[Config] MikroTik REST %s (List: %s, Timeout: %s)",
		mikrotik.RESTBaseURL(cfg.MikroTikHost, cfg.MikroTikPort, cfg.MikroTikUseSSL), cfg.MikroTikList, cfg.MikroTikTimeout)
	log.Printf("[Config] Whitelisted Subnets: %d CIDRs loaded", len(cfg.ParsedWhitelist))

	// 1. Initialize store & mikrotik client. The attack feed is reloaded from disk.
	st := store.NewStore(2000)
	if err := st.Load(cfg.StatePath); err != nil {
		log.Printf("[State] Could not reload the attack feed: %v", err)
	} else {
		log.Printf("[State] Reloaded %d attack events from %s", len(st.GetRecentEvents(0)), cfg.StatePath)
	}
	mt := mikrotik.NewClient(cfg)

	if cfg.ImportOnce {
		if err := runImport(cfg, mt, st); err != nil {
			log.Fatalf("[Import] %v", err)
		}
		return
	}

	// Quick check of MikroTik, and reload addresses that are already on the list.
	go func() {
		res, err := mt.TestConnection()
		if err != nil {
			log.Printf("[MikroTik Warning] Initial check: %v (Check host/credentials)", err)
		} else {
			log.Printf("[MikroTik Connected] Router: %s, Board: %s, Uptime: %s, CPU Load: %s%%",
				res.Platform, res.Board, res.Uptime, res.CPULoad)
		}
		entries, err := mt.ListBlocked()
		if err != nil {
			log.Printf("[MikroTik Warning] Could not read address list: %v", err)
			return
		}
		blocks := make([]store.RouterBlock, 0, len(entries))
		for _, entry := range entries {
			if entry.Address == "" {
				continue
			}
			blocks = append(blocks, store.RouterBlock{
				Address: entry.Address,
				Timeout: entry.Timeout,
				Comment: entry.Comment,
			})
		}
		st.SetRouterBlocks(blocks)
		log.Printf("[MikroTik] %s still has %d address-list entries", cfg.MikroTikList, len(blocks))
	}()

	// 2. Setup Honeypot HTTP Server (port 8080)
	engine := honeypot.NewEngine(cfg, mt, st, attrib.NewCache())
	hpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ListenPort),
		Handler:      engine,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// 3. Setup Dashboard HTTP Server (port 8081)
	dashMux := http.NewServeMux()
	dashHandler := web.NewDashboardHandler(cfg, st, mt)
	dashHandler.RegisterRoutes(dashMux)

	dashServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.DashboardPort),
		Handler:      dashMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Start Honeypot
	go func() {
		log.Printf("[Honeypot] Ingress listening on http://0.0.0.0:%d (Target for Nginx default_server)", cfg.ListenPort)
		if err := hpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Honeypot Error] %v", err)
		}
	}()

	// Start Dashboard
	go func() {
		log.Printf("[Dashboard] Web UI listening on http://0.0.0.0:%d", cfg.DashboardPort)
		if err := dashServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Dashboard Error] %v", err)
		}
	}()

	// 4. Graceful Shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("\n[System] Shutting down MSuite-HoneyPot...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = hpServer.Shutdown(ctx)
	_ = dashServer.Shutdown(ctx)
	log.Println("[System] Servers stopped cleanly.")
}

// runImport reads one nginx access log and exits. It does not follow the file.
// "-" reads stdin so a log pasted from another machine can be imported.
func runImport(cfg *config.Config, mt *mikrotik.Client, st *store.Store) error {
	path := cfg.NginxLogFlag
	if path == "" {
		path = cfg.NginxAccessLog
	}
	var reader io.Reader
	if path == "-" {
		reader = os.Stdin
		log.Printf("[Import] Reading a pasted nginx access log from stdin")
	} else {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		reader = f
		log.Printf("[Import] Reading %s once", path)
	}
	sum := nginxlog.Summarize(reader, cfg.OwnAddresses, cfg.ParsedWhitelist)
	result := nginxlog.Apply(sum, mt, st)
	log.Printf("[Import] imported %d, failed %d, skipped local %d, own %d, whitelist %d, normal %d, unparsed %d",
		result.Imported, result.Failed, result.SkippedLocal, result.SkippedOwn, result.SkippedWhitelist, result.SkippedNormal, result.Unparsed)
	return nil
}
