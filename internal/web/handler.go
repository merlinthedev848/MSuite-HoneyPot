package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"

	"github.com/merlinthedev848/msuite-honeypot/internal/config"
	"github.com/merlinthedev848/msuite-honeypot/internal/mikrotik"
	"github.com/merlinthedev848/msuite-honeypot/internal/store"
)

//go:embed static/*
var staticFS embed.FS

type DashboardHandler struct {
	cfg      *config.Config
	store    *store.Store
	mtClient *mikrotik.Client
	fileSys  http.Handler
}

func NewDashboardHandler(cfg *config.Config, st *store.Store, mt *mikrotik.Client) *DashboardHandler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}

	return &DashboardHandler{
		cfg:      cfg,
		store:    st,
		mtClient: mt,
		fileSys:  http.FileServer(http.FS(sub)),
	}
}

func (h *DashboardHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/", h.fileSys)
	mux.HandleFunc("/api/stats", h.handleStats)
	mux.HandleFunc("/api/events", h.handleEvents)
	mux.HandleFunc("/api/stream", h.handleStream)
	mux.HandleFunc("/api/mikrotik/status", h.handleMikroTikStatus)
	mux.HandleFunc("/api/block", h.handleBlock)
	mux.HandleFunc("/api/unblock", h.handleUnblock)
}

func (h *DashboardHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.store.GetStats())
}

func (h *DashboardHandler) handleEvents(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.store.GetRecentEvents(limit))
}

func (h *DashboardHandler) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := h.store.Subscribe()
	defer h.store.Unsubscribe(ch)

	notify := r.Context().Done()

	for {
		select {
		case <-notify:
			return
		case ev := <-ch:
			data, err := json.Marshal(ev)
			if err == nil {
				fmt.Fprintf(w, "data: %s\n\n", string(data))
				flusher.Flush()
			}
		}
	}
}

func (h *DashboardHandler) handleMikroTikStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	res, err := h.mtClient.TestConnection()
	resp := map[string]interface{}{
		"host":      h.cfg.MikroTikHost,
		"list_name": h.cfg.MikroTikList,
		"timeout":   h.cfg.MikroTikTimeout,
		"connected": err == nil,
	}
	if err != nil {
		resp["error"] = err.Error()
	} else {
		resp["resource"] = res
	}
	_ = json.NewEncoder(w).Encode(resp)
}

type manualBlockReq struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

func (h *DashboardHandler) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req manualBlockReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "Manual block from dashboard"
	}

	err := h.mtClient.BlockIP(req.IP, reason)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{"status": "blocked", "ip": req.IP})
}

func (h *DashboardHandler) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req manualBlockReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := h.mtClient.UnblockIP(req.IP)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{"status": "unblocked", "ip": req.IP})
}
