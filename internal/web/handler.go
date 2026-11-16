package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/merlinthedev848/msuite-honeypot/internal/config"
	"github.com/merlinthedev848/msuite-honeypot/internal/mikrotik"
	"github.com/merlinthedev848/msuite-honeypot/internal/nginxlog"
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
	mux.HandleFunc("/api/ranges", h.handleRanges)
	mux.HandleFunc("/api/stream", h.handleStream)
	mux.HandleFunc("/api/mikrotik/status", h.handleMikroTikStatus)
	mux.HandleFunc("/api/block", h.handleBlock)
	mux.HandleFunc("/api/unblock", h.handleUnblock)
	mux.HandleFunc("/api/import-log", h.handleImportLog)
}

func (h *DashboardHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	h.syncRouterBlocks()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.store.GetStats())
}

// syncRouterBlocks copies the live MikroTik address list into the dashboard.
// A failed read keeps the previous copy so a blip does not blank the list.
func (h *DashboardHandler) syncRouterBlocks() {
	entries, err := h.mtClient.ListBlocked()
	if err != nil {
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
	h.store.SetRouterBlocks(blocks)
}

func (h *DashboardHandler) handleRanges(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.store.GetRanges())
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
		"port":      h.cfg.MikroTikPort,
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

func (h *DashboardHandler) handleImportLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reader, err := importBody(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sum := nginxlog.Summarize(reader, h.cfg.OwnAddresses, h.cfg.ParsedWhitelist)
	result := nginxlog.Apply(sum, h.mtClient, h.store)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func importBody(w http.ResponseWriter, r *http.Request) (io.Reader, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return nil, err
		}
		if f, _, err := r.FormFile("log"); err == nil {
			defer f.Close()
			buf, err := io.ReadAll(io.LimitReader(f, 32<<20))
			if err != nil {
				return nil, err
			}
			return bytes.NewReader(buf), nil
		}
		if text := r.FormValue("text"); strings.TrimSpace(text) != "" {
			return strings.NewReader(text), nil
		}
		return nil, fmt.Errorf("paste a log or upload a file")
	}
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, err
	}
	if strings.TrimSpace(body.Text) == "" {
		return nil, fmt.Errorf("paste a log or upload a file")
	}
	return strings.NewReader(body.Text), nil
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

	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "blocked",
		"ip":     req.IP,
		"list":   h.cfg.MikroTikList,
	})
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
