// Package webui WebUI 处理层
//
// 路由：
//   /                            仪表盘首页
//   /api/health                  健康检查
//   /api/regions                 地区列表 (GET/PUT)
//   /api/regions/{name}          单个地区 (PUT/DELETE)
//   /api/ips                     IP 库查询 (GET)
//   /api/ips/add                 手动加 IP (POST)
//   /api/ips/remove              手动删 IP (POST)
//   /api/scanner                 扫描器配置 (GET/PUT)
//   /api/scanner/run             立即扫描 (POST)
//   /api/scanner/stop            停止扫描 (POST)
//   /api/scanner/history         扫描历史 (GET)
//   /api/fofa/keys               FOFA key 列表 (GET/POST)
//   /api/fofa/keys/{id}          单个 key (PUT/DELETE)
//   /api/fofa/search             手动触发 FOFA 搜索 (POST)
//   /api/fofa/log                FOFA 使用日志 (GET)
//   /api/settings                通用设置 (GET/PUT)
//   /api/proxy/status            代理状态 (GET)
//   /api/proxy/sync              同步代理配置 (POST)
package webui

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cfnat-aio/internal/config"
	"cfnat-aio/internal/fofa"
	"cfnat-aio/internal/iplibrary"
	"cfnat-aio/internal/logging"
	"cfnat-aio/internal/proxy"
	"cfnat-aio/internal/scanner"
)

// Handlers WebUI 处理器
type Handlers struct {
	Store   *config.SQLiteStore
	CfgMgr  *config.Manager
	Lib     *iplibrary.Library
	Scanner *scanner.Scanner
	FOFA    *fofa.Client
	Proxy   *proxy.Manager

	tpl *template.Template
}

//go:embed templates/*
var templatesFS embed.FS

// New 创建 Handlers
func New(store *config.SQLiteStore, cfgMgr *config.Manager, lib *iplibrary.Library,
	sc *scanner.Scanner, fc *fofa.Client, pm *proxy.Manager) *Handlers {
	tpl := template.Must(template.ParseFS(templatesFS, "templates/*.html"))
	return &Handlers{
		Store: store, CfgMgr: cfgMgr, Lib: lib,
		Scanner: sc, FOFA: fc, Proxy: pm,
		tpl: tpl,
	}
}

// === 通用辅助 ===

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// === 首页 ===

func (h *Handlers) HandleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := map[string]interface{}{
		"General": h.CfgMgr.General(),
	}
	if err := h.tpl.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Printf("[webui] template error: %v", err)
	}
}

// HandleHealth 健康检查
func (h *Handlers) HandleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// === 地区管理 ===

func (h *Handlers) HandleAPIRegions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, h.CfgMgr.Regions())
	case http.MethodPut, http.MethodPost:
		var regions []config.ProxyRegion
		if err := readJSON(r, &regions); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		// 校验端口冲突
		ports := make(map[int]bool)
		for _, r := range regions {
			if ports[r.Port] {
				writeError(w, 400, "端口冲突: "+strconv.Itoa(r.Port))
				return
			}
			ports[r.Port] = true
		}
		if err := h.CfgMgr.UpdateRegions(regions); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		go h.Proxy.Sync()
		writeJSON(w, 200, regions)
	default:
		writeError(w, 405, "method not allowed")
	}
}

// HandleAPIRegion 单个地区
func (h *Handlers) HandleAPIRegion(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		writeError(w, 400, "invalid path")
		return
	}
	name := parts[2]
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var region config.ProxyRegion
		if err := readJSON(r, &region); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		region.Name = name
		err := h.CfgMgr.UpdateRegion(name, func(p *config.ProxyRegion) {
			*p = region
		})
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		go h.Proxy.Sync()
		writeJSON(w, 200, region)
	case http.MethodDelete:
		regions := h.CfgMgr.Regions()
		var out []config.ProxyRegion
		for _, rg := range regions {
			if rg.Name != name {
				out = append(out, rg)
			}
		}
		if err := h.CfgMgr.UpdateRegions(out); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		go h.Proxy.Sync()
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	default:
		writeError(w, 405, "method not allowed")
	}
}

// === 日志系统 ===

// HandleAPILogs 获取最近日志
// GET /api/logs?limit=200
func (h *Handlers) HandleAPILogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	writeJSON(w, 200, logging.Default().Snapshot(limit))
}

// HandleAPILogsStream 实时日志流（SSE）
// GET /api/logs/stream
func (h *Handlers) HandleAPILogsStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	sub, unsubscribe := logging.Default().Subscribe(true)
	defer unsubscribe()

	// 心跳（防止代理超时）
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	notify := r.Context().Done()
	for {
		select {
		case <-notify:
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case e, ok := <-sub.Ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// === IP 库 ===

func (h *Handlers) HandleAPIIPs(w http.ResponseWriter, r *http.Request) {
	region := r.URL.Query().Get("region")
	entries := h.Lib.ListIPs(region)
	writeJSON(w, 200, entries)
}

func (h *Handlers) HandleAPIIPAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string  `json:"ip"`
		Region string  `json:"region"`
		Source string  `json:"source"`
		Colo   string  `json:"colo"`
		Speed  float64 `json:"speed_mbps"`
		Latency float64 `json:"latency_ms"`
		Note   string  `json:"note"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.Region == "" {
		req.Region = req.Colo
	}
	if req.Source == "" {
		req.Source = "manual"
	}
	if err := h.Lib.AddIP(req.IP, req.Region, req.Source, req.Colo, req.Speed, req.Latency, req.Note); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (h *Handlers) HandleAPIIPRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Region string `json:"region"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if err := h.Lib.RemoveIP(req.IP, req.Region); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// === 扫描器 ===

func (h *Handlers) HandleAPIScanner(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, h.CfgMgr.Scanner())
	case http.MethodPut, http.MethodPost:
		var sc config.ScannerConfig
		if err := readJSON(r, &sc); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		if err := h.CfgMgr.UpdateScanner(sc); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, sc)
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h *Handlers) HandleAPIScannerRun(w http.ResponseWriter, r *http.Request) {
	if h.Scanner.IsRunning() {
		writeError(w, 409, "扫描已在进行中")
		return
	}
	go h.Scanner.RunOnce()
	writeJSON(w, 202, map[string]string{"status": "started"})
}

func (h *Handlers) HandleAPIScannerStop(w http.ResponseWriter, r *http.Request) {
	h.Scanner.Stop()
	writeJSON(w, 200, map[string]string{"status": "stopped"})
}

func (h *Handlers) HandleAPIScannerHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.Scanner.History())
}

// === FOFA ===

func (h *Handlers) HandleAPIFOFAKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys, _ := h.Store.ListFOFAKeys()
		// 隐藏真实 key
		type SafeKey struct {
			ID         int64  `json:"id"`
			Name       string `json:"name"`
			Email      string `json:"email"`
			KeyMasked  string `json:"key_masked"`
			QuotaUsed  int    `json:"quota_used"`
			QuotaTotal int    `json:"quota_total"`
			Enabled    bool   `json:"enabled"`
			Note       string `json:"note"`
			CreatedAt  string `json:"created_at"`
		}
		out := make([]SafeKey, 0, len(keys))
		for _, k := range keys {
			masked := k.Key
			if len(masked) > 8 {
				masked = masked[:4] + "****" + masked[len(masked)-4:]
			} else {
				masked = "****"
			}
			out = append(out, SafeKey{
				ID: k.ID, Name: k.Name, Email: k.Email, KeyMasked: masked,
				QuotaUsed: k.QuotaUsed, QuotaTotal: k.QuotaTotal,
				Enabled: k.Enabled, Note: k.Note, CreatedAt: k.CreatedAt,
			})
		}
		writeJSON(w, 200, out)
	case http.MethodPost:
		var k config.FOFAKey
		if err := readJSON(r, &k); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		if k.QuotaTotal == 0 {
			k.QuotaTotal = 10000
		}
		id, err := h.Store.AddFOFAKey(k)
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]int64{"id": id})
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h *Handlers) HandleAPIFOFAKeyOne(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		writeError(w, 400, "invalid path")
		return
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		writeError(w, 400, "invalid id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var k config.FOFAKey
		if err := readJSON(r, &k); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		k.ID = id
		if err := h.Store.UpdateFOFAKey(k); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	case http.MethodDelete:
		if err := h.Store.DeleteFOFAKey(id); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	default:
		writeError(w, 405, "method not allowed")
	}
}

func (h *Handlers) HandleAPIFOFASearch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query   string `json:"query"`
		Region  string `json:"region"`
		Preset  string `json:"preset"`
		AutoAdd bool   `json:"auto_add"` // 是否自动入库（未测速，建议 false）
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	q := req.Query
	if req.Preset != "" {
		if v, ok := fofa.PresetQueries[req.Preset]; ok {
			q = v
		}
	}
	if q == "" {
		writeError(w, 400, "query 或 preset 不能为空")
		return
	}
	resp, err := h.FOFA.Search(q, "ip,port,protocol")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	entries := h.FOFA.ExtractIPs(resp, req.Region)
	autoAdded := 0
	if req.AutoAdd {
		for _, e := range entries {
			if err := h.Lib.AddIP(e.IP, e.Region, "fofa", e.Region, 0, 0, "FOFA候选"); err == nil {
				autoAdded++
			}
		}
	}
	writeJSON(w, 200, map[string]interface{}{
		"query":      q,
		"total":      resp.Total,
		"results":    entries,
		"auto_added": autoAdded,
	})
}

func (h *Handlers) HandleAPIFOFALog(w http.ResponseWriter, r *http.Request) {
	logs, _ := h.Store.ListFOFALog(100)
	writeJSON(w, 200, logs)
}

func (h *Handlers) HandleAPIFOFAPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, fofa.PresetQueries)
}

// === 通用设置 ===

func (h *Handlers) HandleAPISettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, h.CfgMgr.General())
	case http.MethodPut, http.MethodPost:
		var g config.GeneralConfig
		if err := readJSON(r, &g); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		// WebUI 端口变更需要重启
		if err := h.CfgMgr.UpdateGeneral(g); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, g)
	default:
		writeError(w, 405, "method not allowed")
	}
}

// === 代理状态 ===

func (h *Handlers) HandleAPIProxyStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.Proxy.Status())
}

func (h *Handlers) HandleAPIProxySync(w http.ResponseWriter, r *http.Request) {
	if err := h.Proxy.Sync(); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "synced"})
}

// 路由分发辅助（按子路径处理 /api/regions/{name} 等）
func (h *Handlers) RouteRegionsSubpath(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "regions" {
		h.HandleAPIRegion(w, r)
		return
	}
	http.NotFound(w, r)
}

func (h *Handlers) RouteFOFAKeysSubpath(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "fofa" && parts[2] == "keys" {
		h.HandleAPIFOFAKeyOne(w, r)
		return
	}
	http.NotFound(w, r)
}
