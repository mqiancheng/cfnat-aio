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
//   /api/ips/import-probe        导入探测 CMIN2 (POST)
//   /api/scanner                 扫描器配置 (GET/PUT)
//   /api/scanner/run             立即扫描 (POST)
//   /api/scanner/stop            停止扫描 (POST)
//   /api/scanner/history         扫描历史 (GET)
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
	"sync"
	"time"

	"cfnat-aio/internal/config"
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
	Proxy   *proxy.Manager

	tpl *template.Template
}

//go:embed templates/*
var templatesFS embed.FS

// New 创建 Handlers
func New(store *config.SQLiteStore, cfgMgr *config.Manager, lib *iplibrary.Library,
	sc *scanner.Scanner, pm *proxy.Manager) *Handlers {
	tpl := template.Must(template.New("").Delims("[[", "]]").ParseFS(templatesFS, "templates/*.html"))
	return &Handlers{
		Store: store, CfgMgr: cfgMgr, Lib: lib,
		Scanner: sc, Proxy: pm,
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

// === IP 导入探测 ===

// HandleAPIIPImportProbe 批量导入 IP 并探测 CMIN2 + 测速
// POST /api/ips/import-probe
// body: {"ips": ["ip:port", ...], "auto_import": true}
// 流程: 解析 → 去重 → 探活(取colo) → 测速(达标>阈值入库) → 返回详细结果
func (h *Handlers) HandleAPIIPImportProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req struct {
		IPs        []string `json:"ips"`
		AutoImport bool     `json:"auto_import"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if len(req.IPs) == 0 {
		writeError(w, 400, "IP 列表为空")
		return
	}

	// 解析 IP（支持 ip:port#注释 和纯 ip 格式）
	var targetIPs []string
	rawMap := make(map[string]string) // ip → 原始注释
	for _, raw := range req.IPs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		note := ""
		if idx := strings.Index(raw, "#"); idx >= 0 {
			note = strings.TrimSpace(raw[idx+1:])
			raw = raw[:idx]
		}
		raw = strings.TrimSpace(raw)
		ip := raw
		if idx := strings.LastIndex(raw, ":"); idx > 0 {
			ip = raw[:idx]
		}
		targetIPs = append(targetIPs, ip)
		if note != "" {
			rawMap[ip] = note
		}
	}

	if len(targetIPs) == 0 {
		writeError(w, 400, "解析后无有效 IP")
		return
	}

	logging.InfoTo("webui", "批量导入探测: %d 个 IP", len(targetIPs))

	// 去重
	seen := make(map[string]bool)
	var deduped []string
	for _, ip := range targetIPs {
		if !seen[ip] {
			seen[ip] = true
			deduped = append(deduped, ip)
		}
	}
	logging.InfoTo("webui", "去重后: %d 个 IP，开始探活...", len(deduped))

	// 阶段 1: 并发探活（取 colo）
	sc := h.CfgMgr.Scanner()
	importCfg := sc
	importCfg.MaxDelayMs = 5000
	results := scanner.ProbeBatch(deduped, importCfg)

	// 阶段 2: 对 CMIN2 节点进行测速
	type ProbeItem struct {
		IP       string  `json:"ip"`
		Colo     string  `json:"colo"`
		IsCMIN2  bool    `json:"is_cmin2"`
		OK       bool    `json:"ok"`
		Error    string  `json:"error"`
		Latency  float64 `json:"latency_ms"`
		SpeedMbps float64 `json:"speed_mbps"`
		Imported bool    `json:"imported"`
		Note     string  `json:"note"`
	}

	items := make([]ProbeItem, 0, len(results))
	imported := 0
	cmin2Count := 0
	totalOK := 0
	speedPassed := 0
	minSpeed := sc.MinSpeedMBps
	if minSpeed <= 0 {
		minSpeed = 3.0
	}

	// 收集 CMIN2 候选（需要测速）
	var cmin2Candidates []struct {
		ip   string
		colo string
		lat  float64
		note string
	}
	for _, r := range results {
		if r.OK && scanner.IsCMIN2Colo(r.Colo) {
			cmin2Candidates = append(cmin2Candidates, struct {
				ip   string
				colo string
				lat  float64
				note string
			}{r.IP, r.Colo, r.Latency, rawMap[r.IP]})
			cmin2Count++
			totalOK++
		} else if r.OK {
			totalOK++
		}
	}

	// 阶段 2: 对 CMIN2 候选测速
	speedResults := make(map[string]float64) // ip → mbps
	if len(cmin2Candidates) > 0 {
		logging.InfoTo("webui", "发现 %d 个 CMIN2 候选，开始测速(阈值 %.1fMB/s)...", len(cmin2Candidates), minSpeed)
		// 用 scanner 的测速逻辑（并发测速）
		speedURL := ""
		if sc.SpeedTestURL == "" || sc.SpeedTestURL == "auto" {
			speedURL = "https://speed.cloudflare.com/__down?bytes=10485760"
		} else {
			speedURL = sc.SpeedTestURL
		}
		// 逐批测速（限制并发 30）
		type speedTask struct {
			ip   string
			colo string
			lat  float64
			note string
		}
		sem := make(chan struct{}, 30)
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, c := range cmin2Candidates {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip, colo string, lat float64, note string) {
				defer wg.Done()
				defer func() { <-sem }()
				mbps, _ := h.Scanner.MeasureSpeed(ip, speedURL, sc.Port)
				mu.Lock()
				speedResults[ip] = mbps
				mu.Unlock()
			}(c.ip, c.colo, c.lat, c.note)
		}
		wg.Wait()
	}

	// 组装结果 + 入库（测速达标才入库）
	for _, r := range results {
		isCMIN2 := r.OK && scanner.IsCMIN2Colo(r.Colo)
		item := ProbeItem{
			IP:      r.IP,
			Colo:    r.Colo,
			IsCMIN2: isCMIN2,
			OK:      r.OK,
			Error:   r.Error,
			Latency: r.Latency,
			Note:    rawMap[r.IP],
		}
		if isCMIN2 {
			mbps := speedResults[r.IP]
			item.SpeedMbps = mbps
			if mbps >= minSpeed {
				speedPassed++
				if req.AutoImport {
					region := r.Colo
					err := h.Lib.AddIP(r.IP, region, "import", r.Colo, mbps, r.Latency, rawMap[r.IP])
					if err == nil {
						item.Imported = true
						imported++
					}
				}
			}
		}
		items = append(items, item)
	}

	logging.InfoTo("webui", "导入探测完成: 去重 %d, 探活 %d, CMIN2 %d, 测速达标 %d, 入库 %d",
		len(deduped), totalOK, cmin2Count, speedPassed, imported)

	writeJSON(w, 200, map[string]interface{}{
		"total":        len(deduped),
		"probed":       len(results),
		"ok":           totalOK,
		"cmin2":        cmin2Count,
		"speed_passed": speedPassed,
		"min_speed":    minSpeed,
		"imported":     imported,
		"auto_import":  req.AutoImport,
		"results":      items,
	})
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

// === cfnat 代理配置 ===

// HandleAPICfnatConfig cfnat 配置 GET/PUT
func (h *Handlers) HandleAPICfnatConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, h.CfgMgr.Cfnat())
	case http.MethodPut, http.MethodPost:
		var c config.CfnatConfig
		if err := readJSON(r, &c); err != nil {
			writeError(w, 400, err.Error())
			return
		}
		// 校验
		if c.IPPoolSize < 1 {
			c.IPPoolSize = 1
		}
		if c.ForwardNum < 1 {
			c.ForwardNum = 1
		}
		if c.SpeedTime < 1 {
			c.SpeedTime = 1
		}
		if c.ExpectCode < 100 || c.ExpectCode > 599 {
			c.ExpectCode = 200
		}
		if err := h.CfgMgr.UpdateCfnat(c); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, c)
	default:
		writeError(w, 405, "method not allowed")
	}
}

// === 扫描进度 ===

func (h *Handlers) HandleAPIScannerProgress(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.Scanner.Progress())
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


