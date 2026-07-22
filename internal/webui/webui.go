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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
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

// HandleAPIRegionPinned 热切换某地区"使用收藏IP做代理"开关（不重启监听/扫描）
// POST /api/regions/{name}/pinned  body: {"use_pinned": bool}
func (h *Handlers) HandleAPIRegionPinned(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "regions" || parts[3] != "pinned" {
		writeError(w, 400, "invalid path")
		return
	}
	name := parts[2]
	var req struct {
		UsePinned bool `json:"use_pinned"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if err := h.CfgMgr.UpdateRegion(name, func(p *config.ProxyRegion) {
		p.UsePinned = req.UsePinned
	}); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	// 原地热刷新：端口不断、扫描器不重启，立即切到收藏IP或热兜底池
	go h.Proxy.RefreshRegionIPs(name)
	writeJSON(w, 200, map[string]string{"status": "ok"})
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
	// 删除的可能是代理正在使用的收藏 IP，需通知代理重新加载该地区 IP 池，
	// 否则代理会继续转发到已删除的 IP 直到重启。
	go h.Proxy.RefreshRegionIPs(req.Region)
	h.Proxy.ScheduleDomainSync(req.Region) // 收藏可能变化 → 防抖同步优选域名
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// HandleAPIIPPriority 设置某 IP 的优先级（收藏/取消收藏）
// POST /api/ips/priority  body: {"ip","region","priority"}
//   priority > 0: 收藏（分配下一个可用排位号）
//   priority = 0: 取消收藏
func (h *Handlers) HandleAPIIPPriority(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req struct {
		IP       string `json:"ip"`
		Region   string `json:"region"`
		Priority int    `json:"priority"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.IP == "" || req.Region == "" {
		writeError(w, 400, "ip 和 region 必填")
		return
	}
	if req.Priority > 0 {
		// 收藏：分配该地区下一个可用排位号（max(priority)+1）
		pinned := h.Lib.ListIPs(req.Region)
		maxP := 0
		for _, e := range pinned {
			if e.Priority > maxP {
				maxP = e.Priority
			}
		}
		req.Priority = maxP + 1
	} else {
		req.Priority = 0 // 取消收藏
	}
	if err := h.Store.SetPriority(req.IP, req.Region, req.Priority); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	h.Lib.Reload()
	go h.Proxy.RefreshRegionIPs(req.Region)
	h.Proxy.ScheduleDomainSync(req.Region) // 收藏变化 → 防抖同步优选域名
	writeJSON(w, 200, map[string]interface{}{"status": "ok", "priority": req.Priority})
}

// HandleAPIIPReorder 调整收藏 IP 排序（与相邻项交换位置）
// POST /api/ips/reorder  body: {"ip","region","direction":"up"|"down"}
func (h *Handlers) HandleAPIIPReorder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req struct {
		IP        string `json:"ip"`
		Region    string `json:"region"`
		Direction string `json:"direction"` // "up" or "down"
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.IP == "" || req.Region == "" || (req.Direction != "up" && req.Direction != "down") {
		writeError(w, 400, "参数错误：需要 ip, region, direction(up/down)")
		return
	}
	if err := h.Store.ReorderPriority(req.IP, req.Region, req.Direction); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	h.Lib.Reload()
	go h.Proxy.RefreshRegionIPs(req.Region)
	h.Proxy.ScheduleDomainSync(req.Region) // 排序变化 → 防抖同步优选域名
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// HandleAPIDomainSync 手动立即同步某地区优选域名（无视自动开关）
// POST /api/domains/sync  body: {"region":"HKG"}
func (h *Handlers) HandleAPIDomainSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req struct {
		Region string `json:"region"`
	}
	if err := readJSON(r, &req); err != nil || req.Region == "" {
		writeError(w, 400, "region 必填")
		return
	}
	h.Proxy.SyncRegionDomain(req.Region, true)
	writeJSON(w, 200, h.Proxy.DomainSyncStatusMap())
}

// HandleAPIDomainStatus 各地区优选域名同步状态
// GET /api/domains/status
func (h *Handlers) HandleAPIDomainStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.Proxy.DomainSyncStatusMap())
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

// HandleAPIIPImportProbe 批量导入 IP 并探测 CMIN2 + 测速（SSE 流式，对应前端 /api/probe/stream）
// POST /api/probe/stream  (别名 /api/ips/import-probe)
// body: {"lines": ["ip", ...], "auto_import": true, "config": {port,max_delay_ms,min_speed_mbps,speed_test_url,threads,timeout,verify_sni}}
// 事件流: probe / sni_skip / speedstart / speed / imported / done / error
func (h *Handlers) HandleAPIIPImportProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req struct {
		Lines      []string `json:"lines"`
		AutoImport bool     `json:"auto_import"`
		Config     struct {
			Port         int     `json:"port"`
			MaxDelayMs   int     `json:"max_delay_ms"`
			MinSpeedMBps float64 `json:"min_speed_mbps"`
			SpeedTestURL string  `json:"speed_test_url"`
			Threads      int     `json:"threads"`
			Timeout      int     `json:"timeout"`
			VerifySNI    string  `json:"verify_sni"`
		} `json:"config"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if len(req.Lines) == 0 {
		writeError(w, 400, "IP 列表为空")
		return
	}

	// 解析 IP（支持 ip:port#注释 和纯 ip 格式）
	type target struct {
		ip   string
		note string
	}
	seen := make(map[string]bool)
	var targets []target
	for _, raw := range req.Lines {
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
		ip := scanner.NormalizeIP(raw)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		targets = append(targets, target{ip, note})
	}
	if len(targets) == 0 {
		writeError(w, 400, "解析后无有效 IP")
		return
	}

	// SSE 头
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// SSE 写锁：所有探测 goroutine 并发调用 sse，http.ResponseWriter 不支持并发写，
	// 裸写会交叉破坏 HTTP chunk 帧，浏览器 fetch 直接报 "network error" 中断整条流，
	// 前端于是把所有未完成 IP 标成失败（"N 有效 / M 失败"全是误报）
	var sseMu sync.Mutex
	sse := func(event string, data interface{}) {
		b, _ := json.Marshal(data)
		sseMu.Lock()
		defer sseMu.Unlock()
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, string(b))
		flusher.Flush()
	}

	// 构造探测配置（继承后台扫描器默认值，前端 config 覆盖）
	sc := h.CfgMgr.Scanner()
	if req.Config.Port > 0 {
		sc.Port = req.Config.Port
	}
	if req.Config.MaxDelayMs > 0 {
		sc.MaxDelayMs = req.Config.MaxDelayMs
	}
	if req.Config.Threads > 0 {
		sc.Threads = req.Config.Threads
	}
	if req.Config.VerifySNI != "" {
		sc.VerifySNI = req.Config.VerifySNI
	}
	if req.Config.SpeedTestURL != "" && req.Config.SpeedTestURL != "auto" {
		sc.SpeedTestURL = req.Config.SpeedTestURL
	}
	minSpeed := req.Config.MinSpeedMBps
	if minSpeed <= 0 {
		minSpeed = sc.MinSpeedMBps
	}
	if minSpeed <= 0 {
		minSpeed = 3.0
	}
	speedURL := sc.SpeedTestURL
	if speedURL == "" || speedURL == "auto" {
		speedURL = "https://speed.cloudflare.com/__down?bytes=10485760"
	}
	speedSec := sc.SpeedTestSec
	if speedSec <= 0 {
		speedSec = 5
	}

	logging.InfoTo("webui", "导入探测(流式): %d 个目标", len(targets))

	var (
		mu          sync.Mutex
		okCount     int
		cmin2Count  int
		speedPassed int
		imported    int
	)
	sem := make(chan struct{}, sc.Threads)
	if sem == nil || cap(sem) == 0 {
		sem = make(chan struct{}, 50)
	}
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t target) {
			defer wg.Done()
			defer func() {
				<-sem
				if r := recover(); r != nil {
					logging.ErrorTo("webui", "探测异常 %s: %v", t.ip, r)
					sse("probe", map[string]interface{}{
						"ip": t.ip, "colo": "", "latency_ms": 0,
						"ok": false, "is_cmin2": false, "error": fmt.Sprintf("内部异常: %v", r),
						"sni_match": false,
					})
				}
			}()
			res := scanner.ProbeOne(t.ip, sc)

			if !res.OK {
				sse("probe", map[string]interface{}{
					"ip": t.ip, "colo": res.Colo, "latency_ms": res.Latency,
					"ok": false, "is_cmin2": false, "error": res.Error, "sni_match": res.SNIMatch,
				})
				return
			}

			// SNI 严格不匹配 → 标记 sni_skip（跳过测速/入库）
			if sc.VerifySNI != "" && sc.VerifySNI != "cloudflare.com" && !res.SNIMatch {
				sse("sni_skip", map[string]interface{}{
					"ip": t.ip, "colo": res.Colo, "latency_ms": res.Latency,
					"sni_match": res.SNIMatch, "verify_sni": sc.VerifySNI,
				})
				return
			}

			isCMIN2 := scanner.IsCMIN2Colo(res.Colo)
			sse("probe", map[string]interface{}{
				"ip": t.ip, "colo": res.Colo, "latency_ms": res.Latency,
				"ok": true, "is_cmin2": isCMIN2, "error": "", "sni_match": res.SNIMatch,
			})
			mu.Lock()
			okCount++
			mu.Unlock()
			if !isCMIN2 {
				return
			}
			mu.Lock()
			cmin2Count++
			mu.Unlock()

		// CMIN2 节点：先测速，达标（>= min_speed）才入库——min_speed_mbps 是入库门槛，
		// 未达标的慢节点不进库（此前"先入库后测速"会让低于门槛的 IP 留在库里）
		sse("speedstart", map[string]interface{}{"ip": t.ip})
		mbps, _ := h.Scanner.MeasureSpeed(t.ip, speedURL, sc.Port, speedSec)
		passed := mbps >= minSpeed
		reason := ""
		if !passed {
			if mbps <= 0 {
				reason = "测速失败或无数据"
			} else {
				reason = fmt.Sprintf("测速 %.1fMB/s 低于门槛 %.1fMB/s", mbps, minSpeed)
			}
		}
		if passed {
			mu.Lock()
			speedPassed++
			mu.Unlock()
		}

		didImport := false
		if passed && req.AutoImport {
			if err := h.Lib.AddIP(t.ip, res.Colo, "import", res.Colo, mbps, res.Latency, t.note); err == nil {
				sse("imported", map[string]interface{}{"ip": t.ip})
				mu.Lock()
				imported++
				mu.Unlock()
				didImport = true
			}
		}
		sse("speed", map[string]interface{}{"ip": t.ip, "speed_mbps": mbps, "passed": passed, "imported": didImport, "reason": reason})
		// 已在库中的 IP：回写最新测速数据（只是记录，不影响入库门槛判定）
		if mbps > 0 {
			_ = h.Lib.UpdateSpeed(t.ip, res.Colo, mbps, res.Latency)
		}
		}(t)
	}
	wg.Wait()

	sse("done", map[string]interface{}{
		"ok": okCount, "cmin2": cmin2Count, "speed_passed": speedPassed, "imported": imported,
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
		if len(parts) >= 4 && parts[3] == "pinned" {
			h.HandleAPIRegionPinned(w, r)
			return
		}
		h.HandleAPIRegion(w, r)
		return
	}
	http.NotFound(w, r)
}


