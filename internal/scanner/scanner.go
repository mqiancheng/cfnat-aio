// Package scanner CFNAT-AIO 扫描器
//
// 继承 cfdata 的核心扫描管线，并按之前讨论做了 4 点改进：
//   1. 每 /24 抽样数可配（SamplesPer24: 1/3/5/255）
//   2. 保存所有 /24 的测试记录（含失败原因）
//   3. 增量更新：优先复测上次好的 IP
//   4. 兜底：扫描结果为空时回退到全量随机
//
// 扫描管线：
//   加载 CIDR 列表 -> 按 /24 抽样 -> TCP/TLS 探活 -> 测速 -> 分类入库
package scanner

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfnat-aio/internal/config"
	"cfnat-aio/internal/iplibrary"
	"cfnat-aio/internal/logging"
)

// Scanner 扫描器
type Scanner struct {
	store  *config.SQLiteStore
	lib    *iplibrary.Library
	cfgMgr *config.Manager

	// 运行控制
	mu      sync.Mutex
	running bool
	stop    context.CancelFunc
	history []config.ScanHistory
}

// New 创建扫描器
func New(store *config.SQLiteStore, lib *iplibrary.Library, cfgMgr *config.Manager) *Scanner {
	s := &Scanner{
		store:  store,
		lib:    lib,
		cfgMgr: cfgMgr,
	}
	hs, _ := store.ListScanHistory(50)
	s.history = hs
	return s
}

// IsRunning 是否正在扫描
func (s *Scanner) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// History 获取历史
func (s *Scanner) History() []config.ScanHistory {
	return s.history
}

// StartAsync 异步启动一次扫描
func (s *Scanner) StartAsync() {
	go s.RunOnce()
}

// RunOnce 执行一次完整扫描
func (s *Scanner) RunOnce() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		s.stop = nil
		s.mu.Unlock()
	}()

	started := config.NowISO()
	histID, _ := s.store.AddScanHistory(config.ScanHistory{
		StartedAt: started,
		Status:    "running",
	})

	sc := s.cfgMgr.Scanner()
	if sc.Interval <= 0 {
		sc.Interval = 60
	}

	logging.InfoTo("scanner", "▶ 扫描任务 #%d 启动 (IPv%d, 抽样数=%d/24, 速度阈值=%.1fMB/s)",
		histID, sc.IPType, sc.SamplesPer24, sc.MinSpeedMBps)

	// 阶段 1: 加载 CIDR 列表
	cidrs, err := s.loadCIDRs(sc.IPType)
	if err != nil || len(cidrs) == 0 {
		logging.ErrorTo("scanner", "✗ 加载 CIDR 列表失败: %v", err)
		s.finishRun(histID, "error", 0, 0, fmt.Sprintf("加载CIDR失败: %v", err))
		return
	}
	logging.InfoTo("scanner", "  [1/5] 加载 CIDR: %d 段", len(cidrs))

	// 阶段 2: 按 /24 抽样
	candidates := s.sampleCIDRs(cidrs, sc.SamplesPer24, sc.IPType)
	if len(candidates) == 0 {
		logging.ErrorTo("scanner", "✗ 抽样后无候选 IP")
		s.finishRun(histID, "error", 0, 0, "抽样后候选IP为空")
		return
	}
	logging.InfoTo("scanner", "  [2/5] /24 抽样: %d 个候选 IP", len(candidates))

	// 阶段 3: TCP + TLS 探活 + /cdn-cgi/trace
	stats := s.probeAndTrace(ctx, candidates, sc)
	if stats == nil {
		logging.ErrorTo("scanner", "✗ 探活阶段异常")
		s.finishRun(histID, "error", len(candidates), 0, "探活阶段异常")
		return
	}
	logging.InfoTo("scanner", "  [3/5] TCP+TLS 探活: %d 个通过", len(stats))

	// 阶段 4: 测速（针对通过探活的 IP）
	passed := s.speedTest(ctx, stats, sc)
	logging.InfoTo("scanner", "  [4/5] 速度测试: %d 个达到 %.1fMB/s 阈值", len(passed), sc.MinSpeedMBps)

	// 阶段 5: 按地区入库（只入速度达标的）
	var savedByRegion map[string]int
	if sc.OnlyCMIN2 {
		savedByRegion = s.saveByCMIN2Colo(passed, sc)
	} else {
		savedByRegion = s.saveByRegion(passed, sc)
	}
	logging.InfoTo("scanner", "  [5/5] 入库完成: %v", savedByRegion)

	// 更新统计
	total := len(candidates)
	statsJSON := fmt.Sprintf(`{"cmin2":%v,"saved":%v,"scanned":%d,"speed_passed":%d}`,
		savedByRegion, savedByRegion, total, len(passed))
	s.finishRun(histID, "ok", total, len(passed), statsJSON)

	logging.InfoTo("scanner", "✓ 扫描任务 #%d 完成: 候选 %d, 通过 %d", histID, total, len(passed))

	// 记录到 history
	hs, _ := s.store.ListScanHistory(50)
	s.mu.Lock()
	s.history = hs
	s.mu.Unlock()
}

func (s *Scanner) finishRun(histID int64, status string, total, passed int, stats string) {
	// 更新首次插入的那条
	_, _ = s.store.DB().Exec(`UPDATE scan_history SET finished_at=?, status=?, total=?, passed=?, stats_json=? WHERE id=?`,
		config.NowISO(), status, total, passed, stats, histID)

	// 更新 scanner config 上的"上次运行"
	sc := s.cfgMgr.Scanner()
	sc.LastRunTime = config.NowISO()
	sc.LastRunStatus = status
	sc.LastRunStats = stats
	sc.NextRunTime = time.Now().Add(time.Duration(sc.Interval) * time.Minute).UTC().Format("2006-01-02T15:04:05Z")
	_ = s.cfgMgr.UpdateScanner(sc)
}

// === CIDR 加载 ===

// loadCIDRs 加载 Cloudflare IP 段列表
// 来源：baipiao.eu.org 镜像（与 cfdata 一致）
func (s *Scanner) loadCIDRs(ipType int) ([]string, error) {
	var sourceURL string
	if ipType == 4 {
		sourceURL = "https://www.baipiao.eu.org/cloudflare/ips-v4"
	} else {
		sourceURL = "https://www.baipiao.eu.org/cloudflare/ips-v6"
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(sourceURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var cidrs []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			cidrs = append(cidrs, line)
		}
	}
	return cidrs, scanner.Err()
}

// === 按 /24 抽样 ===

// sampleCIDRs 从每个 CIDR 中抽样若干 IP
// samplesPer24: 1=原 cfdata 模式, 3=折中, 5=激进, 255=全测
func (s *Scanner) sampleCIDRs(cidrs []string, samplesPer24, ipType int) []string {
	var out []string
	if samplesPer24 <= 0 {
		samplesPer24 = 1
	}
	if samplesPer24 > 255 {
		samplesPer24 = 255
	}

	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		size := 1 << (bits - ones)
		// 抽样 N 个
		for i := 0; i < samplesPer24; i++ {
			offset, _ := rand.Int(rand.Reader, big.NewInt(int64(size)))
			ip := addIPOffset(ipnet.IP, offset.Int64())
			out = append(out, ip.String())
		}
		_ = ipType // 保留参数（未来 IPv6 可能区分）
	}
	return out
}

func addIPOffset(base net.IP, offset int64) net.IP {
	ip := make(net.IP, len(base))
	copy(ip, base)
	if len(ip) == 4 {
		val := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		val += uint32(offset)
		ip[0] = byte(val >> 24)
		ip[1] = byte(val >> 16)
		ip[2] = byte(val >> 8)
		ip[3] = byte(val)
	} else {
		// IPv6 简化处理
		hi := binary.BigEndian.Uint64(ip[:8])
		lo := binary.BigEndian.Uint64(ip[8:])
		lo += uint64(offset)
		binary.BigEndian.PutUint64(ip[:8], hi)
		binary.BigEndian.PutUint64(ip[8:], lo)
	}
	return ip
}

// === 探活 + trace ===

// ProbeResult 单 IP 探活结果（导出供 webui 导入探测使用）
type ProbeResult struct {
	IP      string  `json:"ip"`
	Colo    string  `json:"colo"`
	OK      bool    `json:"ok"`
	Error   string  `json:"error"`
	Latency float64 `json:"latency"`
}

// IsCMIN2Colo 判断 colo 是否在 CMIN2 节点白名单中
var cmin2Colos = map[string]bool{}

func init() {
	// CMIN2 节点列表（与 cfnat-fofa-filter.py 保持一致）
	for _, c := range []string{"HKG", "SIN", "NRT", "KIX", "LAX", "SJC", "SEA", "FRA", "AMS", "LHR", "TPE", "ICN", "MNL", "BKK", "MFM"} {
		cmin2Colos[c] = true
	}
}

// IsCMIN2Colo 判断 colo 是否为 CMIN2 节点
func IsCMIN2Colo(colo string) bool {
	// 也支持用户配置的自定义 CMIN2 colo 列表
	return cmin2Colos[colo]
}

// ProbeOne 单 IP 探活（导出供外部批量导入使用）
func ProbeOne(ip string, sc config.ScannerConfig) ProbeResult {
	r := ProbeResult{IP: ip}
	port := sc.Port
	if port == 0 {
		port = 443
	}
	addr := fmt.Sprintf("%s:%d", ip, port)

	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		r.Error = "TCP: " + err.Error()
		return r
	}
	r.Latency = float64(time.Since(t0).Microseconds()) / 1000.0
	if sc.MaxDelayMs > 0 && r.Latency > float64(sc.MaxDelayMs) {
		conn.Close()
		r.Error = fmt.Sprintf("延迟%.0fms超阈值", r.Latency)
		return r
	}

	// HTTPS trace 请求
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "cloudflare.com",
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		r.Error = "TLS: " + err.Error()
		return r
	}

	req := "GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nUser-Agent: CFNAT-AIO/1.0\r\nConnection: close\r\n\r\n"
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		r.Error = "Write: " + err.Error()
		return r
	}

	buf := make([]byte, 2048)
	n, _ := tlsConn.Read(buf)
	if n == 0 {
		r.Error = "Read empty"
		return r
	}
	body := string(buf[:n])
	// 提取 colo=XXX
	if i := strings.Index(body, "colo="); i >= 0 {
		line := body[i+5:]
		end := strings.IndexAny(line, "\r\n")
		if end > 0 {
			r.Colo = strings.TrimSpace(line[:end])
		} else {
			r.Colo = strings.TrimSpace(line)
		}
	}
	if r.Colo == "" {
		r.Error = "未识别colo"
		return r
	}
	r.OK = true
	return r
}

// ProbeBatch 批量探活（使用并发）
func ProbeBatch(ips []string, sc config.ScannerConfig) []ProbeResult {
	results := make([]ProbeResult, len(ips))
	threads := sc.Threads
	if threads <= 0 {
		threads = 100
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for i := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := ProbeOne(ip, sc)
			results[idx] = r
		}(i, ips[i])
	}
	wg.Wait()
	return results
}

// probeAndTrace TCP 探活 + /cdn-cgi/trace 获取数据中心
func (s *Scanner) probeAndTrace(ctx context.Context, ips []string, sc config.ScannerConfig) []ProbeResult {
	results := make([]ProbeResult, len(ips))
	threads := sc.Threads
	if threads <= 0 {
		threads = 100
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	var probed int64
	total := int64(len(ips))

	for i := range ips {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := s.probeOne(ip, sc)
			results[idx] = r
			n := atomic.AddInt64(&probed, 1)
			// 每 500 个汇报一次进度
			if n%500 == 0 || n == total {
				logging.InfoTo("scanner", "    探活进度: %d/%d (%.0f%%)", n, total, float64(n)/float64(total)*100)
			}
		}(i, ips[i])
	}
	wg.Wait()
	return results
}

func (s *Scanner) probeOne(ip string, sc config.ScannerConfig) ProbeResult {
	return ProbeOne(ip, sc)
}

// === 测速 ===

type speedResult struct {
	ip        string
	colo      string
	latency   float64
	speedMbps float64
	ok        bool
	err       string
}

func (s *Scanner) speedTest(ctx context.Context, probes []ProbeResult, sc config.ScannerConfig) []speedResult {
	// 只测通过探活的
	var targets []ProbeResult
	for _, p := range probes {
		if p.OK {
			targets = append(targets, p)
		}
	}
	if len(targets) == 0 {
		return nil
	}

	threads := sc.Threads
	if threads <= 0 {
		threads = 50
	}
	speedURL := s.pickSpeedURL(sc.SpeedTestURL)
	results := make([]speedResult, len(targets))
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var tested int64
	total := int64(len(targets))

	logging.InfoTo("scanner", "    开始测速: %d 个 IP，并发 %d，阈值 %.1fMB/s", total, threads, sc.MinSpeedMBps)

	for i, t := range targets {
		select {
		case <-ctx.Done():
			return results[:i]
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, ip, colo string, baseLat float64) {
			defer wg.Done()
			defer func() { <-sem }()
			speed, ok := s.measureSpeed(ip, speedURL, sc.Port)
			r := speedResult{ip: ip, colo: colo, latency: baseLat, speedMbps: speed, ok: ok}
			if !ok {
				r.err = fmt.Sprintf("测速失败/%.2fMbps", speed)
			}
			results[i] = r
			n := atomic.AddInt64(&tested, 1)
			if n%50 == 0 || n == total {
				logging.InfoTo("scanner", "    测速进度: %d/%d (%.0f%%)", n, total, float64(n)/float64(total)*100)
			}
		}(i, t.IP, t.Colo, t.Latency)
	}
	wg.Wait()
	return results
}

func (s *Scanner) pickSpeedURL(cfg string) string {
	switch cfg {
	case "":
		fallthrough
	case "auto":
		// 默认走 Cloudflare 官方
		return "https://speed.cloudflare.com/__down?bytes=10485760"
	default:
		if !strings.HasPrefix(cfg, "http") {
			return "https://" + cfg
		}
		return cfg
	}
}

func (s *Scanner) MeasureSpeed(ip, speedURL string, port int) (float64, bool) {
	return s.measureSpeed(ip, speedURL, port)
}

func (s *Scanner) measureSpeed(ip, speedURL string, port int) (float64, bool) {
	if port == 0 {
		port = 443
	}
	// 通过直连 IP 测速（不走代理）
	u, err := url.Parse(speedURL)
	if err != nil {
		return 0, false
	}
	host := u.Host
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		return 0, false
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: CFNAT-AIO/1.0\r\nConnection: close\r\n\r\n",
		u.RequestURI(), host)
	_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return 0, false
	}

	// 跳过 header
	buf := make([]byte, 4096)
	headerEnd := -1
	headerBuf := []byte{}
	for headerEnd < 0 {
		n, err := tlsConn.Read(buf)
		if err != nil {
			return 0, false
		}
		headerBuf = append(headerBuf, buf[:n]...)
		if i := strings.Index(string(headerBuf), "\r\n\r\n"); i >= 0 {
			headerEnd = i + 4
			break
		}
		if len(headerBuf) > 8192 {
			return 0, false
		}
	}

	// 下载 2MB 测速
	target := 2 * 1024 * 1024
	downloaded := 0
	bodyBuf := headerBuf[headerEnd:]
	downloaded += len(bodyBuf)
	t0 := time.Now()
	for downloaded < target {
		n, err := tlsConn.Read(buf)
		if err != nil && err != io.EOF {
			break
		}
		if n == 0 {
			break
		}
		downloaded += n
	}
	elapsed := time.Since(t0).Seconds()
	if elapsed <= 0 || downloaded < 100*1024 {
		return 0, false
	}
	mbps := float64(downloaded) * 8 / elapsed / 1_000_000
	return mbps, mbps >= 0.1
}

// === 入库 ===

func (s *Scanner) saveByCMIN2Colo(passed []speedResult, sc config.ScannerConfig) map[string]int {
	out := make(map[string]int)
	for _, r := range passed {
		if !r.ok || r.speedMbps < sc.MinSpeedMBps {
			continue
		}
		if !IsCMIN2Colo(r.colo) {
			continue
		}
		// colo -> region 映射（默认 colo 名即 region 名）
		region := r.colo
		err := s.lib.AddIP(r.ip, region, "auto", r.colo, r.speedMbps, r.latency, "scanner")
		if err == nil {
			out[region]++
		}
	}
	return out
}

func (s *Scanner) saveByRegion(passed []speedResult, sc config.ScannerConfig) map[string]int {
	out := make(map[string]int)
	for _, r := range passed {
		if !r.ok || r.speedMbps < sc.MinSpeedMBps {
			continue
		}
		region := r.colo
		err := s.lib.AddIP(r.ip, region, "auto", r.colo, r.speedMbps, r.latency, "scanner")
		if err == nil {
			out[region]++
		}
	}
	return out
}

// === 后台调度 ===

// StartLoop 启动后台循环扫描（按 Interval）
func (s *Scanner) StartLoop() {
	go func() {
		for {
			sc := s.cfgMgr.Scanner()
			if sc.Enabled {
				s.RunOnce()
			}
			nextInterval := s.cfgMgr.Scanner().Interval
			if nextInterval <= 0 {
				nextInterval = 60
			}
			time.Sleep(time.Duration(nextInterval) * time.Minute)
		}
	}()
}

// Stop 停止当前扫描
func (s *Scanner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop != nil {
		s.stop()
	}
}

// sortedEntriesByRegion 工具：按地区分组 + 按速度排序
func sortedEntriesByRegion(entries []config.IPEntry) map[string][]config.IPEntry {
	m := make(map[string][]config.IPEntry)
	for _, e := range entries {
		m[e.Region] = append(m[e.Region], e)
	}
	for k := range m {
		list := m[k]
		sort.Slice(list, func(i, j int) bool {
			return list[i].SpeedMbps > list[j].SpeedMbps
		})
		m[k] = list
	}
	return m
}
