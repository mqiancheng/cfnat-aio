package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"cfnat-aio/internal/config"
	"cfnat-aio/internal/logging"
)

// === 常驻地区扫描器（cfnat-docker 同款 scanIPs 循环）===
//
// 设计意图（与用户确认）：
//   - 每个 enabled 地区 = 一个独立的 cfnat-docker 实例
//   - 扫描器【常驻运行】，与代理是否使用 IP 库 IP 互不干扰：
//       代理用库 IP 时，扫描器照常后台刷新热池；
//       库 IP 挂了，代理立即从已预热的热池取（零等待），不会现扫
//   - 扫描逻辑完全复用 cfnat-docker 的 scanIPs：
//       生成 CF 随机 IP → TCP:80 握手测延迟 + 读 CF-RAY 拿 colo → 按地区 colo 过滤 → 按延迟排序
//   - 热池只保留匹配本地区 colo 的节点，彻底避免"假 LAX/全局最低延迟"问题

// StartRegionScanner 启动某地区的常驻后台扫描 goroutine（幂等：已在运行则跳过）
// 注意：使用独立 scanMu，不占用 m.mu，避免与 Sync() 持有的 m.mu 产生死锁
func (m *Manager) StartRegionScanner(r config.ProxyRegion) {
	m.scanMu.Lock()
	if _, ok := m.regionScanCancel[r.Name]; ok {
		m.scanMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.regionScanCancel[r.Name] = cancel
	m.scanMu.Unlock()

	go m.regionScanLoop(ctx, r)
}

// StopRegionScanner 停止某地区的常驻扫描
func (m *Manager) StopRegionScanner(name string) {
	m.scanMu.Lock()
	cancel, ok := m.regionScanCancel[name]
	if ok {
		cancel()
		delete(m.regionScanCancel, name)
	}
	m.scanMu.Unlock()
	if ok {
		logging.InfoTo("proxy", "地区 %s 常驻扫描已停止", name)
	}
}

// regionScanLoop 常驻循环：启动即扫一次，之后按间隔刷新热池
func (m *Manager) regionScanLoop(ctx context.Context, r config.ProxyRegion) {
	defer func() {
		m.scanMu.Lock()
		delete(m.regionScanCancel, r.Name)
		m.scanMu.Unlock()
	}()

	interval := m.scanInterval
	if interval <= 0 {
		interval = 10 * time.Minute
	}

	// 启动立即扫一次，保证代理一开始就有热池可用
	m.scanRegionFallback(ctx, r)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scanRegionFallback(ctx, r)
		}
	}
}

// scanRegionFallback 执行一次 cfnat-docker 式扫描：
// 生成 CF 随机候选 → TCP:80 探活拿 colo(CF-RAY) + 延迟（与 cfnat-docker scanIPs 同款探针）
// → 按地区 colo 过滤 → 按延迟排序 → 写入热池
func (m *Manager) scanRegionFallback(ctx context.Context, r config.ProxyRegion) {
	candidates := m.genFallbackCandidates()
	if len(candidates) == 0 {
		return
	}

	// 探测并发度（与 cfnat-docker 同口径）
	const threads = 300

	type res struct {
		ip   string
		colo string
		lat  int64
	}
	results := make([]res, 0, len(candidates))
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, ip := range candidates {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			// 双模式探测: 先 :80 CF-RAY(cfnat-docker同款), 失败 fallback 到 :443 /cdn-cgi/trace
			colo, lat, ok := probeCFIP(ip)
			if !ok {
				return
			}
			// 严格按地区 colo 过滤（与 cfnat-docker -colo 一致），不匹配直接丢弃
			if r.Code != "" && !strings.EqualFold(colo, r.Code) {
				return
			}
			mu.Lock()
			results = append(results, res{ip, colo, lat})
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	// 按延迟升序（pool[0] 即最优）
	sort.Slice(results, func(i, j int) bool { return results[i].lat < results[j].lat })

	// 取前 IPNum 个（与 cfnat-docker 一致：扫描后只保留阈值数量的优选 IP 作为列表）
	keep := r.IPNum
	if keep <= 0 {
		keep = 20
	}
	if len(results) > keep {
		results = results[:keep]
	}

	pool := make([]string, 0, len(results))
	for _, x := range results {
		pool = append(pool, x.ip)
	}

	// 读取实时地区配置（在加锁前读取，避免与 Sync 的加锁顺序相反导致死锁），
	// 决定扫描结果是否推送给监听器。
	usePinned := false
	if live := m.liveRegion(r.Name); live != nil {
		usePinned = live.UsePinned
	}

	m.mu.Lock()
	m.fallbackPicks[r.Name] = pool
	// 仅当该地区未开启"使用收藏IP"时，才把扫描结果推给监听器作为代理目标。
	// 开启收藏IP时，扫描器只负责维持兜底热池（fallbackPicks）作为故障备份，
	// 绝不覆盖 listener 当前正在使用的收藏IP（cfnat-docker 单实例无此冲突，AIO 需显式隔离）。
	if l, ok := m.listeners[r.Name]; ok && !usePinned {
		l.ipMgr.refresh(pool)
		l.ipMgr.markFallback()
	}
	m.mu.Unlock()

	if len(results) > 0 {
		logging.InfoTo("proxy", "地区 %s 常驻扫描完成: 命中 %d 个 %s 节点（保留前 %d，最低 %dms / 最高 %dms）",
			r.Name, len(m.fallbackPicks[r.Name]), r.Code, keep, results[0].lat, results[len(results)-1].lat)
	} else {
		logging.WarnTo("proxy", "地区 %s 常驻扫描: 未找到匹配 %s 的节点（兜底池为空）", r.Name, r.Code)
	}
}

// probeCFIP 双模式探测 CF IP 的 colo（兼容本地 PC + NAS 两种环境）：
//
// 模式 A — :80 + CF-RAY（与 cfnat-docker scanIPs 同款）：
//   TCP:80 握手测延迟 → HTTP GET 根路径 → 读响应头 CF-RAY → 取末段 colo
//   适用：NAS Linux Docker 环境（CF 对正常出口返回有效射线）
//
// 模式 B — :443 /cdn-cgi/trace fallback：
//   TLS:443 握手 → GET /cdn-cgi/trace → 解析 "colo=XXX" 行
//   适用：本地 PC 等对 :80 返回空射线的环境
//
// 先试模式 A，若 CF-RAY 为空则自动 fallback 到模式 B。
func probeCFIP(ip string) (colo string, latMs int64, ok bool) {
	// --- 模式 A: :80 CF-RAY ---
	if colo, latMs, ok = probeColoVia80(ip); ok {
		return
	}

	// --- 模式 B: :443 /cdn-cgi/trace ---
	colo, latMs, ok = probeTraceVia443(ip)
	return
}

// probeColoVia80 移植自 cfnat-docker 的 scanIPs 探针：
// TCP:80 握手测延迟 + HTTP GET 读 CF-RAY header 末段提取 colo。
func probeColoVia80(ip string) (colo string, latMs int64, ok bool) {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	start := time.Now()
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "80"))
	if err != nil {
		return "", 0, false
	}
	defer conn.Close()
	tcpDur := time.Since(start)

	req, err := http.NewRequest("GET", "http://"+net.JoinHostPort(ip, "80"), nil)
	if err != nil {
		return "", 0, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := req.Write(conn); err != nil {
		return "", 0, false
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return "", 0, false
	}
	defer resp.Body.Close()

	cfRay := strings.TrimSpace(resp.Header.Get("CF-RAY"))
	if cfRay == "" || cfRay == "-" {
		return "", 0, false
	}
	parts := strings.Split(cfRay, "-")
	if len(parts) < 2 {
		return "", 0, false
	}
	colo = strings.TrimSpace(parts[len(parts)-1])
	if colo == "" {
		return "", 0, false
	}
	return colo, tcpDur.Milliseconds(), true
}

// probeTraceVia443 通过 :443 HTTPS 的 /cdn-cgi/trace 获取 colo：
// 适用于 :80 返回空射线的环境（如部分本地 PC 出口）。
func probeTraceVia443(ip string) (colo string, latMs int64, ok bool) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp", net.JoinHostPort(ip, "443"),
		&tls.Config{InsecureSkipVerify: true, ServerName: ip},
	)
	if err != nil {
		return "", 0, false
	}
	defer conn.Close()
	start := time.Now()

	fmt.Fprintf(conn, "GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", ip)
	conn.SetReadDeadline(time.Now().Add(4 * time.Second))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", 0, false
	}
	body := string(buf[:n])
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "colo=") && len(line) > 5 {
			return strings.TrimPrefix(line, "colo="), time.Since(start).Milliseconds(), true
		}
	}
	return "", 0, false
}

// genFallbackCandidates 从 CF 全量 IP 段生成随机候选（每个 /24 抽 1 个，每次扫描刷新随机性）
// 与 cfnat-docker 的 getRandomIPv4s 同口径
func (m *Manager) genFallbackCandidates() []string {
	out := make(map[string]struct{})
	for _, c := range fallbackCIDRs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		subs := expandToSlash24(ipnet)
		for _, sub := range subs {
			offset := uint32(rand.Intn(254)) + 1
			ip := addOffset(sub.IP.To4(), offset)
			if ip != nil {
				out[ip.String()] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(out))
	for ip := range out {
		result = append(result, ip)
	}
	shuffleStrings(result)
	return result
}
