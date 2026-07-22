// Package proxy CFNAT-AIO 代理转发模块
//
// 核心特性：
//   - 继承 cfnat 的粘性单 IP + 故障切换逻辑（cfnat-docker 方案）
//   - 多地区管理：每个 ProxyRegion 一个独立监听端口
//   - 动态增删地区（WebUI 改配置即可，不重启进程）
//   - 收藏 IP：priority>0，按排位号顺序使用（#1最优先），挂了换下一个
//   - 无收藏 IP 时：动态搜索 CF 全网 IP 作为代理目标
//   - 后台 statusCheck 自检：连续失败触发 switchToNextValidIP
//   - 兜底：收藏 IP 全挂时自动切全量 CF 随机 IP
//   - 热重载：regions 变更后自动重启对应监听
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfnat-aio/internal/config"
	"cfnat-aio/internal/iplibrary"
	"cfnat-aio/internal/logging"
)

// 全量 CF IPv4 兜底池（与旧 cfnat 一致：完整 /24 列表，每个抽随机 IP）
// 来源：https://www.baipiao.eu.org/cloudflare/ips-v4
var fallbackCIDRs = []string{
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14",
	"108.162.192.0/18",
	"131.0.72.0/22",
	"141.101.64.0/18",
	"162.158.0.0/15",
	"172.64.0.0/13",
	"173.245.48.0/20",
	"188.114.96.0/20",
	"190.93.240.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
}

// 全量 CF IPv6 兜底池（IP 类型=6 时使用）
// 来源：https://www.baipiao.eu.org/cloudflare/ips-v6
var fallbackCIDRs6 = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// 每个 IPv6 CIDR 抽样的地址数（IPv6 无 /24 概念，按大段随机抽样以覆盖更多边缘节点）
const ipv6SamplesPerCIDR = 256

// sampleIPv6 在 ipnet 的 host 位内随机取 n 个地址（保留网络前缀，随机化主机位）
func sampleIPv6(ipnet *net.IPNet, n int) []string {
	maskOnes, _ := ipnet.Mask.Size()
	base := new(big.Int).SetBytes(ipnet.IP.Mask(ipnet.Mask).To16())
	hostBits := 128 - maskOnes
	if hostBits <= 0 {
		return nil
	}
	max := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	res := make([]string, 0, n)
	for i := 0; i < n; i++ {
		off := new(big.Int).Rand(rng, max)
		addr := new(big.Int).Add(base, off)
		b := addr.Bytes()
		ip := make(net.IP, 16)
		copy(ip[16-len(b):], b)
		res = append(res, ip.String())
	}
	return res
}

// mergePools 合并扫描新结果与旧池（对齐 cfnat-docker 的 IP 列表稳定性）：
//   - 优先保留新鲜扫描结果（已按延迟升序）
//   - 若当前粘性 IP(curIP) 不在新结果中，强制保留它（替换最差的一个新鲜结果），
//     避免每次扫描把正在用的 IP 冲掉导致频繁换 IP
//   - 补充旧池里残余的低延迟 IP（去重）
//   - 总量截断到 capN（= IPNum），与 cfnat-docker 的列表规模一致
func mergePools(newP, old []string, capN int, curIP string) []string {
	seen := make(map[string]struct{}, capN)
	out := make([]string, 0, capN)
	add := func(ip string) {
		if ip == "" {
			return
		}
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			out = append(out, ip)
		}
	}
	for _, ip := range newP {
		add(ip)
	}
	// 当前粘性 IP 不在新结果中时，强制保留（替换最差新鲜结果，保证不换 IP）
	if curIP != "" {
		if _, ok := seen[curIP]; !ok {
			if len(out) >= capN {
				out[capN-1] = curIP
				seen[curIP] = struct{}{}
			} else {
				out = append(out, curIP)
				seen[curIP] = struct{}{}
			}
		}
	}
	for _, ip := range old {
		add(ip)
	}
	if len(out) > capN {
		out = out[:capN]
	}
	return out
}
type Manager struct {
	store  *config.SQLiteStore
	lib    *iplibrary.Library
	cfgMgr *config.Manager

	mu        sync.Mutex
	listeners map[string]*regionListener // region -> listener
	regions   map[string]config.ProxyRegion

	fallbackPicks map[string][]string // region -> 当前兜底热池（常驻扫描维护，已按 colo 筛选+延迟排序）

	// SpeedTestFn 自动测速入库用的测速函数（main 装配为 scanner.MeasureSpeed，避免 proxy 依赖 scanner 包）
	SpeedTestFn func(ip, speedURL string, port, sec int) (float64, bool)
	autoTested  map[string]bool // "region|ip" -> 本进程已自动测速过（去重防复测）

	// 常驻扫描（cfnat-docker 同款 scanIPs 循环）：每个 enabled 地区一个后台 goroutine
	scanMu           sync.Mutex                    // 保护 regionScanCancel（与 m.mu 分开，避免 Sync 死锁）
	regionScanCancel map[string]context.CancelFunc // region -> 取消函数
	scanInterval     time.Duration                 // 常驻扫描刷新间隔

	// 运行状态（供 WebUI 显示）
	running    bool
	startedAt  time.Time
	lastHealth map[string]time.Time // region -> 上次健康检查时间
	lastRescan map[string]time.Time // region -> 上次兜底池重扫时间（防雪崩：短时间不重复扫）
}

// New 创建代理管理器
func New(store *config.SQLiteStore, lib *iplibrary.Library, cfgMgr *config.Manager) *Manager {
	m := &Manager{
		store:         store,
		lib:           lib,
		cfgMgr:        cfgMgr,
		listeners:     make(map[string]*regionListener),
		regions:       make(map[string]config.ProxyRegion),
		fallbackPicks:    make(map[string][]string),
		autoTested:       make(map[string]bool),
		regionScanCancel: make(map[string]context.CancelFunc),
		scanInterval:     10 * time.Minute,
		lastHealth:       make(map[string]time.Time),
		lastRescan:       make(map[string]time.Time),
		startedAt:        time.Now(),
	}
	return m
}

// Sync 同步 regions（与 config 保持一致）
//   - 新增的 region：start listener
//   - 删除的 region：stop listener
//   - 端口/colo 变化的 region：restart
func (m *Manager) Sync() error {
	desired := m.cfgMgr.Regions()
	desiredMap := make(map[string]config.ProxyRegion)
	for _, r := range desired {
		desiredMap[r.Name] = r
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 停止不再需要的
	for name, l := range m.listeners {
		if _, ok := desiredMap[name]; !ok || !l.region.Enabled {
			l.stop()
			delete(m.listeners, name)
			delete(m.regions, name)
			m.StopRegionScanner(name)
		}
	}

	// 启动 / 重启
	for name, r := range desiredMap {
		if !r.Enabled {
			continue
		}
		cur, exists := m.listeners[name]
		if exists && cur.region == r {
			continue
		}
		if exists {
			cur.stop()
			delete(m.listeners, name)
			m.StopRegionScanner(name)
		}
		l := m.startRegion(r)
		if l != nil {
			m.listeners[name] = l
			m.regions[name] = r
			logging.InfoTo("proxy", "region %s listening on :%d", name, r.Port)
			// 启动该地区的常驻扫描（cfnat-docker 同款 scanIPs 循环），与代理独立运行
			m.StartRegionScanner(r)
		}
	}
	return nil
}

// regionListener 每个地区的代理监听器
// 实现了 cfnat-docker 的粘性单 IP + 故障切换机制
type regionListener struct {
	region config.ProxyRegion
	ln     net.Listener
	cancel context.CancelFunc
	done   chan struct{}

	// usePinned 为热切换标志：WebUI 切换"使用收藏IP"时原地更新，
	// 运行中的 pickTarget 立即读到，无需重启监听/扫描（由 RefreshRegionIPs 维护）
	usePinned atomic.Bool

	// rrIdx 转发数（Num）负载均衡轮询计数器：每个新连接自增后取模，
	// 在池内前 Num 个 IP 间轮转分发（与 cfnat-docker 的 num 负载均衡同义）
	rrIdx atomic.Int64

	// failStreak 健康检查连续失败计数：对齐 cfnat-docker 的 failCount<2，
	// 必须连续 2 次失败才清空/切换当前 IP，避免单次端口抖动引发的频繁换 IP
	failStreak atomic.Int64

	// initialScanDone 标记「启动后首次扫描是否已完成」。
	// 用于方案B：重启后先用数据库里记的老 IP 顶着（秒级可用），
	// 等这第一次扫描跑完，再用本次扫描挑出的最优 IP 覆盖老 IP，
	// 之后周期扫描只刷新候选池（故障备份），不再动 currentIP。
	initialScanDone atomic.Bool

	// lastAutoTestIP 自动测速入库：上次触发时的 currentIP（仅 statusCheckLoop 访问，
	// 换 IP 才触发，currentIP 不变不重复触发）
	lastAutoTestIP string

	// === 粘性 IP 管理（cfnat-docker 方案）===
	ipMgr *ipManager
}

// ipManager 粘性 IP 管理器（移植自 cfnat-docker/cfnat.go）
//   - 持有一个 currentIP
//   - 故障时切到 ipAddresses 列表中的下一个有效 IP
//   - 全失败时标记 allChecked
//   - 支持 currentIP 来自兜底池（fallbackMode）—— 同样粘性
type ipManager struct {
	mu            sync.RWMutex
	currentIP     string
	ipAddresses   []string // 收藏 IP 列表（无收藏时为空）
	currentIndex  int
	allIPsChecked bool
	fallbackMode  bool // 当前 currentIP 来自兜底池
	currentDelayMs int64 // 当前 IP 的延迟（毫秒），0 表示未测量/来自 IP 库
}

func (im *ipManager) setIPs(ips []string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.ipAddresses = ips
	im.currentIndex = 0
	im.currentIP = ""
	im.fallbackMode = false
	im.allIPsChecked = false
	im.currentDelayMs = 0
}

// refresh 刷新 IP 列表（保留 currentIP 如果它仍在列表中，否则清空）
// 注意：不修改 fallbackMode，由调用方根据业务逻辑显式设置
func (im *ipManager) refresh(ips []string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.ipAddresses = ips
	im.allIPsChecked = false
	// 如果当前 currentIP 不在新列表里 → 清空（但不改变 fallbackMode）
	found := false
	for i, x := range ips {
		if x == im.currentIP {
			im.currentIndex = i
			found = true
			break
		}
	}
	if !found {
		im.currentIP = ""
		im.currentIndex = 0
		im.currentDelayMs = 0
	}
}

// setFallbackIP 设置一个兜底池 IP 作为 currentIP（粘性使用）
func (im *ipManager) setFallbackIP(ip string, delayMs int64) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.currentIP = ip
	im.fallbackMode = true
	im.currentDelayMs = delayMs
	im.allIPsChecked = false
}

// markFallback 标记当前为兜底池模式（用于展示与失败处理区分）
func (im *ipManager) markFallback() {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.fallbackMode = true
}

// isFallback 判断 currentIP 是否来自兜底池
func (im *ipManager) isFallback() bool {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.fallbackMode && im.currentIP != ""
}

func (im *ipManager) getCurrentDelayMs() int64 {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.currentDelayMs
}

func (im *ipManager) updateDelayMs(ms int64) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.currentDelayMs = ms
}

func (im *ipManager) getCurrentIP() string {
	im.mu.RLock()
	defer im.mu.RUnlock()
	return im.currentIP
}

func (im *ipManager) setCurrentIP(ip string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.currentIP = ip
	for i, x := range im.ipAddresses {
		if x == ip {
			im.currentIndex = i
			break
		}
	}
}

func (im *ipManager) getIPs() []string {
	im.mu.RLock()
	defer im.mu.RUnlock()
	out := make([]string, len(im.ipAddresses))
	copy(out, im.ipAddresses)
	return out
}

func (im *ipManager) clearCurrent() {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.currentIP = ""
	im.fallbackMode = false
}

// switchToNextValidIP 切换到下一个有效 IP（移植自 cfnat-docker）
//   - 从当前位置往后找
//   - 跳过当前 IP
//   - 验证后切换
//   - 都轮过了则标记 allChecked
func (im *ipManager) switchToNextValidIP(checkFn func(ip string) bool) bool {
	im.mu.Lock()
	defer im.mu.Unlock()

	for i := im.currentIndex + 1; i < len(im.ipAddresses); i++ {
		ip := im.ipAddresses[i]
		if ip == im.currentIP {
			continue
		}
		if checkFn(ip) {
			oldIP := im.currentIP
			im.currentIP = ip
			im.currentIndex = i
			im.allIPsChecked = false
			logging.InfoTo("proxy", "切换 IP: %s → %s (索引 %d)", oldIP, ip, i)
			return true
		}
	}

	im.allIPsChecked = true
	logging.WarnTo("proxy", "所有 IP 都已轮过")
	return false
}

func (rl *regionListener) stop() {
	if rl.cancel != nil {
		rl.cancel()
	}
	if rl.ln != nil {
		_ = rl.ln.Close()
	}
	<-rl.done
}

func (m *Manager) startRegion(r config.ProxyRegion) *regionListener {
	addr := fmt.Sprintf(":%d", r.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logging.ErrorTo("proxy", "✗ 监听 :%d 失败: %v", r.Port, err)
		return nil
	}
	logging.InfoTo("proxy", "▶ 启动代理 %s → :%d (colo=%s, 当前可用 IP=%d, 首选 IP=%d)",
		r.Name, r.Port, r.Code, m.lib.CountIPs(r.Name), m.lib.CountIPs(r.Name))
	ctx, cancel := context.WithCancel(context.Background())
	rl := &regionListener{
		region: r,
		ln:     ln,
		cancel: cancel,
		done:   make(chan struct{}),
		ipMgr:  &ipManager{},
	}
	rl.usePinned.Store(r.UsePinned)

	// 初始化 IP 池：优先首选 IP（priority<=2），关闭收藏时则用兜底池（cfnat-docker 同款 IP 列表）
	ips := m.initRegionIPs(r)
	rl.ipMgr.refresh(ips)
	// 兜底模式（use_pinned=false 且池非空）→ 标记，使选 IP / 故障切换 / 展示与收藏 IP 走一致逻辑
	if !r.UsePinned && len(ips) > 0 {
		rl.ipMgr.markFallback()
	}

	// 重启记忆：优先复用上次关闭前使用的 IP（秒级可用，后台扫描同步进行）。
	// 仅当该 IP 仍可达时才复用，否则回落到下方的常规选择逻辑。
	if saved, ok := m.store.LoadRegionCurrentIP(r.Name); ok && saved != "" {
		if m.checkValidIP(saved, r) {
			if r.UsePinned {
				// 收藏模式：仅当该 IP 在收藏列表内才复用
				inPool := false
				for _, x := range ips {
					if x == saved {
						inPool = true
						break
					}
				}
				if inPool {
					rl.ipMgr.setCurrentIP(saved)
					logging.InfoTo("proxy", "地区 %s 复用上次收藏 IP = %s", r.Name, saved)
				}
			} else {
				rl.ipMgr.setCurrentIP(saved)
				rl.ipMgr.markFallback()
				logging.InfoTo("proxy", "地区 %s 复用上次兜底 IP = %s（后台扫描同步进行）", r.Name, saved)
			}
		}
	}

	// 选第一个有效 IP 作为 currentIP（仅当重启记忆未设定时才执行）
	if rl.ipMgr.getCurrentIP() == "" {
		m.selectInitialIP(rl)
	}

	go func() {
		defer close(rl.done)
		m.serveRegion(ctx, ln, r, rl)
	}()

	// 后台 statusCheck 协程（cfnat-docker 风格）
	go m.statusCheckLoop(ctx, r, rl)

	return rl
}

// resolveDomainIPs 解析域名得到 IPv4 列表（支持多 A 记录轮询）
// 域名应关闭 Cloudflare 代理（灰色云朵），A 记录直接指向优选 IP
func (m *Manager) resolveDomainIPs(domain string) []string {
	host := domain
	if i := strings.Index(host, "/"); i > 0 {
		host = host[:i]
	}
	if host == "" {
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		logging.ErrorTo("proxy", "域名 %s 解析失败: %v", host, err)
		return nil
	}
	var out []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}

// initRegionIPs 初始化地区 IP 池
//   - 只使用收藏的 IP（priority<=2）作为代理候选，按优先级升序、速度降序排列
//   - 无收藏 IP 时返回 nil（代理将直接走常驻扫描热池/兜底池）
//   - 域名模式（UseDomainIP=true）：解析 Domain 得到多 IP（由测速脚本维护为优选低延迟 IP）
func (m *Manager) initRegionIPs(r config.ProxyRegion) []string {
	// 开关关闭时：不使用收藏 IP，使用 cfnat-docker 同款兜底池（即 IP 列表本身）
	if !r.UsePinned {
		// 兜底池由常驻扫描维护，已按 colo 过滤 + 延迟排序；直接作为 IP 列表加载，
		// 与收藏 IP 走完全相同的 selectInitialIP / switchToNextValidIP 逻辑。
		// 注意：本函数仅在 Sync() 持 m.mu 时调用，直接读 fallbackPicks 即可（避免重复加锁死锁）。
		pool := m.fallbackPicks[r.Name]
		if len(pool) > 0 {
			logging.InfoTo("proxy", "地区 %s 已关闭收藏IP代理（use_pinned=false），使用兜底池 %d 个IP", r.Name, len(pool))
			return pool
		}
		logging.InfoTo("proxy", "地区 %s 兜底池尚未就绪，首次连接时按需扫描", r.Name)
		return nil
	}
	// 域名模式：解析 Domain 得到多 IP 作为转发目标池
	if r.UseDomainIP && r.Domain != "" {
		ips := m.resolveDomainIPs(r.Domain)
		if len(ips) > 0 {
			logging.InfoTo("proxy", "地区 %s 域名模式: %s 解析到 %d 个IP（DNS 已优选）", r.Name, r.Domain, len(ips))
			return ips
		}
		logging.WarnTo("proxy", "地区 %s 域名 %s 解析为空，回退到收藏IP", r.Name, r.Domain)
	}
	// IP 库模式：只取收藏 IP（priority>0）
	entries := m.lib.ListIPs(r.Name)
	if len(entries) == 0 {
		logging.InfoTo("proxy", "地区 %s 无IP库IP，将走兜底池", r.Name)
		return nil
	}
	var pinned []config.IPEntry
	for _, e := range entries {
		if normPriority(e.Priority) > 0 {
			pinned = append(pinned, e)
		}
	}
	if len(pinned) == 0 {
		logging.InfoTo("proxy", "地区 %s 有 %d 个IP但无收藏IP，将走兜底池", r.Name, len(entries))
		return nil
	}
	// 收藏 IP 排序：排位号升序（1最前=最高优先）
	sort.Slice(pinned, func(i, j int) bool {
		return pinned[i].Priority < pinned[j].Priority
	})
	ips := make([]string, 0, len(pinned))
	for _, e := range pinned {
		ips = append(ips, e.IP)
	}
	logging.InfoTo("proxy", "地区 %s 使用 %d 个收藏IP作为代理候选（共 %d 个IP库IP）", r.Name, len(ips), len(entries))
	return ips
}

// normPriority 将 0 视为未收藏
func normPriority(p int) int {
	if p <= 0 {
		return 0
	}
	return p
}

// selectInitialIP 选第一个有效 IP
func (m *Manager) selectInitialIP(rl *regionListener) {
	ips := rl.ipMgr.getIPs()
	if rl.region.UseDomainIP {
		// 域名模式：DNS 里的 IP 已是测速脚本筛选的优选低延迟 IP，
		// 直接选第一个（DNS 轮询本身提供多 IP 负载均衡），无需再做延迟筛选
		if len(ips) > 0 {
			rl.ipMgr.setCurrentIP(ips[0])
			logging.InfoTo("proxy", "地区 %s 域名模式初始 currentIP = %s（共 %d 个候选，DNS 已优选）", rl.region.Name, ips[0], len(ips))
		}
		return
	}
	// IP 库模式：选第一个可达的
	for _, ip := range ips {
		if m.checkValidIP(ip, rl.region) {
			rl.ipMgr.setCurrentIP(ip)
			logging.InfoTo("proxy", "地区 %s 初始 currentIP = %s", rl.region.Name, ip)
			return
		}
	}
	if len(ips) > 0 {
		rl.ipMgr.setCurrentIP(ips[0])
		logging.WarnTo("proxy", "地区 %s 所有 IP 都验证失败，临时使用 %s", rl.region.Name, ips[0])
		return
	}
	// 库 IP 为空（use_pinned=false 或无收藏 IP）→ 标记为兜底模式
	// 不在此处阻塞式扫描兜底池（会拖慢启动），由 pickTarget 在首次连接时按需扫描
	logging.InfoTo("proxy", "地区 %s 无库IP可用，将使用兜底池（首次连接时按需选取）", rl.region.Name)
}

// checkValidIP 验证 IP 是否可用（移植自 cfnat-docker）
func (m *Manager) checkValidIP(ip string, r config.ProxyRegion) bool {
	address := ip
	if strings.Contains(ip, ":") {
		address = fmt.Sprintf("[%s]", ip)
	}
	domain := r.Domain
	if domain == "" {
		domain = "cloudflaremirrors.com/debian"
	}
	targetURL := fmt.Sprintf("https://%s", domain)
	if !r.TLS {
		targetURL = fmt.Sprintf("http://%s", domain)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			tp := r.TargetPort
			if tp <= 0 {
				tp = 443
			}
			return dialer.DialContext(ctx, network, fmt.Sprintf("%s:%d", address, tp))
		},
	}
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: tr,
	}
	resp, err := client.Get(targetURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == r.ExpectCode
}

func (m *Manager) serveRegion(ctx context.Context, ln net.Listener, r config.ProxyRegion, rl *regionListener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if strings.Contains(err.Error(), "closed") {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go m.handleConn(ctx, conn, r, rl)
	}
}

// handleConn 处理一个客户端连接
// 核心：使用 rl.ipMgr 的 currentIP，而不是每次随机
func (m *Manager) handleConn(ctx context.Context, client net.Conn, r config.ProxyRegion, rl *regionListener) {
	defer client.Close()

	target, isFallback, err := m.pickTarget(rl, r)
	if err != nil {
		logging.WarnTo("proxy", "%s: 没有可用目标 IP: %v", r.Name, err)
		return
	}
	src := "IP库"
	if isFallback {
		src = "兜底池"
	}
	tp := r.TargetPort
	if tp <= 0 {
		tp = 443
	}
	logging.InfoTo("proxy", "%s: %s → %s:%d (%s)", r.Name,
		client.RemoteAddr().String(),
		target, tp, src)

	// 对齐 cfnat-docker：以当前 currentIP 为目标，并发拨 num 份，
	// 用 r.Delay 当拨号超时（超过阈值的握手直接掐掉），并取延迟最低的那个用于转发。
	// （currentIP 粘性，不再像之前那样在池内轮询不同 IP 导致连接乱跳）
	upstream, err := m.dialBest(ctx, target, tp, r.Num, r.Delay)
	if err != nil {
		// 对齐 cfnat-docker handleConnection（cfnat.go:877-879）：拨号全部超时仅关闭
		// 当前客户端连接，绝不在连接路径切换 IP——抖动由客户端重试吸收；
		// 换 IP 只由后台健康检查在连续 2 次失败后触发（cfnat.go:797-804）。
		logging.WarnTo("proxy", "%s: 连接 %s:%d 失败: %v", r.Name, target, tp, err)
		_ = m.store.MarkIPChecked(target, r.Name, false, 0, 0)
		return
	}
	defer upstream.Close()

	// 协议自动检测
	firstByte := make([]byte, 1)
	client.SetReadDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.ReadFull(client, firstByte); err != nil {
		return
	}

	switch {
	case firstByte[0] == 0x05:
		if err := m.proxySOCKS5WithByte(client, upstream, firstByte); err != nil {
			upstream.Write(firstByte)
			go io.Copy(upstream, client)
			io.Copy(client, upstream)
		}
	case firstByte[0] >= 0x20 && firstByte[0] <= 0x7E:
		if err := m.proxyHTTPConnect(client, upstream, firstByte); err != nil {
			upstream.Write(firstByte)
			go io.Copy(upstream, client)
			io.Copy(client, upstream)
		}
	default:
		upstream.Write(firstByte)
		client.SetReadDeadline(time.Time{})
		go io.Copy(upstream, client)
		io.Copy(client, upstream)
	}
}

// pickTarget 选取转发目标（cfnat-docker 风格：优先用 currentIP）
// 1. 收藏 IP 有 → 用收藏 IP（currentIP 已记录）
// 2. 收藏 IP 空 / 全挂 → 从常驻扫描维护的热兜底池取（已按 colo 筛选 + 延迟排序，零等待）
// 3. Num>1 时：在池内前 Num 个 IP 之间轮询负载均衡（与 cfnat-docker 的 num 同义）
func (m *Manager) pickTarget(rl *regionListener, r config.ProxyRegion) (string, bool, error) {
	// 首次 / 上一轮耗尽时，从 ipMgr 列表或兜底热池选第一个有效 IP
	if cur := rl.ipMgr.getCurrentIP(); cur == "" {
		ips := rl.ipMgr.getIPs()
		if len(ips) == 0 {
			// 兜底池尚未就绪（后台扫描器可能还在首次扫描中）。
			// 不在此处同步阻塞重扫——由 regionScanLoop 异步维护热池，
			// 避免每个连接请求都触发一次全量探测导致雪崩。
			m.mu.Lock()
			pool := m.fallbackPicks[r.Name]
			m.mu.Unlock()
			if len(pool) == 0 {
				return "", false, fmt.Errorf("no candidates for region %s (fallback pool not ready)", r.Name)
			}
			rl.ipMgr.refresh(pool)
			rl.ipMgr.markFallback()
			ips = pool
		}
		// 选第一个可达的（与 selectInitialIP 一致）。usePinned 读原子标志，热切换即时生效。
		usePinned := rl.usePinned.Load()
		for _, ip := range ips {
			if m.checkValidIP(ip, rl.region) {
				rl.ipMgr.setCurrentIP(ip)
				if !usePinned {
					rl.ipMgr.markFallback()
				}
				return ip, rl.ipMgr.isFallback(), nil
			}
		}
		if len(ips) > 0 {
			rl.ipMgr.setCurrentIP(ips[0])
			if !usePinned {
				rl.ipMgr.markFallback()
			}
			logging.WarnTo("proxy", "%s: 兜底池所有 IP 验证失败，临时使用 %s", r.Name, ips[0])
			return ips[0], rl.ipMgr.isFallback(), nil
		}
		return "", false, fmt.Errorf("no valid IP for region %s", r.Name)
	}
	// 已有 currentIP：直接返回（Num 负载均衡由 handleConn 的 dialBest 并发拨号实现，不此处轮询）
	return rl.ipMgr.getCurrentIP(), rl.ipMgr.isFallback(), nil
}

// dialBest 对齐 cfnat-docker 的 generateTargets + handleConnection：
// 对同一个 currentIP 并发拨 num 份连接，用 delayMs 当拨号超时（与 cfnat-docker
// net.DialTimeout(addr, delay) 一致，超过阈值的握手直接失败），并在成功的连接里
// 取【延迟最低】的那个用于转发（对齐 cfnat-docker 的 bestConn/bestDelay 选优）。
// currentIP 始终保持粘性，绝不在池内轮询不同 IP（这是之前 HKG 连接乱跳的根因）。
func (m *Manager) dialBest(ctx context.Context, target string, port, num, delayMs int) (net.Conn, error) {
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	// 拨号超时对齐 cfnat-docker：以地区 delay 为准（delay<=0 时给一个保底值）
	timeout := time.Duration(delayMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dial := func() (net.Conn, time.Duration, error) {
		d := &net.Dialer{Timeout: timeout}
		t0 := time.Now()
		c, err := d.DialContext(ctx, "tcp", addr)
		return c, time.Since(t0), err
	}
	if num <= 1 {
		c, _, err := dial()
		return c, err
	}
	type res struct {
		conn  net.Conn
		delay time.Duration
		err   error
	}
	ch := make(chan res, num)
	for i := 0; i < num; i++ {
		go func() {
			c, d, err := dial()
			ch <- res{c, d, err}
		}()
	}
	// 收集所有结果，取延迟最低的有效连接（cfnat-docker handleConnection 的选优逻辑）
	var best net.Conn
	var bestDelay time.Duration
	for i := 0; i < num; i++ {
		r := <-ch
		if r.err == nil && r.conn != nil {
			if best == nil || r.delay < bestDelay {
				if best != nil {
					best.Close()
				}
				best = r.conn
				bestDelay = r.delay
			} else {
				r.conn.Close()
			}
		}
	}
	if best != nil {
		return best, nil
	}
	return nil, fmt.Errorf("dial %s failed", addr)
}

// 注意：AIO 严格保持 cfnat-docker 的切换逻辑 —— 只有健康检查(127.0.0.1:port，读检测)
// 连续 2 次失败才切换 IP（cfnat.go:797-804）；连接路径拨号失败只关闭当前连接、绝不换 IP
// （cfnat.go:877-879），没有任何"超延时就切"的功能。之前的 switchForDelay / ipUnderDelay
// / measureTargetLatency 等延迟切换逻辑已全部移除，切勿再自行添加。
//
// 重要：cfnat-docker 的 delay 仅作「代理拨号超时」(handleConnection 的 DialTimeout)
// 与「自检拨号超时」(statusCheck 的 DialTimeout)，【扫描/选池阶段绝不按 delay 过滤】。
// 因此 AIO 也不在扫描期对 IP 池做任何延迟阈值过滤——任何"低于 Delay 才保留"的逻辑
// 都是与 cfnat-docker 不符的错误实现，切勿再加回来。

// detectColo 通过 TCP 连接到 :80 读取 CF-RAY 头识别数据中心代码
// 延迟仅测量 TCP 握手时间（与旧 cfnat scanIPs 第764-771行一致），不含 HTTP 往返
// CF-RAY 格式为 "<id>-<colo_code>"
func (m *Manager) detectColo(ip string) (string, time.Duration) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	t0 := time.Now()
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "80"))
	if err != nil {
		return "", -1
	}
	tcpLat := time.Since(t0) // 纯 TCP 握手时间（与 cfnat-docker 一致）

	// 再发 HTTP 请求拿 CF-RAY（复用已有连接，不计入延迟）
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true
	if err := req.Write(conn); err != nil {
		conn.Close()
		return "", tcpLat
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return "", tcpLat
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // drain body

	cfRay := resp.Header.Get("CF-RAY")
	if cfRay == "" {
		return "", tcpLat
	}
	parts := strings.Split(cfRay, "-")
	return parts[len(parts)-1], tcpLat
}

// statusCheckLoop 后台健康检查循环（移植自 cfnat-docker statusCheck）
// 定时连接自己的 127.0.0.1:port 并做读检测（能感知上游 currentIP 死活，cfnat.go:743-789），
// 连续 2 次失败才切换 IP（cfnat.go:797-804）；连接路径绝不切换（cfnat.go:877-879）。
// 每隔几个周期还会刷新当前 IP 的延迟值（用于仪表盘展示）
func (m *Manager) statusCheckLoop(ctx context.Context, r config.ProxyRegion, rl *regionListener) {
	_, localPort, _ := net.SplitHostPort(fmt.Sprintf(":%d", r.Port))
	checkAddr := fmt.Sprintf("127.0.0.1:%s", localPort)

	// 给一个初始延迟
	select {
	case <-ctx.Done():
		return
	case <-time.After(10 * time.Second):
	}

	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()

	delayCheckTick := 0 // 计数器：每 4 次健康检查（约 32s）测一次延迟

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if rl.ipMgr.getCurrentIP() == "" {
				// 尚未选出 IP（首次扫描进行中 / 已耗尽等重扫）：无 IP 可判死，
				// 不计失败不切换（cfnat-docker 扫完才接客，永远不会处于此状态）
				rl.failStreak.Store(0)
			} else if m.doStatusCheck(checkAddr, r) {
				rl.failStreak.Store(0)
			} else {
				// 对齐 cfnat-docker statusCheck：需连续 2 次失败才切换（容忍单次抖动），
				// 单次失败只计数不动作（cfnat.go:735-795）
				streak := rl.failStreak.Add(1)
				if streak < 2 {
					logging.WarnTo("proxy", "%s: 单次健康检查失败（%d/2），暂不切换", r.Name, streak)
				} else {
					rl.failStreak.Store(0)
					logging.WarnTo("proxy", "%s: 连续两次状态检查失败，切换到下一个 IP", r.Name)
					m.switchRegionIP(r, rl)
				}
			}
			// 自动测速入库：currentIP 新上任（首次选定/故障切换/重启复用/换池）才触发，
			// 只测"正在当代理用的唯一一颗 IP"，同一 IP 只测一次（开关在地区配置里，默认关）
			if cur := rl.ipMgr.getCurrentIP(); cur != "" && cur != rl.lastAutoTestIP {
				rl.lastAutoTestIP = cur
				m.maybeAutoSpeedtest(r, cur)
			}
			m.mu.Lock()
			m.lastHealth[r.Name] = time.Now()
			m.mu.Unlock()

		// 周期性刷新当前 IP 的延迟（每 ~32 秒一次）
		delayCheckTick++
		if delayCheckTick >= 4 {
			delayCheckTick = 0
			m.refreshCurrentDelay(rl, r)
		}

		// 持久化当前使用的 IP（重启记忆）：关闭程序后可优先复用，秒级可用
		if cur := rl.ipMgr.getCurrentIP(); cur != "" {
			_ = m.store.SaveRegionCurrentIP(r.Name, cur)
		}
	}
	}
}

// switchRegionIP 连续 2 次健康检查失败后的切换动作（对齐 cfnat.go:797-804 的
// switchToNextValidIP + allIPsChecked → done → 主循环重扫 cfnat.go:340-347）：
//   - 顺序切到当前列表下一个有效 IP（收藏/兜底同一套，与 docker 单一列表一致）
//   - 收藏列表耗尽 → 换用常驻扫描维护的兜底热池
//   - 兜底池耗尽 → 触发重扫（60s 冷却防雪崩）
func (m *Manager) switchRegionIP(r config.ProxyRegion, rl *regionListener) {
	if rl.ipMgr.switchToNextValidIP(func(ip string) bool {
		return m.checkValidIP(ip, r)
	}) {
		return
	}
	if rl.ipMgr.isFallback() {
		logging.WarnTo("proxy", "%s: 兜底池所有 IP 已轮过，触发重新扫描", r.Name)
		m.triggerFallbackRescan(r)
		return
	}
	// 收藏 IP 全部轮过 → 换用兜底热池（与 use_pinned=false 时同池，已按 colo 筛选+延迟排序）
	m.mu.Lock()
	pool := m.fallbackPicks[r.Name]
	m.mu.Unlock()
	if len(pool) > 0 {
		rl.ipMgr.refresh(pool)
		rl.ipMgr.markFallback()
		logging.WarnTo("proxy", "%s 所有收藏 IP 都已耗尽，切入兜底池（%d 个候选）", r.Name, len(pool))
		return
	}
	rl.ipMgr.clearCurrent()
	logging.WarnTo("proxy", "%s 所有收藏 IP 都已耗尽且兜底池未就绪，触发重新扫描", r.Name)
	m.triggerFallbackRescan(r)
}

// triggerFallbackRescan 触发一次兜底池重扫（对齐 cfnat-docker 主循环重扫），
// 60s 冷却防雪崩：本地网络不通时池内 IP 全 timeout 会反复触发重扫导致 CPU/网络打满。
func (m *Manager) triggerFallbackRescan(r config.ProxyRegion) {
	const rescanCooldown = 60 * time.Second
	m.mu.Lock()
	last := m.lastRescan[r.Name]
	since := time.Since(last)
	if since < rescanCooldown {
		m.mu.Unlock()
		logging.WarnTo("proxy", "%s: 距上次重扫仅 %.0fs（冷却 %ds），跳过重扫",
			r.Name, since.Seconds(), int(rescanCooldown.Seconds()))
		return
	}
	m.lastRescan[r.Name] = time.Now()
	m.mu.Unlock()
	go m.scanRegionFallback(context.Background(), r)
}

// maybeAutoSpeedtest 自动测速入库（该地区开关开启时）：对 currentIP 测速一次，
// 达标（>= scanner.min_speed_mbps）才入库：source="auto"、priority=0（不收藏）。
// 去重原则（= 不复测）：本进程已测过 / 已在 IP 库（含收藏 IP）→ 跳过。
// 注意：速度只决定入不入库，绝不影响 cfnat 的选 IP/换 IP 逻辑（cfnat-docker 也不看速度）。
func (m *Manager) maybeAutoSpeedtest(r config.ProxyRegion, ip string) {
	if ip == "" || !r.AutoSpeedtest {
		return
	}
	key := r.Name + "|" + ip
	m.mu.Lock()
	if m.autoTested[key] {
		m.mu.Unlock()
		return
	}
	m.autoTested[key] = true
	m.mu.Unlock()
	// 已在库（含收藏 IP）→ 跳过
	for _, e := range m.lib.ListIPs(r.Name) {
		if e.IP == ip {
			return
		}
	}
	if m.SpeedTestFn == nil {
		return
	}
	go func() {
		sc := m.cfgMgr.Scanner()
		speedURL := sc.SpeedTestURL
		if speedURL == "" || speedURL == "auto" {
			speedURL = "https://speed.cloudflare.com/__down?bytes=10485760"
		}
		port := sc.Port
		if port <= 0 {
			port = 443
		}
		sec := sc.SpeedTestSec
		if sec <= 0 {
			sec = 5
		}
		mbps, _ := m.SpeedTestFn(ip, speedURL, port, sec)
		minSpeed := sc.MinSpeedMBps
		if minSpeed <= 0 {
			minSpeed = 3.0
		}
		if mbps < minSpeed {
			logging.InfoTo("proxy", "%s: 自动测速 %s = %.1fMB/s 低于门槛 %.1fMB/s，不入库", r.Name, ip, mbps, minSpeed)
			return
		}
		// 顺手测一次目标端口握手延迟作为库记录（与 refreshCurrentDelay 同口径）
		var latMs float64
		t0 := time.Now()
		if c, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port))); err == nil {
			latMs = float64(time.Since(t0).Milliseconds())
			c.Close()
		}
		if err := m.lib.AddIP(ip, r.Name, "auto", r.Code, mbps, latMs, "自动测速入库"); err == nil {
			logging.InfoTo("proxy", "%s: 自动测速 %s = %.1fMB/s ≥ %.1f，已自动入库（未收藏）", r.Name, ip, mbps, minSpeed)
		}
	}()
}

// doStatusCheck 单次自检（移植 cfnat-docker statusCheck 的读检测，cfnat.go:743-789）：
// 连接 127.0.0.1:port 后尝试读数据——
//   - 上游 currentIP 拨号成功：代理管道建立，CF 不会主动发数据 → 读超时 = 正常
//   - 上游拨号失败：handleConn 直接关闭连接 → 读到 EOF = 失败
//
// 因此它能感知上游死活，而非仅验证本机端口在监听。
// 超时对齐 cfnat-docker：用本地区 delay 当拨号/读超时（cfnat.go:743,755）。
func (m *Manager) doStatusCheck(checkAddr string, r config.ProxyRegion) bool {
	timeout := time.Duration(r.Delay) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second // delay 未配置时给保底值，避免自检永远超时
	}
	conn, err := net.DialTimeout("tcp", checkAddr, timeout)
	if err != nil {
		logging.WarnTo("proxy", "%s statusCheck 失败: %v", r.Name, err)
		return false
	}
	defer conn.Close()

	checkSuccess := make(chan bool, 1)
	go func() {
		reader := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(timeout + 1*time.Second))
		_, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				checkSuccess <- false // 服务端断开：上游拨号失败
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				checkSuccess <- true // 超时说明连接保持正常（上游管道建立）
			} else {
				checkSuccess <- false
			}
		} else {
			checkSuccess <- true
		}
	}()

	select {
	case success := <-checkSuccess:
		if !success {
			logging.WarnTo("proxy", "%s statusCheck 失败: 服务端断开连接（上游不可达）", r.Name)
		}
		return success
	case <-time.After(timeout + 2*time.Second):
		return true // 连接保持稳定
	}
}

// refreshCurrentDelay 对当前 IP 做 detectColo 刷新延迟（用于仪表盘展示）
// 非阻塞：在后台跑，成功就更新 ipMgr 的 currentDelayMs
// refreshCurrentDelay 刷新当前 IP 的延迟显示（用于 WebUI/日志）。
//
// 测量方式严格对齐 cfnat-docker 的 handleConnection（cfnat.go:830）：
// 对实际代理目标端口(默认 :443)做一次纯 TCP 握手，取 time.Since(start) 作为延迟。
// 绝不使用 :80 CF-RAY 探针（detectColo）——那是扫描阶段挑 IP 用的，与真实代理链路不同，
// 且 HTTP 往返抖动大，会导致显示数字剧烈波动（56ms→230ms→2237ms），与 cfnat-docker 不符。
func (m *Manager) refreshCurrentDelay(rl *regionListener, r config.ProxyRegion) {
	cur := rl.ipMgr.getCurrentIP()
	if cur == "" {
		return
	}
	go func() {
		tp := r.TargetPort
		if tp <= 0 {
			tp = 443
		}
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		t0 := time.Now()
		conn, err := dialer.Dial("tcp", net.JoinHostPort(cur, fmt.Sprintf("%d", tp)))
		if err != nil {
			return
		}
		conn.Close()
		lat := time.Since(t0).Milliseconds()
		rl.ipMgr.updateDelayMs(lat)
		logging.InfoTo("proxy", "%s: 延迟刷新 %s = %dms", r.Name, cur, lat)
	}()
}

// getFallbackCandidates 懒加载兜底池（与旧 cfnat 一致：全量 CF IP 范围）
// 每个 /24 生成 samplesPer24 个随机 IP，保证足够大的候选池来找到低延迟 IP
func (m *Manager) getFallbackCandidates(r config.ProxyRegion) []string {
	// 域名模式：兜底也用域名解析（可能拿到更新的 IP）
	if r.UseDomainIP && r.Domain != "" {
		return m.resolveDomainIPs(r.Domain)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cached, ok := m.fallbackPicks[r.Name]; ok && len(cached) > 0 {
		return cached
	}

	samplesPer24 := 1 // 每个 /24 抽 1 个随机 IP（与旧 cfnat 一致）
	out := make(map[string]struct{}) // 去重

	var cidrs []string
	if r.IPsType == "6" {
		cidrs = fallbackCIDRs6
	} else {
		cidrs = fallbackCIDRs
	}

	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		if ipnet.IP.To4() != nil {
			// IPv4：把大段拆成 /24 子网
			subnets := expandToSlash24(ipnet)
			for _, sub := range subnets {
				for i := 0; i < samplesPer24; i++ {
					offset := uint32(time.Now().UnixNano()+int64(i*1000))%254 + 1
					ip := addOffset(sub.IP.To4(), offset)
					if ip != nil {
						out[ip.String()] = struct{}{}
					}
				}
			}
		} else {
			// IPv6：随机抽 ipv6SamplesPerCIDR 个地址
			for _, ip := range sampleIPv6(ipnet, ipv6SamplesPerCIDR) {
				out[ip] = struct{}{}
			}
		}
	}

	result := make([]string, 0, len(out))
	for ip := range out {
		result = append(result, ip)
	}
	// 打乱顺序避免总是测同一批
	shuffleStrings(result)

	m.fallbackPicks[r.Name] = result
	if r.IPsType == "6" {
		logging.InfoTo("proxy", "兜底池生成 %d 个 IPv6 候选 IP", len(result))
	} else {
		logging.InfoTo("proxy", "兜底池生成 %d 个候选 IP（%d 个 /24 × 每个抽 %d）",
			len(result), countSlash24(fallbackCIDRs), samplesPer24)
	}
	return result
}

// expandToSlash24 将任意 CIDR 拆分为 /24 子网列表
func expandToSlash24(ipnet *net.IPNet) []*net.IPNet {
	var result []*net.IPNet
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return result
	}
	maskSize, _ := ipnet.Mask.Size()
	if maskSize >= 24 {
		// 已经是 /24 或更小，直接返回
		result = append(result, ipnet)
		return result
	}

	start := binary.BigEndian.Uint32(ip4)
	end := start | ^binary.BigEndian.Uint32(ipnet.Mask)

	// 遍历每个 /24 的起始地址
	for addr := start & 0xFFFFFF00; addr <= end; addr += 256 {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, addr)
		_, n, _ := net.ParseCIDR(fmt.Sprintf("%s/24", ip.String()))
		result = append(result, n)
	}
	return result
}

// countSlash24 统计所有 CIDR 包含多少个 /24
func countSlash24(cidrs []string) int {
	total := 0
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		maskSize, _ := ipnet.Mask.Size()
		if maskSize < 24 {
			total += 1 << (24 - maskSize)
		} else if maskSize == 24 {
			total++
		}
	}
	return total
}

func addOffset(base net.IP, offset uint32) net.IP {
	if len(base) != 4 {
		return nil
	}
	ip := make(net.IP, 4)
	val := binary.BigEndian.Uint32(base) + offset
	binary.BigEndian.PutUint32(ip, val)
	return ip
}

// shuffleStrings Fisher-Yates 打乱字符串切片
func shuffleStrings(s []string) {
	for i := len(s) - 1; i > 0; i-- {
		j := int(time.Now().UnixNano()) % (i + 1)
		s[i], s[j] = s[j], s[i]
	}
}

// proxySOCKS5WithByte 处理 SOCKS5 握手（首字节已读取）
func (m *Manager) proxySOCKS5WithByte(client, upstream net.Conn, firstByte []byte) error {
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))

	nmethodsBuf := make([]byte, 1)
	if _, err := io.ReadFull(client, nmethodsBuf); err != nil {
		return err
	}
	nmethods := int(nmethodsBuf[0])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return err
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return errors.New("unsupported SOCKS command")
	}
	addr, err := readSOCKSAddr(client)
	if err != nil {
		return err
	}
	logging.DebugTo("proxy", "SOCKS5 请求: %s", addr)

	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	_ = client.SetReadDeadline(time.Time{})

	go io.Copy(upstream, client)
	io.Copy(client, upstream)
	return nil
}

// proxyHTTPConnect 处理 HTTP CONNECT 代理（首字节已读取）
func (m *Manager) proxyHTTPConnect(client, upstream net.Conn, firstByte []byte) error {
	client.SetReadDeadline(time.Now().Add(8 * time.Second))

	br := bufio.NewReader(io.MultiReader(bytes.NewReader(firstByte), client))
	req, err := http.ReadRequest(br)
	if err != nil {
		return fmt.Errorf("HTTP parse: %w", err)
	}

	if req.Method != "CONNECT" {
		client.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return fmt.Errorf("unsupported method: %s", req.Method)
	}

	logging.DebugTo("proxy", "HTTP CONNECT: %s", req.Host)

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return err
	}
	client.SetReadDeadline(time.Time{})

	if br.Buffered() > 0 {
		buffered := make([]byte, br.Buffered())
		io.ReadFull(br, buffered)
		upstream.Write(buffered)
	}

	go io.Copy(upstream, client)
	io.Copy(client, upstream)
	return nil
}

func readSOCKSAddr(r io.Reader) (string, error) {
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return "", err
	}
	switch atyp[0] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", b[0], b[1], b[2], b[3],
			int(portBuf[0])<<8|int(portBuf[1])), nil
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		domain := make([]byte, l[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s:%d", string(domain), int(portBuf[0])<<8|int(portBuf[1])), nil
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r, portBuf); err != nil {
			return "", err
		}
		return fmt.Sprintf("[%s]:%d", net.IP(b), int(portBuf[0])<<8|int(portBuf[1])), nil
	}
	return "", errors.New("未知ATYP")
}

// liveRegion 读取实时地区配置（不持 m.mu，避免与 Sync 加锁顺序相反导致死锁）
func (m *Manager) liveRegion(name string) *config.ProxyRegion {
	regions := m.cfgMgr.Regions()
	for i := range regions {
		if regions[i].Name == name {
			r := regions[i]
			return &r
		}
	}
	return nil
}

// RefreshRegionIPs 热刷新指定地区的 IP 池（WebUI 切换"使用收藏IP" / 改了优先级后调用）
// 关键：原地刷新，不重启监听端口、不重启扫描器（cfnat-docker 无此概念，AIO 需要热切换）。
//   - 读取最新配置（UsePinned 等），写入 listener 的原子标志
//   - 重新加载 IP 池（收藏IP 或 热兜底池）
//   - 若当前 currentIP 已不在新列表 / 不再是首选，重新选择
func (m *Manager) RefreshRegionIPs(region string) {
	m.mu.Lock()
	rl, ok := m.listeners[region]
	m.mu.Unlock()
	if !ok || rl == nil {
		return
	}
	live := m.liveRegion(region)
	if live == nil {
		return
	}
	r := *live
	// 把最新 UsePinned 写入原子标志，使运行中的 pickTarget 立即读到（无需重启）
	rl.usePinned.Store(r.UsePinned)

	oldIP := rl.ipMgr.getCurrentIP()
	ips := m.initRegionIPs(r)
	rl.ipMgr.refresh(ips)

	// 兜底模式下 refresh 不改变 fallbackMode，此处显式恢复标记
	if !r.UsePinned && len(ips) > 0 {
		rl.ipMgr.markFallback()
	}

	// refresh 后两种情况需要重新选 currentIP：
	//  1) currentIP 为空（旧 IP 已不在新列表里）
	//  2) currentIP 还在新列表里，但它不是"最优先"的（P1 排第一）
	needReselect := false
	if rl.ipMgr.getCurrentIP() == "" {
		needReselect = true
	} else if len(ips) > 0 && ips[0] != rl.ipMgr.getCurrentIP() {
		// 新排序后第一的 IP 不是 currentIP → 重新选（用最优先的）
		needReselect = true
		logging.InfoTo("proxy", "%s: IP 顺序有变，触发重新选择 (旧=%s, 新首选=%s)",
			region, oldIP, ips[0])
	}
	if needReselect {
		m.selectInitialIP(rl)
	}
}

// Status 健康状态
type Status struct {
	Regions       []RegionStatus `json:"regions"`
	StartedAt     string         `json:"started_at"`
	UptimeSeconds int64          `json:"uptime_seconds"`
}

// RegionStatus 地区状态
type RegionStatus struct {
	Name            string `json:"name"`
	Port            int    `json:"port"`
	Enabled         bool   `json:"enabled"`
	IPCount         int    `json:"ip_count"`
	PinnedCount     int    `json:"pinned_count"`
	Listening       bool   `json:"listening"`
	CurrentIP       string `json:"current_ip"`
	CurrentPriority int    `json:"current_priority"`
	Colo            string `json:"colo"`
	LastHealthCheck string `json:"last_health_check"`
	CurrentDelayMs  int64  `json:"current_delay_ms"` // 当前 IP 延迟（毫秒），0=未测量/IP库
	IsFallback      bool   `json:"is_fallback"`     // 当前 IP 是否来自兜底池
}

// Status 获取所有地区状态
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	regions := m.cfgMgr.Regions()
	out := make([]RegionStatus, 0, len(regions))
	for _, r := range regions {
		rl, listening := m.listeners[r.Name]
		var currentIP string
		var currentDelayMs int64
		var isFallback bool
		if listening && rl != nil {
			currentIP = rl.ipMgr.getCurrentIP()
			currentDelayMs = rl.ipMgr.getCurrentDelayMs()
			isFallback = rl.ipMgr.isFallback()
		}
		var lastCheck string
		if t, ok := m.lastHealth[r.Name]; ok {
			lastCheck = t.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, RegionStatus{
			Name:            r.Name,
			Port:            r.Port,
			Enabled:         r.Enabled,
			IPCount:         m.lib.CountIPs(r.Name),
			PinnedCount:     m.lib.CountPinned(r.Name),
			Listening:       listening,
			CurrentIP:       currentIP,
			CurrentPriority: 0,
			Colo:            r.Code,
			LastHealthCheck: lastCheck,
			CurrentDelayMs:  currentDelayMs,
			IsFallback:      isFallback,
		})
	}
	uptime := int64(0)
	if !m.startedAt.IsZero() {
		uptime = int64(time.Since(m.startedAt).Seconds())
	}
	return Status{
		Regions:       out,
		StartedAt:     m.startedAt.UTC().Format(time.RFC3339),
		UptimeSeconds: uptime,
	}
}
