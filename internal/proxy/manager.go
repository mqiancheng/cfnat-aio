// Package proxy CFNAT-AIO 代理转发模块
//
// 核心特性：
//   - 继承 cfnat 的转发逻辑（SOCKS5 / HTTP）
//   - 多地区管理：每个 ProxyRegion 一个独立监听端口
//   - 动态增删地区（WebUI 改配置即可，不重启进程）
//   - 兜底：库中 IP 全挂时自动切全量 CF 随机 IP
//   - 热重载：regions 变更后自动重启对应监听
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"cfnat-aio/internal/config"
	"cfnat-aio/internal/iplibrary"
	"cfnat-aio/internal/logging"
)

// 全量 CF IP 兜底池（每 /24 抽 1 个，懒加载）
var fallbackCIDRs = []string{
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
	"104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
	"162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
	"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
}

// Manager 多地区代理管理器
type Manager struct {
	store   *config.SQLiteStore
	lib     *iplibrary.Library
	cfgMgr  *config.Manager

	mu      sync.Mutex
	listeners map[string]*regionListener  // region -> listener
	regions   map[string]config.ProxyRegion // region -> 最新配置

	fallbackPicks map[string][]string // region -> 当前兜底池（懒填充）

	// 运行状态（供 WebUI 显示）
	running    bool
	startedAt  time.Time
	lastHealth map[string]time.Time // region -> 上次健康检查时间
	currentIP  map[string]string    // region -> 当前代理中使用的 IP（从日志/手动）
}

// New 创建代理管理器
func New(store *config.SQLiteStore, lib *iplibrary.Library, cfgMgr *config.Manager) *Manager {
	m := &Manager{
		store:         store,
		lib:           lib,
		cfgMgr:        cfgMgr,
		listeners:     make(map[string]*regionListener),
		regions:       make(map[string]config.ProxyRegion),
		fallbackPicks: make(map[string][]string),
		lastHealth:    make(map[string]time.Time),
		currentIP:     make(map[string]string),
		startedAt:     time.Now(),
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
			log.Printf("[proxy] region %s removed/stopped", name)
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
			// 配置变化（端口/colo），重启
			cur.stop()
			delete(m.listeners, name)
		}
		l := m.startRegion(r)
		if l != nil {
			m.listeners[name] = l
			m.regions[name] = r
			log.Printf("[proxy] region %s listening on :%d", name, r.Port)
		}
	}
	return nil
}

type regionListener struct {
	region config.ProxyRegion
	ln     net.Listener
	cancel context.CancelFunc
	done   chan struct{}
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
	logging.InfoTo("proxy", "▶ 启动代理 %s → :%d (colo=%s, 当前可用 IP=%d)",
		r.Name, r.Port, r.Code, m.lib.CountIPs(r.Name))
	ctx, cancel := context.WithCancel(context.Background())
	rl := &regionListener{
		region: r,
		ln:     ln,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(rl.done)
		m.serveRegion(ctx, ln, r)
	}()
	return rl
}

func (m *Manager) serveRegion(ctx context.Context, ln net.Listener, r config.ProxyRegion) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// 判断是否 listener 已关闭
			if strings.Contains(err.Error(), "closed") {
				return
			}
			// 临时错误，继续
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go m.handleConn(ctx, conn, r)
	}
}

// handleConn 处理一个客户端连接（自动协议检测：SOCKS5 / HTTP CONNECT / TLS透传）
func (m *Manager) handleConn(ctx context.Context, client net.Conn, r config.ProxyRegion) {
	defer client.Close()

	// 选 IP
	target, isFallback, err := m.pickTarget(r.Name)
	if err != nil {
		logging.WarnTo("proxy", "%s: 没有可用目标 IP: %v", r.Name, err)
		return
	}
	src := "IP库"
	if isFallback {
		src = "兜底池"
	}
	logging.InfoTo("proxy", "%s: %s → %s:443 (%s)", r.Name,
		client.RemoteAddr().String(),
		target, src)

	m.mu.Lock()
	m.currentIP[r.Name] = target
	m.mu.Unlock()

	// 连接上游 CF IP:443
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	upstream, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:443", target))
	if err != nil {
		logging.WarnTo("proxy", "%s: 连接 %s:443 失败: %v", r.Name, target, err)
		_ = m.store.MarkIPChecked(target, r.Name, false, 0, 0)
		return
	}
	defer upstream.Close()

	// 协议自动检测：读第一个字节判断
	firstByte := make([]byte, 1)
	client.SetReadDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.ReadFull(client, firstByte); err != nil {
		return
	}

	switch {
	case firstByte[0] == 0x05:
		// SOCKS5 CONNECT 代理
		if err := m.proxySOCKS5WithByte(client, upstream, firstByte); err != nil {
			// SOCKS5 握手失败，回退到透传（重发已读字节）
			upstream.Write(firstByte)
			go io.Copy(upstream, client)
			io.Copy(client, upstream)
		}

	case firstByte[0] >= 0x20 && firstByte[0] <= 0x7E:
		// 可打印 ASCII → 可能是 HTTP CONNECT
		if err := m.proxyHTTPConnect(client, upstream, firstByte); err != nil {
			// HTTP 解析失败，回退到透传
			upstream.Write(firstByte)
			go io.Copy(upstream, client)
			io.Copy(client, upstream)
		}

	default:
		// 非标准开头的字节流（TLS ClientHello 等）→ 透传
		upstream.Write(firstByte)
		client.SetReadDeadline(time.Time{})
		go io.Copy(upstream, client)
		io.Copy(client, upstream)
	}
}

// pickTarget 选取转发目标
func (m *Manager) pickTarget(region string) (string, bool, error) {
	ip, err := m.lib.PickRandom(region)
	if err == nil {
		return ip, false, nil
	}
	// 兜底
	candidates := m.getFallbackCandidates(region)
	if len(candidates) == 0 {
		return "", false, fmt.Errorf("no candidates for region %s", region)
	}
	ip, _ = m.lib.PickFallback(candidates)
	return ip, true, nil
}

// getFallbackCandidates 懒加载兜底池
func (m *Manager) getFallbackCandidates(region string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cached, ok := m.fallbackPicks[region]; ok && len(cached) > 0 {
		return cached
	}
	// 从 CIDR 池抽取一些 IP
	var out []string
	for _, c := range fallbackCIDRs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		// 每个 /24 抽一个
		offset := uint32(time.Now().UnixNano()%256) + 1
		ip := addOffset(ipnet.IP.To4(), offset)
		if ip != nil {
			out = append(out, ip.String())
		}
	}
	if len(out) > 50 {
		out = out[:50]
	}
	m.fallbackPicks[region] = out
	return out
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

// proxySOCKS5WithByte 处理 SOCKS5 握手（首字节已读取）
func (m *Manager) proxySOCKS5WithByte(client, upstream net.Conn, firstByte []byte) error {
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))

	// ver 已确认是 0x05（firstByte[0]）
	// 读 nmethods
	nmethodsBuf := make([]byte, 1)
	if _, err := io.ReadFull(client, nmethodsBuf); err != nil {
		return err
	}
	nmethods := int(nmethodsBuf[0])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return err
	}
	// 回应：无需认证
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}

	// 读请求
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

	// 应答成功
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	_ = client.SetReadDeadline(time.Time{})

	// 双向转发
	go io.Copy(upstream, client)
	io.Copy(client, upstream)
	return nil
}

// proxyHTTPConnect 处理 HTTP CONNECT 代理（首字节已读取）
func (m *Manager) proxyHTTPConnect(client, upstream net.Conn, firstByte []byte) error {
	client.SetReadDeadline(time.Now().Add(8 * time.Second))

	// 用 bufio.Reader 包装（首字节 + 客户端流）
	br := bufio.NewReader(io.MultiReader(bytes.NewReader(firstByte), client))

	// 读 HTTP 请求
	req, err := http.ReadRequest(br)
	if err != nil {
		return fmt.Errorf("HTTP parse: %w", err)
	}

	if req.Method != "CONNECT" {
		client.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return fmt.Errorf("unsupported method: %s", req.Method)
	}

	logging.DebugTo("proxy", "HTTP CONNECT: %s", req.Host)

	// 回应 200 Connection Established
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return err
	}
	client.SetReadDeadline(time.Time{})

	// br 可能已缓冲了 CONNECT 之后的隧道数据，先排空
	if br.Buffered() > 0 {
		buffered := make([]byte, br.Buffered())
		io.ReadFull(br, buffered)
		upstream.Write(buffered)
	}

	// 双向转发
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
	case 0x01: // IPv4
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
	case 0x03: // Domain
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
	case 0x04: // IPv6
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

// HandleHTTPProxy HTTP CONNECT 代理（备用）
func (m *Manager) HandleHTTPProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "请使用CONNECT", http.StatusMethodNotAllowed)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	region := r.Header.Get("X-CFNAT-Region")
	if region == "" {
		region = "HKG"
	}
	target, _, err := m.pickTarget(region)
	if err != nil {
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	upstream, err := net.DialTimeout("tcp", fmt.Sprintf("%s:443", target), 5*time.Second)
	if err != nil {
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()
	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go io.Copy(upstream, client)
	io.Copy(client, upstream)
}

// Status 健康状态
type Status struct {
	Regions      []RegionStatus `json:"regions"`
	StartedAt    string         `json:"started_at"`
	UptimeSeconds int64         `json:"uptime_seconds"`
}

// RegionStatus 地区状态
type RegionStatus struct {
	Name      string `json:"name"`
	Port      int    `json:"port"`
	Enabled   bool   `json:"enabled"`
	IPCount   int    `json:"ip_count"`
	Listening bool   `json:"listening"`
	CurrentIP string `json:"current_ip"`
	Colo      string `json:"colo"`
	Clients   int    `json:"clients"` // 当前活跃连接数（近似）
}

// Status 获取所有地区状态
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	regions := m.cfgMgr.Regions()
	out := make([]RegionStatus, 0, len(regions))
	for _, r := range regions {
		_, listening := m.listeners[r.Name]
		out = append(out, RegionStatus{
			Name:      r.Name,
			Port:      r.Port,
			Enabled:   r.Enabled,
			IPCount:   m.lib.CountIPs(r.Name),
			Listening: listening,
			CurrentIP: m.currentIP[r.Name],
			Colo:      r.Code,
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

// 静默导入占位（无）
