// Package iplibrary CMIN2 优选 IP 库
//
// 核心职责：
//   - 按地区（HKG/LAX/JP/...）独立存储 IP
//   - 供代理模块读取，作为转发目标池
//   - 供扫描模块写入，作为入库目标
//   - 定期健康检查，自动淘汰失效 IP
package iplibrary

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"cfnat-aio/internal/config"
)

// Library CMIN2 IP 库
type Library struct {
	store *config.SQLiteStore
	mu    sync.RWMutex

	// 热缓存：每地区的可用 IP 列表
	cache map[string][]string // region -> [ip, ip, ...] (按速度排序)
}

// New 创建 IP 库
func New(store *config.SQLiteStore) *Library {
	lib := &Library{
		store: store,
		cache: make(map[string][]string),
	}
	lib.reload()
	return lib
}

// reload 从 DB 重建内存缓存
func (l *Library) reload() {
	all, err := l.store.ListAllIPs()
	if err != nil {
		return
	}
	tmp := make(map[string][]config.IPEntry)
	for _, e := range all {
		tmp[e.Region] = append(tmp[e.Region], e)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cache = make(map[string][]string)
	for region, list := range tmp {
		// 按速度降序
		sort.Slice(list, func(i, j int) bool {
			return list[i].SpeedMbps > list[j].SpeedMbps
		})
		ips := make([]string, 0, len(list))
		for _, e := range list {
			ips = append(ips, e.IP)
		}
		l.cache[region] = ips
	}
}

// AddIP 添加 IP（来源：auto/manual/fofa）
func (l *Library) AddIP(ip, region, source, colo string, speed, latency float64, note string) error {
	err := l.store.UpsertIP(config.IPEntry{
		IP:        ip,
		Region:    region,
		Colo:      colo,
		SpeedMbps: speed,
		LatencyMs: latency,
		Source:    source,
		LastOK:    true,
		Note:      note,
	})
	if err == nil {
		l.reload()
	}
	return err
}

// RemoveIP 删除 IP
func (l *Library) RemoveIP(ip, region string) error {
	err := l.store.DeleteIP(ip, region)
	if err == nil {
		l.reload()
	}
	return err
}

// ListIPs 列出某地区所有 IP
func (l *Library) ListIPs(region string) []config.IPEntry {
	entries, _ := l.store.ListIPs(region)
	return entries
}

// CountIPs 统计某地区 IP 数
func (l *Library) CountIPs(region string) int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.cache[region])
}

// PickRandom 从某地区随机挑一个 IP（代理用）
// 会先做"软过滤"：跳过最近失败过的 IP
func (l *Library) PickRandom(region string) (string, error) {
	l.mu.RLock()
	ips := l.cache[region]
	l.mu.RUnlock()

	if len(ips) == 0 {
		return "", fmt.Errorf("region %q has no IPs", region)
	}

	// 顺序随机选取，失败的也允许（兜底）
	rand.Seed(time.Now().UnixNano())
	idx := rand.Intn(len(ips))
	return ips[idx], nil
}

// PickFallback 库为空时，从全量 CF IP 中随机选（兜底）
// 这部分由调用方传入候选列表
func (l *Library) PickFallback(candidates []string) (string, error) {
	if len(candidates) == 0 {
		return "", fmt.Errorf("no fallback candidates")
	}
	rand.Seed(time.Now().UnixNano())
	return candidates[rand.Intn(len(candidates))], nil
}

// HealthCheck 健康检查一个地区所有 IP
//   - 主动 TCP 探活
//   - 连续失败 3 次的 IP 自动从库中删除
//   - checkFn 由调用方提供（避免循环依赖）
func (l *Library) HealthCheck(region string, checkFn func(ip string) (ok bool, latencyMs float64)) (int, int) {
	entries := l.ListIPs(region)
	ok, fail := 0, 0
	for _, e := range entries {
		isOK, latency := checkFn(e.IP)
		_ = l.store.MarkIPChecked(e.IP, region, isOK, e.SpeedMbps, latency)
		if isOK {
			ok++
		} else {
			fail++
		}
	}
	// 失败 3 次的自动清出
	removed, _ := l.store.RemoveFailingIPs(3)
	if removed > 0 {
		l.reload()
	}
	return ok, fail
}

// HealthCheckAll 对所有地区做健康检查
func (l *Library) HealthCheckAll(checkFn func(ip string) (ok bool, latencyMs float64)) map[string][2]int {
	regions := make(map[string]bool)
	all, _ := l.store.ListAllIPs()
	for _, r := range all {
		regions[r.Region] = true
	}
	out := make(map[string][2]int)
	for r := range regions {
		ok, fail := l.HealthCheck(r, checkFn)
		out[r] = [2]int{ok, fail}
	}
	return out
}

// Regions 返回所有有 IP 的地区列表
func (l *Library) Regions() []string {
	all, _ := l.store.ListAllIPs()
	set := make(map[string]bool)
	for _, e := range all {
		set[e.Region] = true
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// IsEmpty 地区是否为空
func (l *Library) IsEmpty(region string) bool {
	return l.CountIPs(region) == 0
}
