// Package config 统一管理 CFNAT-AIO 的运行时配置
//
// 配置以内存对象 + SQLite 持久化双写：
//   - 启动时从数据库加载，写入内存
//   - WebUI 修改时，先写 DB，再同步到内存（热更新）
//   - 进程退出时无需主动保存（任何修改都已落库）
package config

import (
	"encoding/json"
	"log"
	"sync"
	"time"
)

// ProxyRegion 描述一个代理地区（监听端口 + CMIN2 IP 库）
type ProxyRegion struct {
	Name      string `json:"name"`       // HKG / LAX / JP
	Code      string `json:"code"`       // 数据中心代码（用于从扫描结果匹配）
	Port      int    `json:"port"`       // 监听端口
	Enabled   bool   `json:"enabled"`    // 是否启用
	Fallback  bool   `json:"fallback"`   // 库中 IP 全不可用时是否自动 fallback 到全量 CF
	IPCount   int    `json:"ip_count"`   // 当前可用 IP 数（运行时统计）
	LastCheck string `json:"last_check"` // 上次健康检查时间
}

// ScannerConfig 扫描器配置
type ScannerConfig struct {
	Enabled       bool    `json:"enabled"`         // 是否开启后台自动扫描
	Interval      int     `json:"interval"`        // 扫描间隔（分钟）
	MinSpeedMBps  float64 `json:"min_speed_mbps"`  // 测速合格阈值（MB/s）
	IPType        int     `json:"ip_type"`         // 4 或 6
	Port          int     `json:"port"`            // 测试端口
	SamplesPer24  int     `json:"samples_per_24"`  // 每 /24 抽样数（1/3/5/全测=255）
	MaxDelayMs    int     `json:"max_delay_ms"`    // 最大延迟阈值
	Threads       int     `json:"threads"`         // 并发数
	ScanMode      string  `json:"scan_mode"`       // tcping / httping
	SpeedTestURL  string  `json:"speed_test_url"`  // 测速下载 URL（auto=自动选）
	OnlyCMIN2     bool    `json:"only_cmin2"`      // 是否只保留 CMIN2 节点
	CMIN2Colos    string  `json:"cmin2_colos"`     // CMIN2 节点列表（逗号分隔）
	NextRunTime   string  `json:"next_run_time"`   // 下次运行时间（运行时计算）
	LastRunTime   string  `json:"last_run_time"`   // 上次完成时间
	LastRunStatus string  `json:"last_run_status"` // 上次状态
	LastRunStats  string  `json:"last_run_stats"`  // 上次扫描统计 JSON
}

// GeneralConfig 通用配置
type GeneralConfig struct {
	WebUIPort    int    `json:"webui_port"`     // WebUI 监听端口
	APIToken     string `json:"api_token"`      // API 鉴权 token（可选）
	DataDir      string `json:"data_dir"`       // 数据目录（存放 cfnat-aio.db）
	LogLevel     string `json:"log_level"`      // debug/info/warn/error
	AutoStart    bool   `json:"auto_start"`     // 容器启动时是否自动开启扫描和代理
}

// Manager 全局配置管理器（线程安全）
type Manager struct {
	mu      sync.RWMutex
	general GeneralConfig
	scanner ScannerConfig
	regions []ProxyRegion
	db      ConfigStore
}

// ConfigStore 配置持久化接口（解耦 DB 依赖）
type ConfigStore interface {
	LoadGeneral() (GeneralConfig, error)
	SaveGeneral(g GeneralConfig) error
	LoadScanner() (ScannerConfig, error)
	SaveScanner(s ScannerConfig) error
	LoadRegions() ([]ProxyRegion, error)
	SaveRegions(regions []ProxyRegion) error
}

// New 创建配置管理器，从 DB 加载初始配置
func New(store ConfigStore) (*Manager, error) {
	m := &Manager{db: store}
	if err := m.loadAll(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) loadAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if g, err := m.db.LoadGeneral(); err == nil {
		m.general = g
	} else {
		// 首次启动，使用默认值
		m.general = GeneralConfig{
			WebUIPort: 1234,
			DataDir:   "/data",
			LogLevel:  "info",
			AutoStart: true,
		}
		_ = m.db.SaveGeneral(m.general)
	}

	if s, err := m.db.LoadScanner(); err == nil {
		m.scanner = s
	} else {
		m.scanner = defaultScannerConfig()
		_ = m.db.SaveScanner(m.scanner)
	}

	if rs, err := m.db.LoadRegions(); err == nil && len(rs) > 0 {
		m.regions = rs
	} else {
		// 默认地区列表
		m.regions = []ProxyRegion{
			{Name: "HKG", Code: "HKG", Port: 1001, Enabled: true, Fallback: true},
			{Name: "LAX", Code: "LAX", Port: 1002, Enabled: true, Fallback: true},
			{Name: "JP",  Code: "NRT", Port: 1003, Enabled: true, Fallback: true},
		}
		_ = m.db.SaveRegions(m.regions)
	}
	return nil
}

func defaultScannerConfig() ScannerConfig {
	return ScannerConfig{
		Enabled:      false,
		Interval:     60,
		MinSpeedMBps: 3.0,
		IPType:       4,
		Port:         443,
		SamplesPer24: 1,
		MaxDelayMs:   500,
		Threads:      100,
		ScanMode:     "tcping",
		SpeedTestURL: "auto",
		OnlyCMIN2:    true,
		CMIN2Colos:   "HKG,SIN,NRT,KIX,LAX,SJC,SEA,FRA,AMS,LHR,TPE,ICN,MNL,BKK,MFM",
	}
}

// === 访问器 ===

func (m *Manager) General() GeneralConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.general
}

func (m *Manager) Scanner() ScannerConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scanner
}

func (m *Manager) Regions() []ProxyRegion {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ProxyRegion, len(m.regions))
	copy(out, m.regions)
	return out
}

// === 修改器（写库 + 更新内存） ===

func (m *Manager) UpdateGeneral(g GeneralConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.db.SaveGeneral(g); err != nil {
		return err
	}
	m.general = g
	return nil
}

func (m *Manager) UpdateScanner(s ScannerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.db.SaveScanner(s); err != nil {
		return err
	}
	m.scanner = s
	return nil
}

func (m *Manager) UpdateRegions(regions []ProxyRegion) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.db.SaveRegions(regions); err != nil {
		return err
	}
	m.regions = regions
	return nil
}

func (m *Manager) UpdateRegion(name string, mut func(*ProxyRegion)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.regions {
		if m.regions[i].Name == name {
			mut(&m.regions[i])
			break
		}
	}
	return m.db.SaveRegions(m.regions)
}

// NowISO 辅助函数
func NowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

// DumpJSON 用于调试
func (m *Manager) DumpJSON() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := map[string]interface{}{
		"general": m.general,
		"scanner": m.scanner,
		"regions": m.regions,
	}
	b, _ := json.MarshalIndent(all, "", "  ")
	return string(b)
}

// Log 简单的日志包装
func (m *Manager) Logf(format string, v ...interface{}) {
	level := m.General().LogLevel
	if level == "debug" {
		log.Printf("[DEBUG] "+format, v...)
	} else {
		log.Printf(format, v...)
	}
}
