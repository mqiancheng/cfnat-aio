// Package config 提供基于 SQLite 的配置持久化实现
package config

import (
	"database/sql"
	"encoding/json"
	"fmt"

	_ "modernc.org/sqlite"
)

// SQLiteStore SQLite 配置存储
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore 创建并初始化 SQLite 配置存储
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	s := &SQLiteStore{db: db}
	if err := s.init(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS kv_config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS iplib_ip (
		ip TEXT NOT NULL,
		region TEXT NOT NULL,
		colo TEXT,
		speed_mbps REAL,
		latency_ms REAL,
		source TEXT,
		added_at TEXT,
		last_check TEXT,
		last_ok INTEGER,
		fail_count INTEGER DEFAULT 0,
		note TEXT,
		priority INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (ip, region)
	);
	CREATE TABLE IF NOT EXISTS iplib_meta (
		ip TEXT NOT NULL,
		region TEXT NOT NULL,
		cidr24 TEXT,
		tested_count INTEGER DEFAULT 0,
		last_test TEXT,
		last_ok INTEGER,
		avg_speed_mbps REAL,
		PRIMARY KEY (ip, region)
	);
	CREATE TABLE IF NOT EXISTS scan_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		started_at TEXT,
		finished_at TEXT,
		status TEXT,
		total INTEGER,
		passed INTEGER,
		stats_json TEXT
	);
	`
	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}
	// 兼容旧库：补充 priority 列（已存在则忽略错误）
	_, _ = s.db.Exec(`ALTER TABLE iplib_ip ADD COLUMN priority INTEGER NOT NULL DEFAULT 0`)
	// 一次性迁移旧数据：旧库默认 priority=3（导入即"收藏"），新语义导入=0（不收藏）
	// 仅执行一次，避免误清用户在排名系统中恰好排第 3 的收藏 IP（priority=3）
	if _, err := s.getKV("migrated_priority_default"); err != nil {
		_, _ = s.db.Exec(`UPDATE iplib_ip SET priority = 0 WHERE priority = 3`)
		_ = s.setKV("migrated_priority_default", "1")
	}
	return nil
}

// === KV 读写辅助 ===

func (s *SQLiteStore) setKV(key, value string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO kv_config(key,value) VALUES(?,?)`, key, value)
	return err
}

func (s *SQLiteStore) getKV(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM kv_config WHERE key=?`, key).Scan(&v)
	return v, err
}

// === ConfigStore 接口实现 ===

func (s *SQLiteStore) LoadGeneral() (GeneralConfig, error) {
	v, err := s.getKV("general")
	if err != nil {
		return GeneralConfig{}, err
	}
	var g GeneralConfig
	err = json.Unmarshal([]byte(v), &g)
	return g, err
}

func (s *SQLiteStore) SaveGeneral(g GeneralConfig) error {
	b, _ := json.Marshal(g)
	return s.setKV("general", string(b))
}

func (s *SQLiteStore) LoadScanner() (ScannerConfig, error) {
	v, err := s.getKV("scanner")
	if err != nil {
		return ScannerConfig{}, err
	}
	var sc ScannerConfig
	err = json.Unmarshal([]byte(v), &sc)
	return sc, err
}

func (s *SQLiteStore) SaveScanner(sc ScannerConfig) error {
	b, _ := json.Marshal(sc)
	return s.setKV("scanner", string(b))
}

func (s *SQLiteStore) LoadCfnat() (CfnatConfig, error) {
	v, err := s.getKV("cfnat")
	if err != nil {
		return CfnatConfig{}, err
	}
	var c CfnatConfig
	err = json.Unmarshal([]byte(v), &c)
	return c, err
}

func (s *SQLiteStore) SaveCfnat(c CfnatConfig) error {
	b, _ := json.Marshal(c)
	return s.setKV("cfnat", string(b))
}

func (s *SQLiteStore) LoadRegions() ([]ProxyRegion, error) {
	v, err := s.getKV("regions")
	if err != nil {
		return nil, err
	}
	var rs []ProxyRegion
	err = json.Unmarshal([]byte(v), &rs)
	return rs, err
}

func (s *SQLiteStore) SaveRegions(regions []ProxyRegion) error {
	b, _ := json.Marshal(regions)
	return s.setKV("regions", string(b))
}

// === IP 库读写 ===

type IPEntry struct {
	IP        string  `json:"ip"`
	Region    string  `json:"region"`
	Colo      string  `json:"colo"`
	SpeedMbps float64 `json:"speed_mbps"`
	LatencyMs float64 `json:"latency_ms"`
	Source    string  `json:"source"`
	AddedAt   string  `json:"added_at"`
	LastCheck string  `json:"last_check"`
	LastOK    bool    `json:"last_ok"`
	FailCount int     `json:"fail_count"`
	Note      string  `json:"note"`
	Priority  int     `json:"priority"`
}

type IPMeta struct {
	IP           string
	Region       string
	CIDR24       string
	TestedCount  int
	LastTest     string
	LastOK       bool
	AvgSpeedMbps float64
}

func (s *SQLiteStore) UpsertIP(e IPEntry) error {
	if e.AddedAt == "" {
		e.AddedAt = NowISO()
	}
	// 保留已有优先级：未显式指定(priority==0)时沿用库中值，避免重新导入把收藏 IP 降级
	// 新 IP（库中不存在）默认 priority=0（仅进入 IP 库列表，不自动收藏）
	priority := e.Priority
	if priority == 0 {
		if p, err := s.getPriority(e.IP, e.Region); err == nil {
			priority = p
		} else {
			priority = 0
		}
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO iplib_ip
		(ip,region,colo,speed_mbps,latency_ms,source,added_at,last_check,last_ok,fail_count,note,priority)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.IP, e.Region, e.Colo, e.SpeedMbps, e.LatencyMs, e.Source,
		e.AddedAt, e.LastCheck, e.LastOK, e.FailCount, e.Note, priority)
	return err
}

// getPriority 读取某 IP 的优先级（不存在返回错误）
func (s *SQLiteStore) getPriority(ip, region string) (int, error) {
	var p int
	err := s.db.QueryRow(`SELECT COALESCE(priority,0) FROM iplib_ip WHERE ip=? AND region=?`, ip, region).Scan(&p)
	return p, err
}

// SetPriority 设置某 IP 的优先级（>0 收藏/排序号，0=未收藏）
func (s *SQLiteStore) SetPriority(ip, region string, priority int) error {
	_, err := s.db.Exec(`UPDATE iplib_ip SET priority=? WHERE ip=? AND region=?`, priority, ip, region)
	return err
}

// ReorderPriority 调整收藏 IP 排序（与相邻项交换位置）
// direction: "up" 向上移（排位-1），"down" 向下移（排位+1）
func (s *SQLiteStore) ReorderPriority(ip, region, direction string) error {
	// 获取该地区所有收藏 IP（priority > 0），按 priority 升序排列
	rows, err := s.db.Query(`SELECT ip, priority FROM iplib_ip WHERE region=? AND priority>0 ORDER BY priority ASC`, region)
	if err != nil {
		return err
	}
	defer rows.Close()
	type item struct {
		ip       string
		priority int
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ip, &it.priority); err != nil {
			return err
		}
		items = append(items, it)
	}

	// 找到目标 IP 的位置
	idx := -1
	for i, it := range items {
		if it.ip == ip {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("ip %s not found in pinned list for region %s", ip, region)
	}

	// 计算交换目标
	swapIdx := -1
	if direction == "up" && idx > 0 {
		swapIdx = idx - 1
	} else if direction == "down" && idx < len(items)-1 {
		swapIdx = idx + 1
	}
	if swapIdx < 0 {
		return nil // 已经在边界，无需操作
	}

	// 交换 priority 值
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	_, _ = tx.Exec(`UPDATE iplib_ip SET priority=? WHERE ip=? AND region=?`,
		items[swapIdx].priority, items[idx].ip, region)
	_, _ = tx.Exec(`UPDATE iplib_ip SET priority=? WHERE ip=? AND region=?`,
		items[idx].priority, items[swapIdx].ip, region)
	return tx.Commit()
}

// UpdateSpeedIP 仅更新速度和延迟（不触碰其他字段）
func (s *SQLiteStore) UpdateSpeedIP(ip, region string, speed, latency float64) error {
	_, err := s.db.Exec(`UPDATE iplib_ip SET speed_mbps=?, latency_ms=?, last_check=?, last_ok=1 WHERE ip=? AND region=?`,
		speed, latency, NowISO(), ip, region)
	return err
}

func (s *SQLiteStore) DeleteIP(ip, region string) error {
	_, err := s.db.Exec(`DELETE FROM iplib_ip WHERE ip=? AND region=?`, ip, region)
	return err
}

func (s *SQLiteStore) ListIPs(region string) ([]IPEntry, error) {
	rows, err := s.db.Query(`SELECT ip,region,colo,COALESCE(speed_mbps,0),COALESCE(latency_ms,0),
		COALESCE(source,''),COALESCE(added_at,''),COALESCE(last_check,''),
		COALESCE(last_ok,0),COALESCE(fail_count,0),		COALESCE(note,''),COALESCE(priority,0)
		FROM iplib_ip WHERE region=? ORDER BY COALESCE(priority,0) ASC, speed_mbps DESC`, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPEntry
	for rows.Next() {
		var e IPEntry
		if err := rows.Scan(&e.IP, &e.Region, &e.Colo, &e.SpeedMbps, &e.LatencyMs,
			&e.Source, &e.AddedAt, &e.LastCheck, &e.LastOK, &e.FailCount, &e.Note, &e.Priority); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *SQLiteStore) ListAllIPs() ([]IPEntry, error) {
	rows, err := s.db.Query(`SELECT ip,region,colo,COALESCE(speed_mbps,0),COALESCE(latency_ms,0),
		COALESCE(source,''),COALESCE(added_at,''),COALESCE(last_check,''),
		COALESCE(last_ok,0),COALESCE(fail_count,0),		COALESCE(note,''),COALESCE(priority,0)
		FROM iplib_ip ORDER BY region, COALESCE(priority,0) ASC, speed_mbps DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPEntry
	for rows.Next() {
		var e IPEntry
		if err := rows.Scan(&e.IP, &e.Region, &e.Colo, &e.SpeedMbps, &e.LatencyMs,
			&e.Source, &e.AddedAt, &e.LastCheck, &e.LastOK, &e.FailCount, &e.Note, &e.Priority); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *SQLiteStore) MarkIPChecked(ip, region string, ok bool, speed, latency float64) error {
	_, err := s.db.Exec(`UPDATE iplib_ip SET last_check=?, last_ok=?,
		speed_mbps=?, latency_ms=?,
		fail_count = CASE WHEN ?=1 THEN 0 ELSE fail_count+1 END
		WHERE ip=? AND region=?`,
		NowISO(), ok, speed, latency, ok, ip, region)
	return err
}

func (s *SQLiteStore) RemoveFailingIPs(maxFails int) (int, error) {
	res, err := s.db.Exec(`DELETE FROM iplib_ip WHERE fail_count >= ?`, maxFails)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *SQLiteStore) UpsertMeta(m IPMeta) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO iplib_meta
		(ip,region,cidr24,tested_count,last_test,last_ok,avg_speed_mbps)
		VALUES(?,?,?,?,?,?,?)`,
		m.IP, m.Region, m.CIDR24, m.TestedCount, m.LastTest, m.LastOK, m.AvgSpeedMbps)
	return err
}

func (s *SQLiteStore) GetMeta(ip, region string) (*IPMeta, error) {
	row := s.db.QueryRow(`SELECT ip,region,COALESCE(cidr24,''),COALESCE(tested_count,0),
		COALESCE(last_test,''),COALESCE(last_ok,0),COALESCE(avg_speed_mbps,0)
		FROM iplib_meta WHERE ip=? AND region=?`, ip, region)
	var m IPMeta
	err := row.Scan(&m.IP, &m.Region, &m.CIDR24, &m.TestedCount, &m.LastTest, &m.LastOK, &m.AvgSpeedMbps)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

type ScanHistory struct {
	ID         int64
	StartedAt  string
	FinishedAt string
	Status     string
	Total      int
	Passed     int
	StatsJSON  string
}

func (s *SQLiteStore) AddScanHistory(h ScanHistory) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO scan_history(started_at,finished_at,status,total,passed,stats_json)
		VALUES(?,?,?,?,?,?)`, h.StartedAt, h.FinishedAt, h.Status, h.Total, h.Passed, h.StatsJSON)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLiteStore) ListScanHistory(limit int) ([]ScanHistory, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id,COALESCE(started_at,''),COALESCE(finished_at,''),
		COALESCE(status,''),COALESCE(total,0),COALESCE(passed,0),COALESCE(stats_json,'')
		FROM scan_history ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScanHistory
	for rows.Next() {
		var h ScanHistory
		if err := rows.Scan(&h.ID, &h.StartedAt, &h.FinishedAt,
			&h.Status, &h.Total, &h.Passed, &h.StatsJSON); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// DB 暴露内部 db 句柄（仅供 scanner 写 scan_history 状态时使用）
func (s *SQLiteStore) DB() *sql.DB { return s.db }

func (s *SQLiteStore) String() string {
	return fmt.Sprintf("SQLiteStore@%p", s)
}
