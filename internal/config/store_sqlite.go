// Package config 提供基于 SQLite 的配置持久化实现
package config

import (
	"database/sql"
	"encoding/json"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
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
	return err
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
	_, err := s.db.Exec(`INSERT OR REPLACE INTO iplib_ip
		(ip,region,colo,speed_mbps,latency_ms,source,added_at,last_check,last_ok,fail_count,note)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		e.IP, e.Region, e.Colo, e.SpeedMbps, e.LatencyMs, e.Source,
		e.AddedAt, e.LastCheck, e.LastOK, e.FailCount, e.Note)
	return err
}

func (s *SQLiteStore) DeleteIP(ip, region string) error {
	_, err := s.db.Exec(`DELETE FROM iplib_ip WHERE ip=? AND region=?`, ip, region)
	return err
}

func (s *SQLiteStore) ListIPs(region string) ([]IPEntry, error) {
	rows, err := s.db.Query(`SELECT ip,region,colo,COALESCE(speed_mbps,0),COALESCE(latency_ms,0),
		COALESCE(source,''),COALESCE(added_at,''),COALESCE(last_check,''),
		COALESCE(last_ok,0),COALESCE(fail_count,0),COALESCE(note,'')
		FROM iplib_ip WHERE region=? ORDER BY speed_mbps DESC`, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPEntry
	for rows.Next() {
		var e IPEntry
		if err := rows.Scan(&e.IP, &e.Region, &e.Colo, &e.SpeedMbps, &e.LatencyMs,
			&e.Source, &e.AddedAt, &e.LastCheck, &e.LastOK, &e.FailCount, &e.Note); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *SQLiteStore) ListAllIPs() ([]IPEntry, error) {
	rows, err := s.db.Query(`SELECT ip,region,colo,COALESCE(speed_mbps,0),COALESCE(latency_ms,0),
		COALESCE(source,''),COALESCE(added_at,''),COALESCE(last_check,''),
		COALESCE(last_ok,0),COALESCE(fail_count,0),COALESCE(note,'')
		FROM iplib_ip ORDER BY region, speed_mbps DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPEntry
	for rows.Next() {
		var e IPEntry
		if err := rows.Scan(&e.IP, &e.Region, &e.Colo, &e.SpeedMbps, &e.LatencyMs,
			&e.Source, &e.AddedAt, &e.LastCheck, &e.LastOK, &e.FailCount, &e.Note); err != nil {
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
