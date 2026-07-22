// CFNAT-AIO 服务入口
//
// 启动流程：
//   1. 打开 SQLite 数据库
//   2. 初始化 config / iplibrary / scanner / proxy / webui
//   3. 同步代理监听（读取 regions 配置启动监听器）
//   4. 启动 WebUI HTTP 服务（默认 :1234）
//   5. 启动扫描器后台循环（若配置启用）
//   6. 等待 SIGINT/SIGTERM 优雅退出
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"cfnat-aio/internal/config"
	"cfnat-aio/internal/iplibrary"
	"cfnat-aio/internal/logging"
	"cfnat-aio/internal/proxy"
	"cfnat-aio/internal/scanner"
	"cfnat-aio/internal/webui"

	_ "modernc.org/sqlite"
)

var (
	dbPath = flag.String("db", "/data/cfnat-aio.db", "SQLite 数据库文件路径")
	port   = flag.Int("port", 0, "WebUI 监听端口（0 = 使用数据库配置）")
)

func main() {
	flag.Parse()

	// 初始化统一日志系统
	logging.InitGlobal()

	// 确保数据目录存在
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}

	// 打开 SQLite
	db, err := sql.Open("sqlite", *dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		log.Fatalf("打开 SQLite 失败: %v", err)
	}
	defer db.Close()
	// 单连接串行化所有读写：写入来自多个 goroutine（导入探测/代理自检/扫描入库），
	// 连接池多连接并发写在 WAL 下仍可能瞬间 SQLITE_BUSY（busy_timeout 对读升级写无效），
	// 导致批量导入时丢 IP。本地工具写量极小，单连接彻底消除 database is locked。
	db.SetMaxOpenConns(1)

	// 初始化各模块
	store, err := config.NewSQLiteStore(db)
	if err != nil {
		log.Fatalf("初始化存储失败: %v", err)
	}

	cfgMgr, err := config.New(store)
	if err != nil {
		log.Fatalf("初始化配置失败: %v", err)
	}

	// 若命令行显式指定了端口（非 0），覆盖配置
	g := cfgMgr.General()
	if *port != 0 {
		g.WebUIPort = *port
		_ = cfgMgr.UpdateGeneral(g)
	}
	if g.DataDir == "" {
		g.DataDir = filepath.Dir(*dbPath)
		_ = cfgMgr.UpdateGeneral(g)
	}

	lib := iplibrary.New(store)
	sc := scanner.New(store, lib, cfgMgr)
	pm := proxy.New(store, lib, cfgMgr)

	// 同步代理监听
	if err := pm.Sync(); err != nil {
		log.Printf("同步代理失败: %v", err)
	}

	// 启动 WebUI
	handlers := webui.New(store, cfgMgr, lib, sc, pm)
	mux := http.NewServeMux()
	registerRoutes(mux, handlers)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", g.WebUIPort),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// 启动后台循环扫描
	if g.AutoStart && cfgMgr.Scanner().Enabled {
		sc.StartLoop()
	}

	// 优雅退出
	_, cancel := context.WithCancel(context.Background())
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("收到退出信号，正在关闭...")
		cancel()
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("=========================================")
	log.Printf("  CFNAT-AIO 启动成功")
	log.Printf("  WebUI:  http://:%d", g.WebUIPort)
	log.Printf("  数据库: %s", *dbPath)
	regions := cfgMgr.Regions()
	log.Printf("  地区:   %d 个已配置", len(regions))
	for _, r := range regions {
		log.Printf("         %s → :%d (%s, IP=%d)",
			r.Name, r.Port,
			map[bool]string{true: "启用", false: "禁用"}[r.Enabled],
			lib.CountIPs(r.Name))
	}
	log.Printf("=========================================")

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP 服务错误: %v", err)
	}
	log.Println("已退出")
}

func registerRoutes(mux *http.ServeMux, h *webui.Handlers) {
	// 页面
	mux.HandleFunc("/", h.HandleIndex)

	// 健康
	mux.HandleFunc("/api/health", h.HandleHealth)

	// 地区
	mux.HandleFunc("/api/regions", h.HandleAPIRegions)
	mux.HandleFunc("/api/regions/", h.RouteRegionsSubpath)

	// IP 库
	mux.HandleFunc("/api/ips", h.HandleAPIIPs)
	mux.HandleFunc("/api/ips/add", h.HandleAPIIPAdd)
	mux.HandleFunc("/api/ips/remove", h.HandleAPIIPRemove)
	mux.HandleFunc("/api/ips/priority", h.HandleAPIIPPriority)
	mux.HandleFunc("/api/ips/import-probe", h.HandleAPIIPImportProbe)
	mux.HandleFunc("/api/probe/stream", h.HandleAPIIPImportProbe)

	// 扫描器
	mux.HandleFunc("/api/scanner", h.HandleAPIScanner)
	mux.HandleFunc("/api/scanner/run", h.HandleAPIScannerRun)
	mux.HandleFunc("/api/scanner/stop", h.HandleAPIScannerStop)
	mux.HandleFunc("/api/scanner/history", h.HandleAPIScannerHistory)
	mux.HandleFunc("/api/scanner/progress", h.HandleAPIScannerProgress)

	// cfnat 代理配置
	mux.HandleFunc("/api/cfnat", h.HandleAPICfnatConfig)

	// 通用
	mux.HandleFunc("/api/settings", h.HandleAPISettings)

	// 日志
	mux.HandleFunc("/api/logs", h.HandleAPILogs)
	mux.HandleFunc("/api/logs/stream", h.HandleAPILogsStream)

	// 代理
	mux.HandleFunc("/api/proxy/status", h.HandleAPIProxyStatus)
	mux.HandleFunc("/api/proxy/sync", h.HandleAPIProxySync)
}
