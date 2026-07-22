// Package logging 统一日志系统
//
// 设计目标：
//   - 内存环形 buffer（最近 N 条），WebUI 可通过 SSE 实时订阅
//   - 同时输出到 stdout（保留 docker logs 能力）
//   - 支持多级别（info/warn/error/debug）
//   - 支持按来源分类（proxy/scanner/fofa/system）
package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// Level 日志级别
type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
	LevelDebug Level = "debug"
)

// Entry 一条日志
type Entry struct {
	Time    time.Time `json:"time"`
	Level   Level     `json:"level"`
	Source  string    `json:"source"`  // proxy / scanner / system / webui
	Message string    `json:"message"`
}

// Subscriber 订阅者
type Subscriber struct {
	ID      int
	Ch      chan Entry
	History bool // 是否先推送历史
}

// Logger 全局日志器
type Logger struct {
	mu      sync.RWMutex
	entries []Entry
	cap     int
	subs    map[int]*Subscriber
	nextID  int

	stdout io.Writer
}

// NewLogger 创建 logger
func NewLogger(cap int) *Logger {
	if cap <= 0 {
		cap = 1000
	}
	return &Logger{
		entries: make([]Entry, 0, cap),
		cap:     cap,
		subs:    make(map[int]*Subscriber),
		stdout:  os.Stdout,
	}
}

// SetStdout 设置额外输出（测试用）
func (l *Logger) SetStdout(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stdout = w
}

// log 内部记录
func (l *Logger) log(level Level, source, format string, args ...interface{}) {
	now := time.Now()
	msg := fmt.Sprintf(format, args...)
	e := Entry{Time: now, Level: level, Source: source, Message: msg}

	l.mu.Lock()
	// 写入 buffer
	l.entries = append(l.entries, e)
	if len(l.entries) > l.cap {
		// 环形：丢弃最早的
		l.entries = l.entries[len(l.entries)-l.cap:]
	}
	// 推送给订阅者（非阻塞）
	for _, sub := range l.subs {
		select {
		case sub.Ch <- e:
		default:
			// 订阅者满了就丢，不阻塞主流程
		}
	}
	stdout := l.stdout
	l.mu.Unlock()

	// 写 stdout（用标准 log 格式，方便 docker logs 抓取）
	if stdout != nil {
		ts := now.Format("2006/01/02 15:04:05")
		fmt.Fprintf(stdout, "%s [%s] %s\n", ts, source, msg)
	}
}

// Info info 级别
func (l *Logger) Info(source, format string, args ...interface{}) {
	l.log(LevelInfo, source, format, args...)
}

// Warn warn 级别
func (l *Logger) Warn(source, format string, args ...interface{}) {
	l.log(LevelWarn, source, format, args...)
}

// Error error 级别
func (l *Logger) Error(source, format string, args ...interface{}) {
	l.log(LevelError, source, format, args...)
}

// Debug debug 级别
func (l *Logger) Debug(source, format string, args ...interface{}) {
	l.log(LevelDebug, source, format, args...)
}

// Snapshot 获取最近 N 条历史（拷贝）
func (l *Logger) Snapshot(n int) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n <= 0 || n > len(l.entries) {
		n = len(l.entries)
	}
	out := make([]Entry, n)
	copy(out, l.entries[len(l.entries)-n:])
	return out
}

// Subscribe 订阅
func (l *Logger) Subscribe(history bool) (*Subscriber, func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	id := l.nextID
	l.nextID++
	sub := &Subscriber{
		ID:      id,
		Ch:      make(chan Entry, 200),
		History: history,
	}
	if history {
		// 推历史：直接放进 channel
		for _, e := range l.entries {
			select {
			case sub.Ch <- e:
			default:
				break
			}
		}
	}
	l.subs[id] = sub
	return sub, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if s, ok := l.subs[id]; ok {
			close(s.Ch)
			delete(l.subs, id)
		}
	}
}

// 全局 logger（直接 log.Printf 走这里）
var std = NewLogger(1000)

// Default 获取全局 logger
func Default() *Logger { return std }

// InfoTo 默认 logger info
func InfoTo(source, format string, args ...interface{}) { std.Info(source, format, args...) }

// WarnTo 默认 logger warn
func WarnTo(source, format string, args ...interface{}) { std.Warn(source, format, args...) }

// ErrorTo 默认 logger error
func ErrorTo(source, format string, args ...interface{}) { std.Error(source, format, args...) }

// DebugTo 默认 logger debug
func DebugTo(source, format string, args ...interface{}) { std.Debug(source, format, args...) }

// InitGlobal 接管标准 log 包
// 所有 log.Printf 调用会同时进我们的 buffer 和 stdout
func InitGlobal() {
	log.SetFlags(0) // 关闭默认前缀，我们自己带时间
	log.SetOutput(&stdWriter{})
}

type stdWriter struct{}

func (stdWriter) Write(p []byte) (int, error) {
	msg := string(p)
	// 去掉末尾换行
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	std.Info("system", "%s", msg)
	// 同时写 stdout
	return os.Stdout.Write(p)
}
