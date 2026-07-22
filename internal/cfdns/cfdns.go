// Package cfdns Cloudflare DNS 记录同步（优选域名维护）
//
// 参考 AutoCloudflareSpeedTest 的 CF API 流程：
//   1. GET  /zones?name=主域名                     → zone_id（带缓存）
//   2. GET  /zones/{zid}/dns_records?name=FQDN     → 现有记录
//   3. 全量对齐：多余的 DELETE、缺失的 POST 创建（ttl=60, proxied=false 灰云）
//
// 认证：API Token（Authorization: Bearer），无需邮箱+全局 key。
package cfdns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"

var httpClient = &http.Client{Timeout: 15 * time.Second}

type cfResp struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (r *cfResp) apiErr() error {
	if r.Success {
		return nil
	}
	if len(r.Errors) > 0 {
		return fmt.Errorf("CF API: %s", r.Errors[0].Message)
	}
	return fmt.Errorf("CF API 返回失败")
}

func do(token, method, url string, body interface{}) (*cfResp, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, apiBase+url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cr cfResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("CF API 响应解析失败: %v", err)
	}
	if err := cr.apiErr(); err != nil {
		return nil, err
	}
	return &cr, nil
}

type zoneResult struct {
	ID string `json:"id"`
}

type dnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

var (
	zoneMu  sync.Mutex
	zoneIDs = map[string]string{}
)

// ZoneID 按主域名查 zone_id（带缓存）
func ZoneID(token, zone string) (string, error) {
	zoneMu.Lock()
	if id, ok := zoneIDs[zone]; ok {
		zoneMu.Unlock()
		return id, nil
	}
	zoneMu.Unlock()
	cr, err := do(token, "GET", "/zones?name="+zone, nil)
	if err != nil {
		return "", err
	}
	var zones []zoneResult
	if err := json.Unmarshal(cr.Result, &zones); err != nil || len(zones) == 0 {
		return "", fmt.Errorf("未找到主域名 %s（确认其已托管到该 CF 账户）", zone)
	}
	zoneMu.Lock()
	zoneIDs[zone] = zones[0].ID
	zoneMu.Unlock()
	return zones[0].ID, nil
}

func listRecords(token, zid, fqdn string) ([]dnsRecord, error) {
	cr, err := do(token, "GET", fmt.Sprintf("/zones/%s/dns_records?name=%s&per_page=100", zid, fqdn), nil)
	if err != nil {
		return nil, err
	}
	var recs []dnsRecord
	if err := json.Unmarshal(cr.Result, &recs); err != nil {
		return nil, fmt.Errorf("解析 DNS 记录失败: %v", err)
	}
	return recs, nil
}

// SyncRecords 把 fqdn 的 A/AAAA 记录全量对齐为 ips（v4→A，v6→AAAA）。
// 已存在且一致的保留；多余的删除；缺失的创建（ttl=60, proxied=false 灰云）。
// ips 为空时删除该域名下全部 A/AAAA 记录。返回 新建数、删除数。
func SyncRecords(token, zone, fqdn string, ips []string) (created, deleted int, err error) {
	zid, err := ZoneID(token, zone)
	if err != nil {
		return 0, 0, err
	}
	existing, err := listRecords(token, zid, fqdn)
	if err != nil {
		return 0, 0, err
	}
	// 目标集合：type|content（同时校验是合法 IP，避免把垃圾写进 DNS）
	want := map[string]bool{}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		rt := "A"
		if strings.Contains(ip, ":") {
			rt = "AAAA"
		}
		want[rt+"|"+ip] = true
	}
	// 删除多余
	for _, rec := range existing {
		if rec.Type != "A" && rec.Type != "AAAA" {
			continue // 不动非 A/AAAA 记录
		}
		if want[rec.Type+"|"+rec.Content] {
			delete(want, rec.Type+"|"+rec.Content) // 已存在且一致 → 保留
			continue
		}
		if _, err := do(token, "DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zid, rec.ID), nil); err != nil {
			return created, deleted, fmt.Errorf("删除记录 %s %s 失败: %v", rec.Type, rec.Content, err)
		}
		deleted++
	}
	// 创建缺失
	for k := range want {
		parts := strings.SplitN(k, "|", 2)
		body := map[string]interface{}{
			"type": parts[0], "name": fqdn, "content": parts[1], "ttl": 60, "proxied": false,
		}
		if _, err := do(token, "POST", fmt.Sprintf("/zones/%s/dns_records", zid), body); err != nil {
			// 已被并发/外部创建：视为已满足（幂等），不算失败
			if strings.Contains(err.Error(), "identical record") {
				continue
			}
			return created, deleted, fmt.Errorf("创建记录 %s %s 失败: %v", parts[0], parts[1], err)
		}
		created++
	}
	return created, deleted, nil
}
