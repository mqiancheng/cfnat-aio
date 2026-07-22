# CFNAT-AIO

**All-In-One Cloudflare 优选 IP 工具** — cfnat-docker 同款优选/代理内核，外加多地区管理、IP 库与收藏、自动测速入库、优选域名（Cloudflare DNS）同步、WebUI 控制台。单容器单进程。

## 代理内核：与 cfnat-docker 逐行对齐

AIO 不改变 cfnat-docker 的任何优选与转发逻辑，只在其上做多地区与管理功能：

- **扫描**：TCP:80 握手测延迟 + 读 `CF-RAY` 取 colo → 按地区 colo 严格过滤 → 按延迟排序取前 `ipnum` 个（扫描期不按 delay 过滤）
- **粘性单 IP**：每地区一个 `currentIP`；每个连接对它并发拨 `num` 份、`delay` 作拨号超时、取延迟最低的一份转发
- **故障处理**：连接拨号失败只断开当前连接、不换 IP（抖动由客户端重试吸收）；只有健康检查（`127.0.0.1:port` 读检测）**连续 2 次失败**才切到列表下一个有效 IP
- **兜底池**：无收藏 IP 时，每地区一条常驻扫描 goroutine（启动即扫 + 每 10 分钟刷新）维护本区域热池；收藏全挂自动落兜底，恢复手动可控

## 功能

| 功能 | 说明 |
|---|---|
| 多地区代理 | 每地区独立端口、独立一套 cfnat 参数；WebUI 增删改，关键参数重启生效、其余热更新 |
| 收藏 IP | IP 库中 ⭐ 收藏，按排位号顺序使用（#1 最优先）；`use_pinned` 开关热切换，断了自上而下换下一个，全挂落兜底 |
| 自动测速入库 | 地区开关（默认关）：currentIP 新上任时对它测速一次，≥速度阈值自动入库（`source=auto`、不收藏、同一 IP 不复测） |
| 优选域名同步 | 收藏 IP 自动写入 Cloudflare DNS（同名多记录轮询，v4→A / v6→AAAA，灰云 ttl=60），收藏变化 30s 防抖对齐，空收藏删光 |
| 测速入库 | 批量粘贴 IP/域名，探测 colo 识别 CMIN2 + 测速，≥速度阈值才入库 |
| 后台扫描 | 独立全量扫描器（可选开启），扫描历史与进度可查 |
| WebUI | 纯静态无外部依赖，实时日志流，默认 `:1234` |
| 持久化 | SQLite 单文件（WAL），挂 `/data` 即可 |

## 部署

Docker（推荐，GitHub Actions 自动构建多架构镜像）：

```bash
docker run -d --name cfnat-aio \
  -p 1234:1234 -p 1001:1001 -p 1002:1002 \
  -v /your/data/dir:/data \
  ghcr.io/mqiancheng/cfnat-aio:latest
```

或仓库自带 compose：`docker compose up -d --build`

本地直接跑（无需 Docker）：

```bash
go build -o cfnat-aio.exe ./cmd/server
./cfnat-aio.exe -db ./cfnat-aio.db   # -port 1234 可改 WebUI 端口
```

访问：`http://<主机>:1234`

## 快速上手

1. **建地区**：代理地区 → 添加（如 HKG→:1001、LAX→:1002）。无需任何 IP，程序立即开始 cfnat 式兜底扫描，几十秒后端口可用——与跑一个 cfnat-docker 容器等效。
2. **攒 IP（可选）**：测速入库页批量导入探测；或给地区开"自动测速入库"让系统自己攒。
3. **用收藏（可选）**：IP 库中 ⭐ 收藏 → 打开该地区"使用收藏IP"开关，立即切换到收藏 #1。
4. **优选域名（可选）**：设置页填 CF API Token + 主域名 → IP库页给地区填优选域名（如 `hkg.tunel.ggff.net`）→ 收藏 IP 自动同步成 DNS 记录，客户端直接拿域名当服务器地址用。

客户端走代理：

```
SOCKS5 / HTTP  主机:1001   # 走 HKG
SOCKS5 / HTTP  主机:1002   # 走 LAX
```

## 地区参数（与 cfnat-docker 一一对应）

| 地区参数 | cfnat-docker | 含义 | 修改后 |
|---|---|---|---|
| colo | `-colo` | 数据中心过滤（HKG/LAX…） | 重启地区 |
| delay | `-delay` | 拨号/自检超时（非扫描过滤） | 重启地区 |
| ips | `-ips` | 4 / 6 | 重启地区 |
| port（目标端口） | `-port` | 转发目标端口 | 重启地区 |
| tls | `-tls` | 验证用 http/https | 重启地区 |
| num | `-num` | 同 IP 并发拨号份数 | 重启地区 |
| expect_code | `-code` | 验证期望状态码 | 重启地区 |
| domain | `-domain` | 验证探测域名 | 重启地区 |
| 端口（监听） | `-addr` | 本地监听端口 | 重启地区 |
| ipnum | `-ipnum` | 扫描后保留前 N 个 | **热更新** |
| task | `-task` | 扫描并发度 | **热更新** |
| random | `-random` | 每 /24 随机抽 1（默认）/ 穷举 | **热更新** |
| use_pinned | — | 使用收藏 IP 开关 | **热更新** |
| auto_speedtest | — | 自动测速入库开关 | **热更新** |
| prefer_domain / domain_sync | — | 优选域名与自动同步 | **热更新** |

## 优选域名同步配置

1. **创建 API Token**（Cloudflare → My Profile → API Tokens）：权限只需 `Zone:Read` + `DNS:Edit`，资源范围限定到你的 zone。
2. **设置页**：填 `CF API Token` 与 `CF 主域名`（你的 zone，如 `tunel.ggff.net`）。
3. **IP库页**：每个地区一行——优选域名（须挂在主域名下，如 `hkg.tunel.ggff.net`）+ 自动同步开关（默认开）+ 立即同步按钮 + 同步状态。

行为约定：

- 内容 = 该地区收藏 IP（按排位）；v4 写 A、v6 写 AAAA；`ttl=60`、`proxied=false`（灰云）。
- 触发：收藏增删/排序后约 30 秒自动对齐；开关打开/域名修改/进程启动时立即对齐；手动按钮无视开关。
- 空收藏 → 删光该域名全部 A/AAAA 记录。
- 同步失败只记状态与日志，绝不影响代理。

> 小贴士：客户端用优选域名比直填 IP 测速高约 25~35ms，那是 DNS 解析开销（ttl=60 加剧），实际使用与速度不受影响。

## 目录结构

```
cfnat-aio/
├── cmd/server/         # main 入口（路由注册、模块装配）
├── internal/
│   ├── config/         # 配置模型 + SQLite 存储
│   ├── iplibrary/      # IP 库（收藏/优先级）
│   ├── cfdns/          # Cloudflare DNS 同步（优选域名）
│   ├── scanner/        # 独立后台扫描器
│   ├── proxy/          # 代理内核（对齐 cfnat-docker）+ 常驻地区扫描
│   ├── logging/        # 统一日志
│   └── webui/          # WebUI 处理器 + 嵌入模板
├── Dockerfile
├── docker-compose.yml
└── .github/workflows/build.yml   # push main → 构建 ghcr.io 多架构镜像
```

## 数据流

```
CF 全网 / 手动导入
   │  常驻地区扫描（:80 CF-RAY 探 colo，延迟排序）      测速入库页（探测+测速）
   ▼                                                  ▼
兜底热池（每地区 top ipnum）                      IP 库（source=import/auto）
   │                                                  │ ⭐ 收藏（手动）
   │  无收藏 / 收藏全挂                                 ▼
   └──────────────►  代理监听（每地区一端口，粘性 currentIP）
                            │
                            ├─ currentIP 新上任 →（可选）自动测速入库 → IP 库
                            │
                            └─ 收藏变化 →（可选）优选域名同步 → Cloudflare DNS（A/AAAA 轮询）
                                                                       │
                                                                       ▼
                                                          客户端直接用优选域名
```

## License

MIT
