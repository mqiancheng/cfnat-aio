# CFNAT-AIO 多阶段构建
# 第一阶段：编译 Go 二进制
FROM golang:1.22-alpine AS builder

# 纯 Go SQLite 驱动，无需 CGO

WORKDIR /src

# 先复制依赖描述文件，单独下载依赖（命中缓存，下次构建秒过）
COPY go.mod go.sum* ./
RUN go env -w GOPROXY=https://proxy.golang.org,direct && \
    go mod download

# 再复制源码（依赖层缓存生效）
COPY . .

# 编译（再次确保 go.sum 完整，避免本地 go.sum 缺失时仍可工作）
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/cfnat-aio ./cmd/server

# 第二阶段：最小运行时镜像
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -g 1000 cfnat && adduser -u 1000 -G cfnat -D cfnat

COPY --from=builder /out/cfnat-aio /usr/local/bin/cfnat-aio
RUN chmod +x /usr/local/bin/cfnat-aio

USER cfnat
WORKDIR /data

EXPOSE 1234

# 端口不在镜像层硬编码：-port 缺省为 0 = 使用数据库配置（WebUI 设置项）。
# 若在此显式传 -port，main.go 会每次启动覆盖并回写数据库配置，
# 导致 WebUI 里的端口修改在重建容器后永远被冲回（2026-07-24 用户实测踩坑）。
ENTRYPOINT ["/usr/local/bin/cfnat-aio"]
CMD []
