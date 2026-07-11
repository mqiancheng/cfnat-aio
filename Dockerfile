# CFNAT-AIO 多阶段构建
# 第一阶段：编译 Go 二进制
FROM golang:1.22-alpine AS builder

# CGO 需要，SQLite 驱动编译时需要
RUN apk add --no-cache gcc musl-dev

WORKDIR /src

# 先复制依赖描述文件，单独下载依赖（命中缓存，下次构建秒过）
COPY go.mod go.sum* ./
RUN go env -w GOPROXY=https://proxy.golang.org,direct && \
    go mod download

# 再复制源码（依赖层缓存生效）
COPY . .

# 编译（再次确保 go.sum 完整，避免本地 go.sum 缺失时仍可工作）
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /out/cfnat-aio ./cmd/server

# 第二阶段：最小运行时镜像
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S cfnat && adduser -S cfnat -G cfnat

COPY --from=builder /out/cfnat-aio /usr/local/bin/cfnat-aio
RUN chmod +x /usr/local/bin/cfnat-aio

USER cfnat
WORKDIR /data

EXPOSE 1234

# 默认参数可通过 docker run -e 或 compose environment 覆盖
ENTRYPOINT ["/usr/local/bin/cfnat-aio"]
CMD ["-port", "1234"]
