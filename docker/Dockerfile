FROM golang:1.22-alpine AS builder
WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o kernel-monitor-server ./cmd/server

FROM alpine:3.19

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser:appgroup

WORKDIR /home/appuser

COPY --from=builder /app/kernel-monitor-server /usr/local/bin/kernel-monitor-server
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

VOLUME ["/certs"]

ENTRYPOINT ["/usr/local/bin/kernel-monitor-server"]