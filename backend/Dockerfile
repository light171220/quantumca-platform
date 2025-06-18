FROM golang:1.22 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y gcc sqlite3 libsqlite3-dev git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o main cmd/api/main.go
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o setup cmd/setup/main.go

FROM debian:stable-slim

RUN apt-get update && apt-get install -y ca-certificates sqlite3 tzdata && \
    groupadd -g 1001 quantumca && \
    useradd -u 1001 -g quantumca quantumca

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/setup .
COPY --from=builder /app/configs ./configs

RUN mkdir -p data/keys data/certificates backups logs && \
    chown -R quantumca:quantumca /app

USER quantumca

EXPOSE 8080 8081 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["./main"]