FROM golang:1.22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev sqlite-dev git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o main cmd/api/main.go
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o setup cmd/setup/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates sqlite tzdata
RUN addgroup -g 1001 -S quantumca && adduser -u 1001 -S quantumca -G quantumca

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/setup .
COPY --from=builder /app/web ./web
COPY --from=builder /app/configs ./configs

RUN mkdir -p data/keys data/certificates backups logs
RUN chown -R quantumca:quantumca /app

USER quantumca

EXPOSE 8080 8081 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["./main"]