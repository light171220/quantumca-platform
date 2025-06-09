FROM golang:1.21-alpine AS builder

WORKDIR /app

RUN apk add --no-cache gcc musl-dev sqlite-dev

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o main cmd/api/main.go
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o setup cmd/setup/main.go

FROM alpine:latest

RUN apk --no-cache add ca-certificates sqlite
WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/setup .
COPY --from=builder /app/web ./web
COPY --from=builder /app/configs ./configs

RUN mkdir -p data/keys data/certificates

EXPOSE 8080 8081

CMD ["./main"]