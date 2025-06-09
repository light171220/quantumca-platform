.PHONY: build run setup clean test docker-build docker-run

BINARY_NAME=quantumca
API_BINARY=cmd/api/main.go
SETUP_BINARY=cmd/setup/main.go

build:
	CGO_ENABLED=1 go build -o bin/$(BINARY_NAME)-api $(API_BINARY)
	CGO_ENABLED=1 go build -o bin/$(BINARY_NAME)-setup $(SETUP_BINARY)

run:
	go run $(API_BINARY)

setup:
	go run $(SETUP_BINARY)

clean:
	go clean
	rm -rf bin/
	rm -rf data/

test:
	go test -v ./...

deps:
	go mod download
	go mod tidy

docker-build:
	docker build -t quantumca-platform .

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose down

dev: setup run

install:
	go install ./cmd/api
	go install ./cmd/setup

lint:
	golangci-lint run

format:
	go fmt ./...