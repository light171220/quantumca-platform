FROM golang:1.22 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    git \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_BUILD_ONLY_LIB=ON && \
    cmake --build /tmp/liboqs/build --parallel $(nproc) && \
    cmake --build /tmp/liboqs/build --target install && \
    ldconfig && \
    rm -rf /tmp/liboqs

RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs-go.git /tmp/liboqs-go && \
    cp /tmp/liboqs-go/.config/liboqs-go.pc /usr/local/lib/pkgconfig/ && \
    rm -rf /tmp/liboqs-go

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ENV CGO_ENABLED=1
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV LD_LIBRARY_PATH=/usr/local/lib

RUN go build -a -installsuffix cgo -o bin/quantumca-api cmd/api/main.go
RUN go build -a -installsuffix cgo -o bin/quantumca-setup cmd/setup/main.go

FROM debian:stable-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    sqlite3 \
    wget \
    curl \
    tzdata \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/include/oqs /usr/local/include/oqs

RUN ldconfig

RUN mkdir -p /app/data /app/logs /app/backups /app/keys

COPY --from=builder /app/bin/quantumca-api .
COPY --from=builder /app/bin/quantumca-setup .
COPY --from=builder /app/scripts/docker-entrypoint.sh .

RUN chmod +x docker-entrypoint.sh
RUN chmod 700 /app/keys
RUN chmod 755 /app/data /app/logs /app/backups

RUN groupadd -g 1001 quantumca && \
    useradd -r -u 1001 -g quantumca quantumca

RUN chown -R quantumca:quantumca /app

USER quantumca

EXPOSE 8080 8081 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]