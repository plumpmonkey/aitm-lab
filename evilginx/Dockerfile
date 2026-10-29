FROM golang:1.22-bookworm AS builder

# Build Evilginx3 from source (community edition)
RUN apt-get update && apt-get install -y git make && \
    git clone https://github.com/kgretzky/evilginx2.git /build/evilginx && \
    cd /build/evilginx && \
    sed -i 's/rsa\.GenerateKey(rand\.Reader, 1024)/rsa.GenerateKey(rand.Reader, 2048)/' core/certdb.go && \
    make

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/evilginx/build/evilginx /app/evilginx

WORKDIR /app

# Phishlets are mounted as a volume
RUN mkdir -p /app/phishlets

# Expose ports: HTTPS (443), HTTP (80), admin UI (3333)
EXPOSE 443 80 3333

# Run Evilginx in developer mode (self-signed certs)
# The -developer flag is critical for local lab use
# Students will attach to this container interactively
CMD ["./evilginx", "-developer", "-p", "/app/phishlets"]
