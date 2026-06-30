# Stage 1: Build binlex from source using Cargo
FROM rust:1.85-slim-bullseye AS builder
RUN apt-get update && \
    apt-get install -y --no-install-recommends git pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/c3rb3ru5d3d53c/binlex.git /src
WORKDIR /src
RUN cargo install --path .

# Stage 2: Create python container for scanning and mounting
FROM python:3.10-slim-bullseye
RUN apt-get update && \
    apt-get install -y --no-install-recommends qemu-utils ntfs-3g && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled binlex binary from builder stage
COPY --from=builder /usr/local/cargo/bin/binlex /usr/local/bin/binlex

WORKDIR /app

# Copy the builder script, configs, and entrypoint
COPY build_whitelist.py /app/build_whitelist.py
COPY whitelist_config_docker.json /app/whitelist_config.json
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

# Run the entrypoint script
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
