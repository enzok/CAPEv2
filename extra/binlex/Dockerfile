# Stage 1: Build Environment
FROM ubuntu:24.04 AS builder

# Set non-interactive
ENV DEBIAN_FRONTEND=noninteractive

# Robust Dependency Installation
RUN set -eux; \
    for attempt in 1 2 3; do \
        rm -rf /var/lib/apt/lists/*; \
        apt-get -o Acquire::Retries=5 update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates cmake git curl gnupg libprotobuf-dev libssl-dev lsb-release \
        pkg-config protobuf-compiler software-properties-common && break; \
        if [ "$attempt" -eq 3 ]; then exit 1; fi; \
        sleep 15; \
    done \
    && install -d /usr/share/keyrings \
    && curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors https://apt.llvm.org/llvm-snapshot.gpg.key \
       | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg \
    && . /etc/os-release \
    && echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] https://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-22 main" \
       > /etc/apt/sources.list.d/llvm.list \
    && for attempt in 1 2 3; do rm -rf /var/lib/apt/lists/*; apt-get -o Acquire::Retries=5 update && apt-get install -y --no-install-recommends llvm-22-dev clang-22 libclang-common-22-dev libpolly-22-dev && break; if [ "$attempt" -eq 3 ]; then exit 1; fi; sleep 15; done \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (using stable to ensure valid toolchain)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Configure LLVM and Protobuf paths
ENV LLVM_SYS_221_PREFIX=/usr/lib/llvm-22
ENV PROTOC_INCLUDE=/usr/include

# Clone and Build
WORKDIR /src
RUN git clone https://github.com/enzok/binlex.git .
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo build --release --workspace

# Stage 2: Create container for scanning and mounting
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 qemu-utils ntfs-3g libssl3 && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled binlex binary from builder stage
COPY --from=builder /src/target/release/binlex /usr/local/bin/binlex

WORKDIR /app

# Copy the builder script, configs, and entrypoint
COPY build_whitelist.py /app/build_whitelist.py
COPY whitelist_config_docker.json /app/whitelist_config.json
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

# Run the entrypoint script
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
