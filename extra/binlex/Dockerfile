FROM ghcr.io/c3rb3ru5d3d53c/binlex:latest

# Install Python 3, QEMU NBD client, and NTFS support
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 qemu-utils ntfs-3g && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the builder script, configs, and entrypoint
COPY build_whitelist.py /app/build_whitelist.py
COPY whitelist_config_docker.json /app/whitelist_config.json
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

# Run the entrypoint script
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
