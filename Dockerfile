FROM rust:1.92 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# System dependencies needed to compile (openssl, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /build

WORKDIR /build

#snmpsim-rs/target/release/
RUN cargo build --release --manifest-path snmpsim-rs/Cargo.toml && cp snmpsim-rs/target/release/snmp-command-responder /build

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /sbin/nologin -u 1001 snmpsim

# Copy the compiled binary from the builder stage.
# Adjust the binary name if it differs from "snmpsim-rs".
COPY --from=builder /build/snmp-command-responder /snmp-command-responder

# Copy simulation data files.
COPY --chown=snmpsim:snmpsim data/ /data/

# SNMP runs over UDP 161 (standard).  We expose it here; the compose file
# maps it to the host port you choose.
EXPOSE 161/udp

USER snmpsim

WORKDIR /data

# Default command – override args in docker-compose if needed.
ENTRYPOINT ["/snmp-command-responder"]
CMD ["--data-dir=/data", "--agent-udpv4-endpoint=0.0.0.0:161"]
