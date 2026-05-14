# Headscale-rs Docker Image
# Multi-stage build for minimal final image

# Build stage
FROM rust:1.82-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./
COPY headscale-core/Cargo.toml headscale-core/
COPY headscale-identity/Cargo.toml headscale-identity/
COPY headscale-resources/Cargo.toml headscale-resources/
COPY headscale-payments/Cargo.toml headscale-payments/
COPY headscale-api/Cargo.toml headscale-api/
COPY headscale-db/Cargo.toml headscale-db/
COPY headscale-cli/Cargo.toml headscale-cli/

# Create dummy source files for caching dependencies
RUN mkdir -p headscale-core/src headscale-identity/src headscale-resources/src \
    headscale-payments/src headscale-api/src headscale-db/src headscale-cli/src && \
    echo "fn main() {}" > headscale-cli/src/main.rs && \
    for crate in headscale-core headscale-identity headscale-resources headscale-payments headscale-api headscale-db; do \
        echo "pub fn dummy() {}" > $crate/src/lib.rs; \
    done

# Build dependencies only (this layer gets cached)
RUN cargo build --release --package headscale-cli || true

# Copy actual source code
COPY headscale-core headscale-core
COPY headscale-identity headscale-identity
COPY headscale-resources headscale-resources
COPY headscale-payments headscale-payments
COPY headscale-api headscale-api
COPY headscale-db headscale-db
COPY headscale-cli headscale-cli

# Touch source files to ensure rebuild
RUN find . -name "*.rs" -exec touch {} \;

# Build release binary
RUN cargo build --release --package headscale-cli

# Runtime stage
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false headscale

# Create directories
RUN mkdir -p /etc/headscale /var/lib/headscale && \
    chown headscale:headscale /var/lib/headscale

# Copy binary from builder
COPY --from=builder /build/target/release/headscale /usr/local/bin/headscale

# Default config location
ENV HEADSCALE_CONFIG=/etc/headscale/config.toml

# Server mode by default
EXPOSE 8080
VOLUME ["/etc/headscale", "/var/lib/headscale"]

# Use headscale user for server mode
USER headscale

ENTRYPOINT ["/usr/local/bin/headscale"]
CMD ["server", "--config", "/etc/headscale/config.toml"]
