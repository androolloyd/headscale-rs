# Headscale-rs Docker Image
# Multi-stage build for minimal final image

# Build stage
# Keep this tag equal to the channel in rust-toolchain.toml
# (scripts/check_toolchain_pin.py enforces it).
FROM rust:1.99.0-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .
RUN cargo build --release --locked --package headscale-cli

# Runtime stage
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false headscale

# Create directories
RUN mkdir -p /etc/headscale /var/lib/headscale && \
    chown headscale:headscale /var/lib/headscale

# Copy binary from builder
COPY --from=builder /build/target/release/headscale /usr/local/bin/headscale
COPY vendor/http/LICENSE* /usr/share/licenses/headscale-rs/http/
COPY vendor/h2/LICENSE* /usr/share/licenses/headscale-rs/h2/
COPY vendor/hyper/LICENSE* /usr/share/licenses/headscale-rs/hyper/
COPY vendor/hyper-rustls/LICENSE* /usr/share/licenses/headscale-rs/hyper-rustls/
COPY vendor/hyper-util/LICENSE* /usr/share/licenses/headscale-rs/hyper-util/
COPY vendor/rustls/LICENSE* /usr/share/licenses/headscale-rs/rustls/
COPY vendor/aws-lc-rs/LICENSE* vendor/aws-lc-rs/NOTICE* /usr/share/licenses/headscale-rs/aws-lc-rs/
COPY vendor/instant-acme/LICENSE* /usr/share/licenses/headscale-rs/instant-acme/
COPY vendor/sqlx-postgres/LICENSE* /usr/share/licenses/headscale-rs/sqlx-postgres/
COPY vendor/sqlx-core/LICENSE* /usr/share/licenses/headscale-rs/sqlx-core/
COPY headscale-cli/LICENSE* headscale-cli/NOTICE* /usr/share/licenses/headscale-rs/headscale-cli/
COPY headscale-db/LICENSE* headscale-db/NOTICE* /usr/share/licenses/headscale-rs/headscale-db/
COPY headscale-api-acl/LICENSE* headscale-api-acl/NOTICE* /usr/share/licenses/headscale-rs/headscale-api-acl/
COPY headscale-api/LICENSE* headscale-api/NOTICE* /usr/share/licenses/headscale-rs/headscale-api/

# Default config location
ENV HEADSCALE_CONFIG=/etc/headscale/config.toml

# Server mode by default
EXPOSE 8080
VOLUME ["/etc/headscale", "/var/lib/headscale"]

# Use headscale user for server mode
USER headscale

ENTRYPOINT ["/usr/local/bin/headscale"]
CMD ["serve", "--config", "/etc/headscale/config.toml"]
