# Headscale-rs Docker Deployment

Docker images and compose files for deploying headscale-rs.

## Quick Start

```bash
cd deploy/docker

# Build images
docker compose build

# Start server only
docker compose up -d headscale-server

# Or start both server and a test node
docker compose up -d
```

## Images

### headscale (Server)

Multi-stage build producing a minimal Debian-based image:
- Runs as non-root `headscale` user
- Exposes port 8080 for API
- Mounts config and data volumes

```bash
# Build
docker build -t headscale:latest -f Dockerfile ../..

# Run standalone
docker run -d \
  --name headscale \
  -p 8080:8080 \
  -v ./config/server.toml:/etc/headscale/config.toml:ro \
  -v headscale-data:/var/lib/headscale \
  headscale:latest
```

### headscale-node

Image with additional networking capabilities for mesh nodes:
- Runs as root for TUN/WireGuard access
- Needs NET_ADMIN and NET_RAW capabilities
- Needs /dev/net/tun device access
- Exposes UDP port 51820 for WireGuard

```bash
# Build
docker build -t headscale-node:latest -f Dockerfile.node ../..

# Run standalone (requires --cap-add and device access)
docker run -d \
  --name headscale-node \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -v ./config/node.toml:/etc/headscale/config.toml:ro \
  -v node-data:/var/lib/headscale \
  headscale-node:latest
```

## Configuration

Edit the files in `config/` directory:

- `server.toml` - Control plane server config
- `node.toml` - Mesh node config

## Docker Compose

The `docker-compose.yml` file provides:

1. **headscale-server** - Control plane with health checks
2. **headscale-node** - Example mesh node that connects to the server

### Commands

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Stop all
docker compose down

# Rebuild after code changes
docker compose build --no-cache
```

## Production Deployment

For production, consider:

1. **External database**: Mount a persistent volume or use external SQLite
2. **TLS termination**: Put a reverse proxy (nginx, traefik) in front
3. **Secrets management**: Use Docker secrets for sensitive config
4. **Monitoring**: Add Prometheus scraping for metrics endpoint

Example with Traefik:

```yaml
services:
  headscale-server:
    # ... existing config ...
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.headscale.rule=Host(`headscale.example.com`)"
      - "traefik.http.routers.headscale.tls.certresolver=letsencrypt"
```

## Kubernetes

For Kubernetes deployment, see the `../k8s/` directory (coming soon) or use Helm:

```bash
helm install headscale ./charts/headscale
```

## Troubleshooting

### TUN device not available

Ensure the TUN kernel module is loaded on the host:
```bash
sudo modprobe tun
```

### Permission denied

Node containers need elevated privileges:
```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
devices:
  - /dev/net/tun:/dev/net/tun
```

### Network connectivity issues

For full mesh connectivity, you may need host networking:
```yaml
network_mode: host
```
