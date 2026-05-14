# Headscale-rs Systemd Services

This directory contains systemd service files for deploying headscale-rs.

## Service Files

- `headscale-server.service` - Control plane server (single instance)
- `headscale-node.service` - Mesh node (single instance)
- `headscale@.service` - Template for multiple control plane instances

## Installation

### 1. Create user and directories

```bash
# Create headscale user
sudo useradd -r -s /bin/false headscale

# Create directories
sudo mkdir -p /etc/headscale /var/lib/headscale
sudo chown headscale:headscale /var/lib/headscale
```

### 2. Install binary

```bash
# Build release binary
cargo build --release --package headscale-cli

# Install
sudo cp target/release/headscale /usr/local/bin/
sudo chmod +x /usr/local/bin/headscale
```

### 3. Create configuration

```bash
# Generate example config
sudo headscale init-config --output /etc/headscale/config.toml

# Edit configuration
sudo vi /etc/headscale/config.toml
```

### 4. Install and enable service

For control plane server:
```bash
sudo cp deploy/systemd/headscale-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable headscale-server
sudo systemctl start headscale-server
```

For mesh node:
```bash
sudo cp deploy/systemd/headscale-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable headscale-node
sudo systemctl start headscale-node
```

## Multiple Instances

To run multiple control planes, use the template service:

```bash
# Copy template
sudo cp deploy/systemd/headscale@.service /etc/systemd/system/

# Create instance configs
sudo headscale init-config --output /etc/headscale/production.toml
sudo headscale init-config --output /etc/headscale/staging.toml

# Create instance state directories
sudo mkdir -p /var/lib/headscale/{production,staging}
sudo chown headscale:headscale /var/lib/headscale/*

# Enable instances
sudo systemctl daemon-reload
sudo systemctl enable headscale@production
sudo systemctl enable headscale@staging
sudo systemctl start headscale@production
sudo systemctl start headscale@staging
```

## Logs

```bash
# View server logs
journalctl -u headscale-server -f

# View node logs
journalctl -u headscale-node -f

# View instance logs
journalctl -u headscale@production -f
```

## Troubleshooting

### Permission denied on TUN device

The node service requires access to `/dev/net/tun`. Make sure:
1. The `tun` kernel module is loaded: `sudo modprobe tun`
2. The device exists: `ls -la /dev/net/tun`

### Database permission errors

Ensure the headscale user owns the database directory:
```bash
sudo chown -R headscale:headscale /var/lib/headscale
```

### Port already in use

Check what's using the port:
```bash
sudo ss -tulpn | grep 8080
```
