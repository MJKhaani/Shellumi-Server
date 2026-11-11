# Shellumi Server — Deployment Guide

Shellumi Server is an open-source, MIT-licensed, self-hostable synchronization backend designed to run on any modern Linux host using Docker Compose, native binaries, or systemd services.

---

## 1. Prerequisites

- **Host Architecture:** Linux `x86_64` (amd64) or `aarch64` (arm64).
- **Runtime:** Docker Engine 24+ and Docker Compose v2, or native Rust binary + PostgreSQL 15+.
- **Domain & Networking:** A fully qualified domain name (FQDN) pointed to your host, with ports 80 and 443 open.
- **Resource Recommendations:**
  - Minimum: 1 vCPU, 512 MB RAM, 10 GB SSD.
  - Recommended: 2 vCPUs, 2 GB RAM, 50 GB SSD for team deployments with live collaboration.

---

## 2. Docker Compose Deployment (Recommended)

The `deploy/` directory provides production-ready Compose configurations with PostgreSQL and optional automatic TLS via Caddy.

### Step 1: Clone Repository & Setup Environment

```bash
git clone https://github.com/MJKhaani/Shellumi-Server.git
cd Shellumi-Server/deploy

# Copy example environment configuration
cp .env.example .env
```

Edit `.env` to configure your public domain and secure database credentials:

```bash
# Database credentials
POSTGRES_USER=shellumi
POSTGRES_PASSWORD=generate_a_strong_password_here_32chars
POSTGRES_DB=shellumi_server

# Canonical public URL and Caddy domain
SHELLUMI_SERVER_PUBLIC_URL=https://shellumi.example.com
SHELLUMI_SERVER_DOMAIN=shellumi.example.com

# Server configuration
SHELLUMI_SERVER_LOG_LEVEL=info
SHELLUMI_SERVER_LOG_FORMAT=json
SHELLUMI_SERVER_REGISTRATION=invite_only
SHELLUMI_SERVER_COLLAB_ENABLED=false
```

### Step 2: Launch Services

#### Option A: With Automated TLS (Caddy Reverse Proxy)
```bash
docker compose --profile tls up -d
```
Caddy automatically provisions and renews Let's Encrypt TLS certificates on ports 80/443 and proxies traffic to the backend on `server:8080` with unbuffered Server-Sent Events (SSE).

#### Option B: Behind an Existing Reverse Proxy (Nginx / Traefik / Cloudflare)
```bash
docker compose up -d
```
The server binds to `127.0.0.1:8080`. Configure your host reverse proxy to forward traffic with `X-Forwarded-For` and `X-Forwarded-Proto` headers.

### Step 3: Verification & Initial Bootstrap

Verify service health:

```bash
# Check liveness
curl https://shellumi.example.com/health/live

# Check system readiness and database connectivity
curl https://shellumi.example.com/health/ready

# Check capabilities
curl https://shellumi.example.com/api/v1/capabilities
```

Perform first-run administrator bootstrap:

```bash
curl -X POST https://shellumi.example.com/api/v1/bootstrap \
  -H "Content-Type: application/json" \
  -d '{
    "admin_username": "sysadmin",
    "admin_email": "admin@example.com",
    "admin_password": "YourStrongAdminPassword123!",
    "org_name": "Default Organization"
  }'
```

> [!NOTE]
> `POST /api/v1/bootstrap` can only be invoked once. Subsequent invocations will return HTTP 409 `BOOTSTRAP_ALREADY_CONSUMED`.

---

## 3. Native Linux Binary & Systemd Deployment

### Step 1: Install Binary & Config

Download the native release archive for your architecture (`x86_64` or `aarch64`) and extract:

```bash
tar -xzf shellumi-server-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
sudo mv shellumi-server /usr/local/bin/
sudo chmod +x /usr/local/bin/shellumi-server

# Create configuration directory
sudo mkdir -p /etc/shellumi-server
sudo cp config.example.env /etc/shellumi-server/shellumi.env
sudo chmod 600 /etc/shellumi-server/shellumi.env
```

### Step 2: Systemd Unit Configuration

Create `/etc/systemd/system/shellumi-server.service`:

```ini
[Unit]
Description=Shellumi Synchronization Backend
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=shellumi
Group=shellumi
EnvironmentFile=/etc/shellumi-server/shellumi.env
ExecStart=/usr/local/bin/shellumi-server serve
Restart=always
RestartSec=5s

# Security sandboxing
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now shellumi-server
sudo systemctl status shellumi-server
```

---

## 4. Updates & Maintenance

1. **Pull Latest Image / Binary:**
   ```bash
   cd deploy
   docker compose pull
   ```
2. **Apply Database Migrations:**
   Migrations run automatically on server startup. To inspect status manually:
   ```bash
   docker compose exec server shellumi-server migrate status
   ```
3. **Restart Service:**
   ```bash
   docker compose restart server
   ```
4. **Inspect Diagnostics:**
   ```bash
   docker compose exec server shellumi-server doctor
   ```
