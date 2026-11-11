# Shellumi Server — Deployment Guide

Shellumi Server is designed to be easily deployed on any modern Linux server using Docker Compose or native systemd services.

## Prerequisites
- Linux host (`x86_64` or `aarch64`)
- Docker Engine 24+ and Docker Compose v2 (or native PostgreSQL 15+)
- A domain name pointing to the host with valid TLS certificates (e.g. via Caddy, Nginx, or Traefik)

## Quick Deployment with Docker Compose

1. Clone or copy deployment files:
   ```bash
   git clone https://github.com/MJKhaani/Shellumi-Server.git
   cd Shellumi-Server/deploy
   ```

2. Copy and configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env to set a strong database password and your public domain
   ```

3. Launch services:
   ```bash
   docker compose up -d
   ```

4. Verify health:
   ```bash
   curl https://shellumi.example.com/health/live
   ```
