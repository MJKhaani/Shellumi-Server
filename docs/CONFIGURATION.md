# Shellumi Server — Configuration Reference

Shellumi Server resolves configuration according to the following precedence hierarchy:

1. **Command-Line Arguments** (highest priority)
2. **Environment Variables** (`SHELLUMI_SERVER_*`)
3. **Configuration File** (`config.toml`)
4. **Secure Defaults** (lowest priority)

## Configuration Keys

| Key | CLI Flag | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `listen_addr` | `--listen-addr` | `SHELLUMI_SERVER_LISTEN_ADDR` | `127.0.0.1:8080` | Bind IP and port. Binding to non-loopback addresses without TLS or trusted proxies is rejected. |
| `public_url` | `--public-url` | `SHELLUMI_SERVER_PUBLIC_URL` | `http://127.0.0.1:8080` | Canonical public URL used for validation and link generation. Non-loopback requires `https://`. |
| `database_url` | `--database-url` | `SHELLUMI_SERVER_DATABASE_URL` | `None` | PostgreSQL connection string. |
| `log_level` | `--log-level` | `SHELLUMI_SERVER_LOG_LEVEL` | `info` | Logging verbosity (`trace`, `debug`, `info`, `warn`, `error`). |
| `log_format` | `--log-format` | `SHELLUMI_SERVER_LOG_FORMAT` | `json` | Structured format (`json` or `pretty`). |
| `registration` | `--registration` | `SHELLUMI_SERVER_REGISTRATION` | `invite_only` | Account registration mode (`invite_only` or `closed`). Public open registration is prohibited. |
| `access_token_ttl_secs` | `--access-token-ttl` | `SHELLUMI_SERVER_ACCESS_TOKEN_TTL` | `900` (15m) | Lifetime of signed bearer access tokens. |
| `refresh_token_ttl_secs` | `--refresh-token-ttl` | `SHELLUMI_SERVER_REFRESH_TOKEN_TTL` | `2592000` (30d) | Lifetime of rotating refresh tokens. |
| `max_request_bytes` | `--max-request-bytes` | `SHELLUMI_SERVER_MAX_REQUEST_BYTES` | `10485760` (10 MiB) | Maximum allowed HTTP request body size. |
| `max_record_bytes` | `--max-record-bytes` | `SHELLUMI_SERVER_MAX_RECORD_BYTES` | `1048576` (1 MiB) | Maximum allowed single encrypted record size. |
| `collab_enabled` | `--collab-enabled` | `SHELLUMI_SERVER_COLLAB_ENABLED` | `false` | Enables optional real-time terminal collaboration WSS relay. |
| `metrics_enabled` | `--metrics-enabled` | `SHELLUMI_SERVER_METRICS_ENABLED` | `false` | Enables internal metrics exposition. |
| `trusted_proxies` | `--trusted-proxies` | `SHELLUMI_SERVER_TRUSTED_PROXIES` | `[]` | List of IP addresses trusted for `X-Forwarded-*` headers. |
| `allowed_origins` | `--allowed-origins` | `SHELLUMI_SERVER_ALLOWED_ORIGINS` | `[]` | CORS allowed origins. |

## Example `config.toml`

```toml
listen_addr = "127.0.0.1:8080"
public_url = "http://127.0.0.1:8080"
database_url = "postgres://shellumi:secret@127.0.0.1:5432/shellumi_server"
log_level = "info"
log_format = "json"
registration = "invite_only"
access_token_ttl_secs = 900
refresh_token_ttl_secs = 2592000
max_request_bytes = 10485760
max_record_bytes = 1048576
collab_enabled = false
metrics_enabled = false
trusted_proxies = ["127.0.0.1"]
allowed_origins = []
```
