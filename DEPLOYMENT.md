# SNR — On-Prem Deployment Guide

Self-hosted deployment of SNR (Signal-to-Noise) for an enterprise security program.
SNR is a single Node service that serves both the REST API and the built web UI,
backed by an embedded SQLite database. A reverse proxy in front terminates TLS.

## Architecture

```
            ┌────────────┐      ┌──────────────────────────┐
  HTTPS ───▶│   Caddy    │────▶ │  app (SNR)               │
            │ (TLS, :443)│ :3001│  API + UI, Node 22       │
            └────────────┘      │  SQLite @ /data/snr.db   │
                                │  backups @ /data/backups │
                                └──────────────────────────┘
                                         volume: snr-data
```

## Prerequisites
- Docker Engine 24+ and the Compose plugin.
- An LLM credential: an Anthropic API key, **or** an OpenAI-compatible endpoint
  (Ollama / vLLM / LM Studio / Azure OpenAI) reachable from the host.
- A DNS name pointing at the host if you want a public TLS certificate.

## Quick start
```bash
cp .env.example .env
# Edit .env — at minimum set:
#   JWT_SECRET           (node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
#   ALLOWED_ORIGINS      e.g. https://snr.yourorg.com
#   ANTHROPIC_API_KEY    (or LLM_PROVIDER=openai-compatible + API_BASE_URL)
#   A2N_ADMIN_EMAIL / A2N_ADMIN_PASSWORD   (first-run admin)
#   SNR_DOMAIN           your domain (or "localhost" for a self-signed cert)

docker compose up -d
docker compose logs -f app      # watch startup
```
Then browse to `https://<SNR_DOMAIN>` and log in with the bootstrap admin.

To run **without** the bundled proxy (front SNR with your own LB/proxy): delete the
`caddy` service from `docker-compose.yml`, publish `app`'s `3001`, and set
`TRUST_PROXY` to your proxy depth.

## Configuration reference

| Variable | Default | Notes |
|---|---|---|
| `NODE_ENV` | `development` | Set `production` in deployment (compose does this). |
| `PORT` | `3001` | App listen port. |
| `HOST` | dev `127.0.0.1` / prod `0.0.0.0` | Bind address. |
| `TRUST_PROXY` | dev off / prod `1` | Reverse-proxy hops to trust (real client IP, rate limiting). |
| `DB_PATH` | `./snr.db` | Use an absolute path on a persistent volume (compose: `/data/snr.db`). |
| `ALLOWED_ORIGINS` | — | **Required in prod.** Comma-separated CORS origins. |
| `JWT_SECRET` / `_FILE` | — | **Required in prod.** 64-byte hex recommended. |
| `ANTHROPIC_API_KEY` / `_FILE` | — | LLM key (or use an OpenAI-compatible provider). |
| `A2N_ADMIN_EMAIL` / `_FILE` | — | First-run admin (only used when no users exist). |
| `A2N_ADMIN_PASSWORD` / `_FILE` | — | First-run admin password (complexity enforced). |
| `BACKUP_INTERVAL_HOURS` | `24` | `0` disables scheduled backups. |
| `BACKUP_RETENTION` | `7` | Newest N snapshots kept. |
| `BACKUP_DIR` | `<DB dir>/backups` | Snapshot location. |
| `LOG_LEVEL` | `info` (prod) | pino level. Logs are JSON on stdout. |
| `METRICS_TOKEN` | — | If set, `/metrics` requires `Authorization: Bearer <token>`. |
| `SNR_DOMAIN` | `localhost` | Domain for the Caddy TLS proxy. |

Any secret supports a `*_FILE` variant pointing at a mounted file (Docker/K8s
secrets); the file's contents take precedence over the plain variable.

## TLS
- **Public domain:** set `SNR_DOMAIN` to your FQDN; Caddy auto-provisions a
  Let's Encrypt certificate (ports 80/443 must be reachable).
- **Internal CA / provided cert:** edit `deploy/Caddyfile` to
  `tls /path/cert.pem /path/key.pem`, and mount the cert into the caddy service.
- **Your own proxy:** terminate TLS there and proxy to `app:3001`; keep
  `TRUST_PROXY` aligned with the number of proxies.

## Observability
- **Logs:** structured JSON on stdout (secrets redacted). Ship with your existing
  collector (Fluent Bit / Vector / Splunk UF) and forward to your SIEM.
- **Metrics:** Prometheus text at `GET /metrics` (process metrics plus
  `snr_http_requests_total`, `snr_analysis_runs_total`, `snr_analysis_duration_seconds`).
  Protect it with `METRICS_TOKEN` and scrape over the internal network.
- **Health:** `GET /api/health` (liveness) and `GET /api/ready` (DB read/write).
  The container `HEALTHCHECK` uses `/api/health`.

## Backups & restore
- Scheduled snapshots use SQLite `VACUUM INTO` (consistent even with WAL active),
  written to `BACKUP_DIR` (default `/data/backups`) and pruned to `BACKUP_RETENTION`.
- **Manual snapshot:** `docker compose exec app npm run db:backup`.
- **Restore:**
  ```bash
  docker compose stop app
  # copy a snapshot from /data/backups over /data/snr.db (and remove -wal/-shm)
  docker run --rm -v snr_snr-data:/data busybox sh -c \
    "cp /data/backups/snr-<timestamp>.db /data/snr.db && rm -f /data/snr.db-wal /data/snr.db-shm"
  docker compose start app
  ```

## Upgrades
```bash
git pull            # or pull a new image tag
docker compose build app
docker compose up -d app
```
The DB volume persists; schema migrations apply automatically on startup. Take a
backup first (`npm run db:backup`).

## Hardening checklist
- [ ] `JWT_SECRET` set explicitly (64-byte hex); rotate periodically.
- [ ] `ALLOWED_ORIGINS` restricted to your real UI origin(s).
- [ ] Run behind TLS; never expose `app:3001` directly to clients.
- [ ] Secrets mounted as files (`*_FILE`), not inline in `.env`, where possible.
- [ ] `/metrics` protected with `METRICS_TOKEN` and not internet-exposed.
- [ ] stdout logs shipped to your SIEM; alert on repeated 401/lockout events.
- [ ] `snr-data` volume included in your infrastructure backup/DR plan.
- [ ] Bootstrap admin password rotated after first login; create per-analyst accounts.

## Scaling note
This deployment is **single-node** (embedded SQLite in WAL mode + consistent
snapshots), which is appropriate for typical on-prem CTI workloads. Horizontal
scaling / HA would require migrating to a networked database (e.g. Postgres) and
is tracked as a separate initiative.
