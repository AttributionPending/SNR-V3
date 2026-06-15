# SNR V3 — Signal to Noise

> **V3 is the enterprise-integration & scale evolution of SNR.** It builds on V2 with a
> Postgres data layer, asynchronous LLM analysis (job queue + background workers), a
> machine-authenticated integration API, threat-intel feed ingestion (TAXII/MISP/RSS),
> and detection-as-code publishing via Git pull requests. All V2 features and UX are
> preserved. Work lands phase by phase.

**AI-powered Cyber Threat Intelligence workbench.** Paste a SIEM alert, drop a log
file, or feed in free-text threat reporting, and SNR turns it into structured,
shareable intelligence: an ATT&CK technique chain **and** a MITRE Attack Flow,
extracted/validated IOCs, Sigma/YARA/Suricata detection rules, threat-actor
attribution, and audience-tailored briefs — exportable to STIX, ATT&CK Navigator,
Attack Flow Builder, email, and Markdown. It is **LLM-agnostic** (Anthropic Claude
or any OpenAI-compatible endpoint) and **self-hostable** on your own infrastructure.

> 📖 **New here? Read the [User Manual](./docs/README.md)** — analyst & administrator guides, reference, and troubleshooting.

---

## Features

**Analysis**
- Two-phase LLM pipeline — technical extraction, then an audience-scoped brief (streamed live)
- **ATT&CK chain** and **MITRE Attack Flow** (causal DAG) visualizations
- IOC extraction with validation/dedup; Sigma, YARA & Suricata detection rules
- Threat-actor attribution

**Review & edit**
- Per-session analyst overrides; rich-text editing of the brief
- Severity / TLP control; IOC defang toggle + false-positive marking
- **Re-analyze** an existing session (retry a failure, or regenerate for a different audience) with live progress

**Exports** — STIX 2.1 bundle, ATT&CK Navigator layer, **`.afb`** (Attack Flow Builder), email `.eml`, Markdown report, detection rules, IOC CSV, and a combined ZIP

**Organize & report** — session tags + filters, threat-actor grouping/merge with aggregated TTPs/IOCs, an analytics dashboard, an append-only audit trail, and global search (`Ctrl+K`)

**Customize** — email **layout** + **branding** editors, a CTI **report template** editor, configurable brief sections, and per-audience prompts (all in Settings)

**Enterprise** — JWT auth + RBAC (admin/analyst/viewer), team workspaces, client-side redaction, rate limiting, health/readiness probes, Prometheus `/metrics`, scheduled DB backups, and a one-command Docker/Compose deployment

---

## Requirements

- **Local dev:** Node.js **22.5+** (uses the built-in `node:sqlite` — no native build step)
- **Container deploy:** Docker 24+ with the Compose plugin
- **An LLM credential:** an Anthropic API key, or any OpenAI-compatible endpoint (Ollama, LM Studio, vLLM, Azure OpenAI)

---

## Setup

### A. Run locally (npm) — fastest for evaluation & development

```bash
git clone <repo-url> && cd snr
npm install
cp .env.example .env
#   set ANTHROPIC_API_KEY  (or an OpenAI-compatible provider)
#   set A2N_ADMIN_EMAIL / A2N_ADMIN_PASSWORD  (first-run admin)
npm run dev
```

- UI: **http://localhost:5173** · API: **http://localhost:3001**
- On first start an admin account is bootstrapped from `A2N_ADMIN_EMAIL` / `A2N_ADMIN_PASSWORD`.

### B. Deploy with Docker (on-prem / self-hosted)

```bash
cp .env.example .env
#   set JWT_SECRET, ALLOWED_ORIGINS, an LLM key, admin creds, and SNR_DOMAIN
docker compose up -d
```

- Serves the API + UI behind a Caddy TLS reverse proxy at **https://<SNR_DOMAIN>**
  (`localhost` issues a self-signed cert; a real domain auto-provisions Let's Encrypt).
- Data (SQLite DB + scheduled backups) persists in the `snr-data` volume.
- **Full guide — TLS, secrets, backups/restore, upgrades, hardening checklist — in [DEPLOYMENT.md](./DEPLOYMENT.md).**

> Same codebase either way: the container simply runs `npm run build` + `npm start`
> (the production server serves the built UI). There is no separate "Docker version."

---

## Using SNR

1. **Log in** with the bootstrap admin. Admins create users and team workspaces from the **Admin** panel.
2. **New Analysis** — paste SIEM/alert text, upload a log file (`.csv/.txt/.log/.json`), and/or add free-text intel. **Redact** any sensitive strings (stripped before the LLM call), pick an **audience** (SOC, Purple Team, Red Team, Detection & Response, General, or a custom one), and **Analyze**. Progress streams through Phase 1 (extraction) → Phase 2 (brief).
3. **Review** — toggle **ATT&CK Chain ⇄ Attack Flow** (and expand to full screen); inspect the IOC table (defang, export CSV, flag false positives), detection rules, threat-actor attribution, and analyst notes.
4. **Refine** — edit the brief in rich text, adjust severity/TLP, assign or change the threat actor, or **Re-analyze** to regenerate / switch audience.
5. **Export** — STIX, Navigator, `.afb`, `.eml`, Markdown report, detection rules, IOC CSV, or a full ZIP.
6. **Organize** — tag and filter sessions, group them under threat actors (merge duplicates; see aggregated TTPs/IOCs), open the **Analytics** and **Audit** views, and jump anywhere with global search (`Ctrl+K`).
7. **Configure (Settings)** — LLM provider, analyst identity, **Email Template** + **Branding**, **Brief Sections**, **CTI Report Template**, and per-audience prompts.

---

## Configuration

Common variables (full reference in [`.env.example`](./.env.example) and [DEPLOYMENT.md](./DEPLOYMENT.md)):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | yes* | — | Claude API key. *Or configure an OpenAI-compatible provider (`LLM_PROVIDER`, `API_BASE_URL`, `MODEL_NAME`). |
| `A2N_ADMIN_EMAIL` / `A2N_ADMIN_PASSWORD` | yes (first run) | — | Bootstrap admin (password complexity enforced). |
| `JWT_SECRET` | prod | dev: auto | JWT signing secret. **Required in production.** |
| `ALLOWED_ORIGINS` | prod | — | Comma-separated CORS origins. **Required in production.** |
| `PORT` / `HOST` | no | `3001` / dev `127.0.0.1`, prod `0.0.0.0` | Listen port / bind address. |
| `DB_PATH` | no | `./snr.db` | SQLite file (use a volume path in containers). |
| `BACKUP_INTERVAL_HOURS` / `BACKUP_RETENTION` | no | `24` / `7` | Scheduled snapshot cadence & retention (`0` disables). |
| `METRICS_TOKEN` | no | — | If set, `/metrics` requires `Authorization: Bearer <token>`. |
| `LLM_TIMEOUT` | no | `120` | Per-phase LLM timeout (seconds). |

Any secret also supports a `*_FILE` variant (e.g. `JWT_SECRET_FILE`) pointing at a
mounted file — the standard container-secrets convention; the file's contents win.

---

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Frontend + backend in dev mode |
| `npm run build` | Production frontend build (→ `dist/`) |
| `npm start` | Run the server (serves API + built UI when `NODE_ENV=production`) |
| `npm test` / `npm run test:watch` | Vitest suite |
| `npm run lint` / `lint:fix` | ESLint + type check / autofix |
| `npm run format` / `format:check` | Prettier |
| `npm run db:backup` / `db:restore` | Manual SQLite backup / restore |

---

## Architecture

```
├── server/                 # Express.js backend (TypeScript, ESM)
│   ├── index.ts            # entry: middleware, health/ready, /metrics, backups, graceful shutdown
│   ├── db/database.ts      # SQLite via node:sqlite (WAL), schema + migrations
│   ├── lib/
│   │   ├── claude.ts       # two-phase LLM orchestration, SSE streaming, schema
│   │   ├── providers/      # LLM provider abstraction (Anthropic / OpenAI-compatible) + retry
│   │   ├── stix.ts         # STIX 2.1 bundle + Attack Flow extension objects
│   │   ├── afb.ts          # Attack Flow Builder (.afb) exporter
│   │   ├── attack-flow.ts  # Attack Flow validation / DAG repair
│   │   ├── eml.ts          # email (.eml) builder + token-template engine
│   │   ├── report.ts       # Markdown report + token-template engine
│   │   ├── sections.ts     # configurable brief sections
│   │   ├── auth-utils.ts   # JWT, password hashing, token revocation
│   │   ├── secrets.ts      # *_FILE secret resolution
│   │   ├── backup.ts       # scheduled VACUUM INTO snapshots + retention
│   │   ├── metrics.ts      # Prometheus registry + counters
│   │   └── logger.ts       # pino structured logging
│   ├── middleware/         # auth + team scoping
│   └── routes/             # auth, users, teams, sessions, analyze, settings, analytics, threat-actors, search
├── src/                    # React + Vite frontend (TypeScript)
│   ├── components/         # AttackChainView, AttackFlowView, IOCTable, EmailTemplateEditor,
│   │                       #   ReportTemplateEditor, ThreatActorView, SettingsModal, ReportsModal, …
│   ├── contexts/           # auth context
│   └── lib/                # API client, defang, templates
├── Dockerfile, docker-compose.yml, deploy/Caddyfile, .dockerignore   # on-prem deploy
├── .github/workflows/      # CI (typecheck/build/docker) + release (GHCR image)
├── scripts/                # DB backup/restore utilities
└── tests/                  # Vitest
```

---

## Operations & security

- **Probes:** `GET /api/health` (liveness) and `GET /api/ready` (DB read/write). **Metrics:** Prometheus at `GET /metrics`.
- **Backups:** consistent `VACUUM INTO` snapshots on a schedule, with retention (see DEPLOYMENT.md for restore).
- **Logs:** structured JSON on stdout with secret redaction — ship to your SIEM.
- **Hardening:** Helmet (CSP/HSTS), account lockout, timing-safe auth, prompt-injection defense, client-side redaction, token revocation, rate limiting. The server binds to loopback in dev and `0.0.0.0` in production/containers (front it with TLS). Details in [SECURITY.md](./SECURITY.md).

---

## Documentation

- [User Manual](./docs/README.md) — analyst & administrator guides, reference, troubleshooting
- [DEPLOYMENT.md](./DEPLOYMENT.md) — on-prem install, TLS, backups, hardening
- [API.md](./API.md) — REST endpoint reference
- [SECURITY.md](./SECURITY.md) — security controls & posture
- [`.env.example`](./.env.example) — complete configuration reference

## License

Internal use only.
