[← Reference](./05-reference.md) · [Manual index](./README.md)

# 6. Troubleshooting & FAQ

## Analysis

**An analysis failed or got stuck.**
A failed/interrupted analysis is marked **Failed** (red badge in the sidebar). Open the
session and click **Retry Analysis**, or use **Re-analyze** — both reuse the stored
inputs, so you don't re-enter anything. Watch the in-place progress banner.

**"The model returned an incomplete analysis — missing incident_summary."**
The configured model couldn't produce SNR's required JSON schema. Use a larger/more
capable model, or switch to the Anthropic API (Settings → LLM Provider). Small local
models sometimes can't hold the structured-output format.

**The Flow toggle / Attack Flow isn't showing.**
Attack Flow only appears when the input supports a causal graph (multi-step incident with
clear ordering). Sparse inputs show a "Re-analyze to generate attack flow" hint —
re-analyze a richer write-up to produce one.

**Analysis is slow or times out.**
Long inputs or local models can exceed the per-phase timeout. Increase `LLM_TIMEOUT`
(seconds) in the environment, or reduce input size.

**I changed Brief Sections / prompts but old results look the same.**
Stored results use the schema and prompts active when they were generated. Run a new
analysis or **Re-analyze** the session to apply changes.

## Access & accounts

**Locked out after failed logins.**
Accounts lock temporarily after repeated failures (brute-force protection). Wait for the
window to elapse, or have an admin reset the password (Admin Panel → Users).

**Can't see Settings / Admin Panel / another team's data.**
These are role- and team-scoped. User management and team creation are admin-only; data
is isolated per team. See [Roles & permissions](./04-administrator-guide.md#41-roles--permissions).

**"LLM not configured."**
No working LLM credential. Set `ANTHROPIC_API_KEY` (or `_FILE`), or configure an
OpenAI-compatible provider in Settings → LLM Provider. Check `GET /api/health` → `llm`.

## Deployment & data

**Browser warns the certificate isn't trusted.**
Expected when `SNR_DOMAIN=localhost` (Caddy issues a self-signed cert). Proceed past the
warning for local use, or use a real domain (auto Let's Encrypt) or your internal CA —
see [DEPLOYMENT.md](../DEPLOYMENT.md).

**Where is my data, and how do I back it up / restore it?**
All data is in the SQLite database at `DB_PATH` (a mounted volume in containers).
Scheduled consistent snapshots run automatically; manual backup/restore and the restore
procedure are in [DEPLOYMENT.md](../DEPLOYMENT.md). Deleted sessions are recoverable for
7 days (Undo toast) before purge.

**After `docker compose restart app`, the site 404s briefly.**
The reverse proxy re-resolves the app shortly (within a few seconds). If you customized
the proxy, prefer `docker compose restart` (whole stack) or `docker compose up -d`.

**Monitoring.**
Liveness: `GET /api/health`. Readiness: `GET /api/ready`. Metrics: `GET /metrics`
(Prometheus; protect with `METRICS_TOKEN`). Logs are JSON on stdout — ship to your SIEM.

## Still stuck?

- In-app help: press **`?`** or click **Help**.
- Deployment/ops: [DEPLOYMENT.md](../DEPLOYMENT.md) · API: [API.md](../API.md) · Security: [SECURITY.md](../SECURITY.md)
- Contact your SNR administrator or the team that provided your deployment.
