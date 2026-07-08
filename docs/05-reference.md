[← Administrator Guide](./04-administrator-guide.md) · [Manual index](./README.md) · Next: [Troubleshooting →](./06-troubleshooting.md)

# 5. Reference

## Glossary

| Term | Meaning |
|---|---|
| **Session** | One analysis and its inputs, results, notes, tags, and exports. |
| **Audience** | Stakeholder profile that frames the Phase 2 brief. |
| **TLP** | Traffic Light Protocol marking on exports (CLEAR/GREEN/AMBER/AMBER+STRICT/RED). |
| **ATT&CK chain** | Identified techniques by tactic in kill-chain order. |
| **Attack Flow** | Causal graph of the attack (actions, assets, tools, malware, operators). |
| **IOC** | Indicator of compromise, confidence-scored. |
| **Detection rule** | Sigma / YARA / Suricata rule (extracted or generated). |
| **Threat actor** | Canonical adversary record sessions can be grouped under. |
| **Brief section** | A configurable block of the Phase 2 output. |
| **Override** | An analyst edit (severity, brief text) stored on top of AI output. |
| **Team / workspace** | An isolated tenant with its own data and settings. |

## Keyboard shortcuts

| Key | Action |
|---|---|
| `N` | New session |
| `Ctrl` / `⌘` + `K` | Global intelligence search |
| `?` | Toggle keyboard-shortcut help |
| `S` | Toggle the sidebar |
| `1`–`9` | Select session 1–9 |
| `Esc` | Close modals / clear selection |

## Audience profiles

| Audience | Framing focus |
|---|---|
| SOC | Containment & triage; watchlist IOCs. |
| Purple Team | TTP chain, detection gaps, hunting. |
| Red Team | Adversary behavior, tooling, C2. |
| Detection & Response | Detection gaps, log sources, rule logic. |
| General | Plain-language narrative, business impact. |
| *Custom* | Defined by admins in Settings → Audience Analysis Prompts. |

## Export formats

| Format | Extension | Consumer |
|---|---|---|
| STIX 2.1 bundle | `.json` | TIP / TAXII (OpenCTI, MISP, ThreatConnect); includes Attack Flow extension objects when present |
| ATT&CK Navigator layer | `.json` | MITRE ATT&CK Navigator |
| Attack Flow | `.afb` | MITRE Attack Flow Builder |
| Email brief | `.eml` | Any mail client (HTML + text; optional attachments) |
| CTI Report | `.md` | Written report (configurable template) |
| Detection rules | `.txt` | Detection engineering |
| IOCs | `.csv` | Watchlists / bulk import |
| Export package | `.zip` | Brief + STIX + Navigator + analysis JSON (+ optional IOCs/diagram) |
| Brief PDF | `.pdf` | Print-ready brief |

> False-positive-flagged IOCs are excluded from all exports.

## Brief section types

| Type | Behavior |
|---|---|
| `text` | Free-form paragraph(s). |
| `bullets` | Bullet list. |
| `numbered` | Numbered list (good for actions/steps). |
| `techniques` | Auto, read-only — from Phase 1 ATT&CK mapping. |
| `iocs` | Auto, read-only — from Phase 1 IOC extraction. |

## Template tokens

**Email Template** (body layout) and **CTI Report Template** share a token style:
`{field}` = single value; `{{BLOCK}}` = generated block.

- **Common field tokens:** `{date}` `{tlp}` `{severity}` `{audience}` `{org_name}` `{analyst_name}` `{confidence}` `{incident_title}` `{threat_actor_name}` `{ioc_count}` `{technique_count}`
- **Email blocks:** `{{SECTIONS}}` `{{SECTION:key}}` `{{TECHNIQUES_TABLE}}` `{{IOCS_TABLE}}` `{{PREAMBLE}}` `{{AUDIENCE_INTRO}}` `{{SIGNATURE}}`
- **Report blocks:** `{{SECTIONS}}` `{{SECTION:key}}` `{{ATTACK_TABLE}}` `{{ATTACK_CHAIN}}` `{{IOC_TABLE}}` `{{EMAIL_IOCS}}` `{{AFFECTED_ASSETS_TABLE}}` `{{THREAT_ACTOR}}` `{{CAMPAIGN_TIMELINE}}`

An empty template means "use the built-in default."

## Common configuration (env)

The full, authoritative list is in [`.env.example`](../.env.example); deployment-specific
guidance is in [DEPLOYMENT.md](../DEPLOYMENT.md). The most-used:

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` (or `_FILE`) | LLM credential (or configure an OpenAI-compatible provider). |
| `CLAUDE_MODEL` | Default Anthropic model when none is picked in Settings → LLM Provider (which overrides it per-team). |
| `A2N_ADMIN_EMAIL` / `A2N_ADMIN_PASSWORD` | First-run admin bootstrap. |
| `JWT_SECRET` (or `_FILE`) | Auth signing secret — required in production. |
| `ALLOWED_ORIGINS` | CORS origins — required in production. |
| `PORT` / `HOST` | Listen port / bind address. |
| `DATABASE_URL` | Postgres connection string (compose builds it from `POSTGRES_*`). |
| `LLM_TIMEOUT` | LLM call timeout (seconds). Set on **both** the worker (analysis) and the app (Workbench AI-assist runs the LLM in the API process); compose defaults it to 300. |
| `FEED_POLL_INTERVAL_SECONDS` | Threat-feed scheduler tick; `0` = manual-only (Poll now). |
| `CADDY_TLS_SNIPPET` | `tls_local_long` extends the `localhost` self-signed cert to ~1yr; leave unset for a public `SNR_DOMAIN`. |
| `BACKUP_INTERVAL_HOURS` / `BACKUP_RETENTION` | Scheduled backup cadence / retention. |
| `METRICS_TOKEN` | Bearer token to protect `/metrics`. |

---

Next: [Troubleshooting & FAQ →](./06-troubleshooting.md)
