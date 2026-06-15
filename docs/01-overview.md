[← Manual index](./README.md) · Next: [Getting Started →](./02-getting-started.md)

# 1. Overview & Concepts

## What SNR does

SNR (Signal to Noise) turns raw, noisy security data into structured, shareable
cyber threat intelligence. You give it a SIEM alert, a log file, and/or free-text
threat reporting; SNR produces:

- A **MITRE ATT&CK technique chain** and a **MITRE Attack Flow** (a causal graph of how the attack unfolded)
- Extracted, validated **indicators of compromise (IOCs)**
- **Detection rules** (Sigma, YARA, Suricata) — both extracted from the input and generated from observed behavior
- **Threat-actor attribution** (where the evidence supports it)
- An **audience-tailored intelligence brief** (e.g. SOC vs. executive framing)

Outputs can be exported to STIX 2.1, ATT&CK Navigator, MITRE Attack Flow Builder
(`.afb`), email (`.eml`), Markdown reports, detection-rule files, IOC CSV, or a
combined ZIP.

SNR is **LLM-agnostic** (Anthropic Claude or any OpenAI-compatible endpoint) and
**self-hosted** — your data stays within your deployment except for the analysis
call to the LLM provider you configure.

## How analysis works — the two-phase pipeline

Every analysis runs in two AI phases, streamed live so you can watch progress:

| Phase | Name | Produces |
|---|---|---|
| **1** | Technical Extraction | ATT&CK techniques, IOCs, detection rules, affected assets, threat-actor context, and (when supported) the Attack Flow graph |
| **2** | Stakeholder Brief | The audience-scoped narrative (summary, analysis, recommendations, etc.) built from Phase 1 findings |

Phase 1 is deterministic in structure (a fixed JSON schema); Phase 2 is shaped by
the selected **audience** and your configurable **brief sections**.

## Core concepts & terminology

- **Session** — one analysis and everything attached to it (inputs, results, notes, tags, exports). The unit of work, listed in the sidebar.
- **Audience** — the stakeholder profile that frames the Phase 2 brief: **SOC**, **Purple Team**, **Red Team**, **Detection & Response**, **General**, plus any custom audiences your admin defines.
- **TLP** — Traffic Light Protocol marking (CLEAR / GREEN / AMBER / AMBER+STRICT / RED) applied to exports.
- **ATT&CK chain** — the identified techniques laid out by tactic (kill-chain order).
- **Attack Flow** — a causal directed graph (actions, assets, tools, malware, AND/OR operators) showing *how* steps connected, beyond a flat list. Exportable as `.afb`.
- **IOC** — an indicator (IP, domain, URL, hash, email, filename, etc.) extracted and confidence-scored; can be defanged and flagged as a false positive.
- **Detection rule** — a Sigma / YARA / Suricata rule, extracted from the input or generated from observed TTPs.
- **Threat actor** — a canonical adversary record; sessions can be grouped under one to aggregate TTPs and IOCs across incidents.
- **Brief section** — a configurable block of the Phase 2 output (e.g. Threat Action, Technical Analysis). Admins control which sections exist and in what order.

## Data handling & privacy

- **Client-side redaction.** Before any analysis is sent, you can mark sensitive
  strings (hostnames, usernames, IPs) to be replaced with `[REDACTED]`; the server
  also applies the same masking server-side as defense in depth.
- **No external calls beyond your LLM.** SNR does not phone home or send data to
  third parties — the only outbound traffic is to the LLM provider you configure
  (Anthropic, or your own OpenAI-compatible endpoint, including fully local models).
- **Secrets** (API keys, JWT secret) are read from environment variables or mounted
  secret files; logs redact them automatically.
- **Self-hosted storage.** All sessions, users, and settings live in your deployment's
  database; deletes are soft (recoverable) and purged on a retention schedule.

See [SECURITY.md](../SECURITY.md) for the full control set.

---

Next: [Getting Started →](./02-getting-started.md)
