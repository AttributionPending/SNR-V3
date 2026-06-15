[← Overview](./01-overview.md) · [Manual index](./README.md) · Next: [Analyst Guide →](./03-analyst-guide.md)

# 2. Getting Started

## Signing in

SNR requires an account. On a brand-new deployment, the **first** admin account is
created automatically from the install configuration (`A2N_ADMIN_EMAIL` /
`A2N_ADMIN_PASSWORD`). Use those credentials for the first login, then create
per-analyst accounts (see the [Administrator Guide](./04-administrator-guide.md)).

1. Open SNR in your browser (your deployment URL, or `http://localhost:5173` in local dev).
2. Enter your email and password and select **Sign in**.
3. If your organization uses multiple **teams** (workspaces), you'll work within your
   assigned team; admins can switch teams from the account menu.

> First thing after first login: change the bootstrap admin password and create
> individual accounts — shared logins defeat the audit trail.

## The workspace at a glance

| Area | What it is |
|---|---|
| **Sidebar (left)** | New Analysis button, global search, the **Sessions** list with filters, and a **Threat Actors** view toggle. Bottom: Activity Log, Admin Panel, Settings, Help, account menu. |
| **Analysis canvas (center)** | Two steps: **Configure & Analyze** (inputs) and **Review & Export** (results). |
| **Results panels** | ATT&CK Chain / Attack Flow, IOC table, detection rules, the brief (email) with tabs for STIX / Navigator, analyst notes, and export buttons. |
| **Settings** | All configuration (LLM provider, identity, templates, sections, prompts). Admin/owner-facing. |
| **Reports** (Activity Log) | Analytics dashboard, session history, and the audit trail. |

## Your first analysis (5 minutes)

1. Click **+ New Analysis** in the sidebar.
2. Paste a SIEM/alert payload into **SIEM / Alert Data**, and/or upload a **log file**
   (`.csv`, `.txt`, `.log`, `.json`), and/or type context into **Freeform Notes & Intel**.
   You can combine all three — they're merged before analysis.
3. (Recommended) Click **Redact Sensitive Strings** and add any values to mask before
   the data leaves your browser.
4. Pick a **Target Audience** (start with **SOC**).
5. Click **Analyze**. Watch the two-phase progress stream (Phase 1 extraction → Phase 2 brief).
6. When it completes you're on **Review & Export**: explore the ATT&CK chain, IOCs,
   detection rules, and the generated brief. Try an export (e.g. **Download PDF** or **.eml**).

That's the core loop. The [Analyst Guide](./03-analyst-guide.md) covers every step in depth.

## Keyboard shortcuts

| Key | Action |
|---|---|
| `N` | New session |
| `Ctrl` / `⌘` + `K` | Global intelligence search |
| `?` | Toggle the keyboard-shortcut help |
| `S` | Toggle the sidebar |
| `1`–`9` | Jump to session 1–9 in the list |
| `Esc` | Close modals / clear selection |

> Shortcuts are ignored while you're typing in an input, textarea, or editor.

---

Next: [Analyst Guide →](./03-analyst-guide.md)
