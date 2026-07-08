[← Getting Started](./02-getting-started.md) · [Manual index](./README.md) · Next: [Administrator Guide →](./04-administrator-guide.md)

# 3. Analyst Guide

The end-to-end workflow for turning raw data into shareable intelligence.

- [3.1 Create an analysis](#31-create-an-analysis)
- [3.2 Review the results](#32-review-the-results)
- [3.3 Refine and override](#33-refine-and-override)
- [3.4 Export](#34-export)
- [3.5 Organize sessions](#35-organize-sessions-tags--threat-actors)
- [3.6 Insights & search](#36-insights--search)

---

## 3.1 Create an analysis

Click **+ New Analysis**, then provide one or more inputs:

| Input | Use it for |
|---|---|
| **SIEM / Alert Data** | Paste raw alert JSON or detection output. |
| **Log File** | Upload `.csv`, `.txt`, `.log`, or `.json` (up to 10 MB). |
| **Freeform Notes & Intel** | Paste a threat report, advisory text, or your own notes. |

All provided sources are merged before analysis, so combine them freely.

**Redact sensitive strings.** Click **Redact Sensitive Strings** and add any values
(hostnames, usernames, internal IPs) you don't want sent to the LLM. They are replaced
with `[REDACTED]` in the browser before the request, and the server re-applies the same
masking as a safeguard.

**Select the audience.** The **Target Audience** dropdown shapes the brief:

| Audience | Framing |
|---|---|
| **SOC** | Containment-first, triage steps, watchlist-ready IOCs. |
| **Purple Team** | Full TTP chain, detection-coverage gaps, hunting hypotheses. |
| **Red Team** | Adversary behavior, tooling, C2, exploitation paths. |
| **Detection & Response** | Detection gaps with log sources and rule logic. |
| **General** | Plain-language narrative and business impact. |
| *Custom* | Any audiences your administrator has defined. |

Click **Analyze**. Progress streams through **Phase 1 (ATT&CK + IOC extraction)** and
**Phase 2 (Stakeholder Brief)**. You can keep watching the streamed text or wait for
completion.

## 3.2 Review the results

After completion you're on **Review & Export**. Key panels:

### ATT&CK Chain ⇄ Attack Flow
The graph header has a **Chain / Flow** toggle and an **expand** (⤢) button:

- **Chain** — techniques grouped by tactic in kill-chain order. Click any technique for details (evidence, confidence, ATT&CK link).
- **Flow** — the MITRE Attack Flow causal graph (actions, assets, tools, malware, AND/OR operators with labeled edges). Click an action node to open the same technique detail. The Flow toggle appears only when the analysis produced a flow; older/sparse analyses show a "Re-analyze to generate attack flow" hint.
- **Expand** opens either view full-screen (with its own Chain/Flow toggle) for large graphs.

### IOC table
- **Defang** toggle renders safe values (`hxxp`, `[.]`) for copy/paste into tickets; copies and exports follow the toggle.
- **CSV** and **TXT** export the (filtered, non-false-positive) indicators.
- **Flag false positives** with the per-row flag; flagged IOCs are dimmed, marked **FP**, and excluded from all exports. The state persists with the session.
- Filter by type, copy individual values or all, and view validation warnings on malformed IOCs.

### Detection rules, threat actor, assets, notes
- **Detection rules** — Sigma/YARA/Suricata, each copyable; marked *extracted* vs *generated*.
- **Threat actor** — shown in the session header; click to assign/change (see [3.5](#35-organize-sessions-tags--threat-actors)).
- **Affected assets** and **analyst notes** are available in the results; notes autosave.

## 3.3 Refine and override

- **Severity** — change it from the header dropdown; the override is flagged and flows into exports and the subject line.
- **TLP** — set the marking applied to exports.
- **Edit the brief** — click **Edit** on the email/brief; each section is a rich-text editor (bold, italic, lists, code). Saved edits are stored as overrides and used by the `.eml`, ZIP, and report exports; the original AI output is preserved (use **Reset**).
- **Re-analyze** — regenerate the analysis from the session's stored inputs without re-entering them. Use it to **retry** a failed/interrupted run, or to regenerate for a **different audience** (change the audience, then Re-analyze). Progress shows in place; a new result version replaces the old one when complete.

## 3.4 Export

From **Review & Export**:

| Export | Format | Downstream use |
|---|---|---|
| **STIX** | STIX 2.1 bundle (`.json`) | TIPs / TAXII — OpenCTI, MISP, ThreatConnect. Includes Attack Flow extension objects when a flow exists. |
| **Navigator** | ATT&CK Navigator layer (`.json`) | Import into the MITRE ATT&CK Navigator (color-coded by confidence). |
| **Attack Flow** | `.afb` | Open/refine in MITRE's [Attack Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/ui/). Appears when a flow exists. |
| **Email brief** | `.eml` | Open in any mail client; HTML + plain-text parts; optional STIX/Navigator/IOC/diagram attachments. |
| **CTI Report** | Markdown (`.md`) | Full written report using the configurable report template. |
| **Detection rules** | `.txt` | Hand to detection engineering. |
| **IOCs** | `.csv` | Watchlists / bulk import. |
| **Export package** | `.zip` | Everything bundled (brief + STIX + Navigator + analysis JSON + optional IOCs/diagram). |
| **PDF** | `.pdf` | Print-ready brief. |

False-positive-flagged IOCs are excluded from every export.

### Email Studio

Design the stakeholder email in one place — a full-screen editor with the **rendered brief
beside the controls**, opened from a session's **Email** tab (or from **Settings → Email
Branding & Templates** before your first analysis). It consolidates what used to be split
across settings:

- **Content** — the subject and each brief section (rich text), per session.
- **Layout** — the body-section template (`{{BLOCK}}` / `{field}` tokens), team-wide.
- **Brand Kit** — reusable per-client **brand profiles** (colors, logo, header/subtitle,
  footer, fonts) plus a **sender identity** (From / Reply-To / CC / BCC / preheader / subject
  template), selectable per session. SNR ships a default theme out of the box; brand kits can be
  imported/exported as JSON.
- **Defaults / Sections** — the team-wide branding fallback and which sections appear.

Edits save to the same team-wide settings the exports use, so the downloaded `.eml` matches the
live preview.

## 3.5 Organize sessions, tags & threat actors

**Sessions list** (sidebar): search by name, filter by severity / audience / tag, and
enter **Select** mode for bulk actions. Rename via double-click or the right-click menu.
**Deleting** a session is soft and shows an **Undo** toast. After the toast, deleted sessions
stay recoverable for **7 days** from **Activity & Reports → Recently Deleted → Restore**, then
they're purged.

**Tags:** add tags from a session's hover icon or right-click menu (with autocomplete
from existing tags), or in bulk from Select mode. Filter the list by tag.

**Threat actors:** switch the sidebar to the **Threat Actors** view to see canonical
adversary records. You can:
- **Assign** a session to an actor (from the session header or right-click menu), or **create** an actor manually.
- **Bulk group** several selected sessions under one actor.
- **Merge** duplicate actors.
- Open an actor to see its linked sessions plus **aggregated TTPs and IOCs** across all of them — useful for campaign tracking.

Analyses also auto-link to a detected actor (or an "Unattributed" placeholder) where attribution is possible.

## 3.6 Author your own report — Analyst Workbench

When you've done **original research** and there's no source article to analyze, author the
report directly. From the sidebar click **Write report** (or open **Workbench** on any existing
session to hand-edit it). The full-screen editor has a tab for every part of the result:

- **Summary** — title, severity, confidence, description, analyst notes.
- **ATT&CK** — add techniques with an autocomplete picker that fills the name + tactic from the
  bundled MITRE dataset.
- **IOCs**, **Detections** (author Sigma/YARA/Suricata), **Actor & Assets**.
- **Flow** — build the Attack Flow causal graph: add nodes (action / asset / tool / malware /
  AND-OR) and edges, with a live diagram. Action nodes reference your ATT&CK techniques; a flow
  is kept on save only if it has **≥2 action nodes, ≥1 edge, and forms a DAG**.
- **Narrative** — the email sections.

**AI assist** (optional — you stay the author, nothing auto-saves):
- **Draft with AI** — write the narrative from your structured findings.
- **Suggest from notes** — paste a freeform write-up; the AI extracts techniques / IOCs / rules
  and a flow to merge in.
- **Generate detection rules** — Sigma/YARA/Suricata for your current techniques.

**Save** stores a new result version; the session is tagged **Authored**, and every export works
exactly as for an analyzed session (the CTI report notes "Original research — analyst-authored").

## 3.7 Insights & search

- **Activity Log / Reports** (sidebar): an **Analytics** dashboard (sessions over time, severity/audience breakdowns, export activity, IOC and technique distributions), **Session history**, **Recently Deleted**, and the **Audit trail**.
- **Global search** (`Ctrl`/`⌘`+`K`): search across sessions, IOCs, techniques, threat actors, and assets; jump straight to a result.

---

Next: [Administrator Guide →](./04-administrator-guide.md)
