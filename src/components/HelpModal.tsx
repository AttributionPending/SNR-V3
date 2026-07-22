import { useState } from 'react';
import { X, ChevronDown, ChevronRight, BookOpen, Zap, Settings, LayoutList, Brain, Users, Mail, FileText, Shield, AlertTriangle, CheckCircle2, Info } from 'lucide-react';
import { cn } from '@/lib/utils';

interface Props {
  open: boolean;
  onClose: () => void;
}

// ── Accordion ──────────────────────────────────────────────────────────────────

function Section({
  id, label, icon, children, defaultOpen = false,
}: {
  id: string;
  label: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className={cn(
          'w-full flex items-center gap-2.5 px-4 py-3 text-left transition-colors',
          open ? 'bg-cyan-500/10 border-b border-border' : 'bg-secondary/20 hover:bg-secondary/40',
        )}
        aria-expanded={open}
        aria-controls={`help-${id}`}
      >
        <span className={cn('flex-shrink-0', open ? 'text-cyan-400' : 'text-muted-foreground')}>{icon}</span>
        <span className={cn('text-sm font-semibold flex-1', open ? 'text-foreground' : 'text-foreground/80')}>{label}</span>
        {open ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
      </button>
      {open && (
        <div id={`help-${id}`} className="px-4 pb-4 pt-3 bg-navy-900/40 space-y-3 text-sm text-foreground/80 leading-relaxed">
          {children}
        </div>
      )}
    </div>
  );
}

function Step({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <div className="flex-shrink-0 w-6 h-6 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-[11px] font-bold text-cyan-400">
        {n}
      </div>
      <div className="flex-1 pt-0.5">
        <div className="font-semibold text-foreground text-xs uppercase tracking-wide mb-1">{title}</div>
        <div className="text-xs text-foreground/70 leading-relaxed">{children}</div>
      </div>
    </div>
  );
}

function Note({ type = 'info', children }: { type?: 'info' | 'tip' | 'warn'; children: React.ReactNode }) {
  const styles = {
    info: 'bg-blue-500/8 border-blue-500/20 text-blue-300',
    tip:  'bg-cyan-500/8 border-cyan-500/20 text-cyan-300',
    warn: 'bg-yellow-500/8 border-yellow-500/20 text-yellow-300',
  };
  const icons = {
    info: <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />,
    tip:  <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />,
    warn: <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />,
  };
  return (
    <div className={cn('flex gap-2 rounded-md border px-3 py-2 text-xs', styles[type])}>
      {icons[type]}
      <span>{children}</span>
    </div>
  );
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2 items-start">
      <code className="text-[10px] bg-secondary/50 border border-border/60 rounded px-1.5 py-0.5 text-cyan-400 font-mono flex-shrink-0 mt-0.5">{label}</code>
      <span className="text-xs text-foreground/70">{value}</span>
    </div>
  );
}

// ── Main ───────────────────────────────────────────────────────────────────────

export default function HelpModal({ open, onClose }: Props) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-2xl max-h-[90vh] flex flex-col bg-background border border-border rounded-xl shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center gap-3 px-5 py-4 border-b border-border flex-shrink-0">
          <BookOpen className="w-5 h-5 text-muted-foreground" />
          <div className="flex-1">
            <h2 className="text-base font-semibold text-foreground">SNR — Help & Configuration Guide</h2>
            <p className="text-xs text-muted-foreground mt-0.5">Signal to Noise · Cyber Threat Intelligence Automation</p>
          </div>
          <button
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground transition-colors rounded-md p-1 hover:bg-secondary/50"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-3">

          {/* ── Quick Start ── */}
          <Section id="quickstart" label="Quick Start" icon={<Zap className="w-4 h-4" />} defaultOpen>
            <p>SNR converts raw security alerts and logs into structured, audience-ready intelligence briefs in two AI phases:</p>
            <div className="grid grid-cols-2 gap-3 my-2">
              <div className="rounded-md bg-secondary/30 border border-border p-3 text-xs space-y-1">
                <div className="font-semibold text-cyan-400">Phase 1 — Technical Analysis</div>
                <div className="text-muted-foreground">Maps MITRE ATT&CK techniques, extracts IOCs, identifies affected assets and threat actor context.</div>
              </div>
              <div className="rounded-md bg-secondary/30 border border-border p-3 text-xs space-y-1">
                <div className="font-semibold text-cyan-400">Phase 2 — Stakeholder Brief</div>
                <div className="text-muted-foreground">Generates an audience-tuned narrative: summary, observations, recommendations, and next steps.</div>
              </div>
            </div>
            <div className="space-y-3 mt-2">
              <Step n={1} title="Paste your data">
                Add SIEM alert JSON, raw log content, and/or freeform analyst notes into the input panel. You can use any combination — all three sources are merged before analysis.
              </Step>
              <Step n={2} title="Select audience & run">
                Choose the target audience (SOC, Purple Team, Detection & Response, etc.) from the dropdown, then click <strong>⚡ Analyze</strong>. The analysis streams in real time.
              </Step>
              <Step n={3} title="Review & export">
                Switch to the <strong>Review & Export</strong> tab to read the generated brief, edit any section inline, and download as <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">.eml</code>, <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">.zip</code>, STIX 2.1, or Navigator layer.
              </Step>
            </div>
            <Note type="tip">You can redact sensitive strings (hostnames, usernames, IP ranges) before the data is sent to the API using the <strong>Redact Sensitive Strings</strong> button.</Note>
          </Section>

          {/* ── First-Time Setup ── */}
          <Section id="setup" label="First-Time Setup" icon={<Settings className="w-4 h-4" />}>
            <p>Open <strong>Settings</strong> (gear icon in the sidebar) and configure the following before your first analysis:</p>
            <div className="space-y-3 mt-2">
              <Step n={1} title="Analyst Identity">
                Set your <strong>Analyst Name</strong>, <strong>Email</strong>, <strong>Organization</strong>, and default <strong>TLP level</strong>. These appear in every exported .eml header and CTI report.
              </Step>
              <Step n={2} title="AI Guidance (recommended)">
                Add your <strong>Organizational Context</strong> — a plain description of your environment (e.g., industry, key systems, crown jewels). Also add your <strong>Detection Stack</strong> to enable meaningful detection gap analysis (e.g., "Splunk + CrowdStrike Falcon + Palo Alto NGFW").
              </Step>
              <Step n={3} title="API Key">
                Ensure your <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">ANTHROPIC_API_KEY</code> is set in the <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">.env</code> file in the project root. Without this, no analysis will run.
              </Step>
            </div>
            <Note type="warn">The AI Guidance fields are injected into every analysis. Vague or missing context produces generic output. Be specific: name your SIEM, EDR, and firewall vendors.</Note>
          </Section>

          {/* ── Brief Sections ── */}
          <Section id="sections" label="Configuring Brief Sections" icon={<LayoutList className="w-4 h-4" />}>
            <p>
              <strong>Settings → Brief Sections</strong> controls exactly what Claude writes and in what order. Each section becomes a field in the AI's output schema.
            </p>
            <div className="space-y-2 mt-2">
              <div className="text-xs font-semibold text-foreground/60 uppercase tracking-wide">Section Types</div>
              <div className="space-y-1.5">
                <KV label="text" value="Free-form paragraph. Claude writes it as prose." />
                <KV label="bullets" value="Bullet-point list. Claude uses • as the prefix." />
                <KV label="numbered" value="Numbered list. Best for action items and steps." />
                <KV label="techniques" value="Auto (read-only) — populated directly from Phase 1 ATT&CK mapping. Claude does not regenerate this." />
                <KV label="iocs" value="Auto (read-only) — populated from the Phase 1 IOC extraction (top 15 by confidence)." />
              </div>
            </div>
            <div className="space-y-3 mt-3">
              <Step n={1} title="Reorder sections">
                Use the ↑ ↓ arrows on each section row to change the order. The email renders sections in exactly this order.
              </Step>
              <Step n={2} title="Disable a section">
                Uncheck the checkbox on any section to hide it from the output entirely. It won't appear in the email or be sent to Claude.
              </Step>
              <Step n={3} title="Edit Claude's instructions">
                Click a section row to expand it and edit the <strong>Claude Instructions</strong> field. This is the schema description sent to the model — be specific about length, format, and audience focus.
              </Step>
              <Step n={4} title="Add a custom section">
                Click <strong>Add Section</strong>, then expand the new row to set a label, type, JSON key, and instructions. The JSON key must be unique snake_case (e.g., <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">exec_summary</code>).
              </Step>
            </div>
            <Note type="tip">After changing sections, run a new analysis — previously stored results use the schema that was active at time of analysis and won't retroactively reflect section changes.</Note>
          </Section>

          {/* ── Audience Prompts ── */}
          <Section id="audiences" label="Audience Prompts & Custom Audiences" icon={<Users className="w-4 h-4" />}>
            <p>Each audience has a default prompt that tells Claude how to frame the brief. You can override these or add your own audiences.</p>
            <div className="space-y-3 mt-2">
              <Step n={1} title="Override a built-in audience prompt">
                Go to <strong>Settings → Audience Analysis Prompts</strong>, click <strong>Edit</strong> next to an audience, and rewrite the guidance. The default is pre-loaded — make targeted changes rather than replacing it entirely.
              </Step>
              <Step n={2} title="Add a custom audience">
                Scroll to the bottom of the Audience prompts section and click <strong>Add Custom Audience</strong>. Give it a name and prompt. It will appear in the audience dropdown on the main page.
              </Step>
              <Step n={3} title="Add audience-specific preambles">
                <strong>Settings → Audience-Specific Preambles</strong> lets you add a fixed opening paragraph for each audience — useful for boilerplate disclaimers or mandatory headers required by your org.
              </Step>
            </div>
            <Note type="info">Built-in audiences: <strong>SOC</strong> (triage-first), <strong>Purple Team</strong> (TTP chain + hunting), <strong>Red Team</strong> (adversary behavior focus), <strong>Detection & Response</strong> (detection gaps + rule logic), <strong>General</strong> (plain language, business impact).</Note>
          </Section>

          {/* ── Email Template ── */}
          <Section id="email" label="Email Template & Branding" icon={<Mail className="w-4 h-4" />}>
            <p><strong>Settings → Email Template</strong> controls the visual wrapper around the brief content.</p>
            <div className="space-y-2 mt-2">
              <KV label="Header text" value="Large banner text at the top of the email (defaults to 'SIGNAL TO NOISE')." />
              <KV label="Footer text" value="Small footer line at the bottom of the email." />
              <KV label="Signature block" value="Analyst sign-off appended after the last section." />
              <KV label="Custom preamble" value="Fixed paragraph injected at the very top of the email body — before any AI-generated content. Good for mandatory classification headers." />
            </div>
            <div className="mt-3">
              <div className="text-xs font-semibold text-foreground/60 uppercase tracking-wide mb-1.5">Live Preview</div>
              <p className="text-xs text-foreground/70">The Email Template section includes a live iframe preview using sample data. It updates as you change settings so you can see the final layout before running a real analysis.</p>
            </div>
            <Note type="tip">CC lists per audience are configured in <strong>Settings → CC / BCC Lists per Audience</strong>. Comma-separate multiple addresses.</Note>
          </Section>

          {/* ── CTI Report ── */}
          <Section id="report" label="CTI Report Template" icon={<FileText className="w-4 h-4" />}>
            <p>The CTI Report is a standalone Markdown file with deeper structure than the email brief. Download it from the <strong>Report</strong> tab in the output panel.</p>
            <p className="mt-1">The template uses two token types:</p>
            <div className="space-y-1.5 mt-2">
              <KV label="{field}" value="Single-line value — e.g. {date}, {severity}, {analyst_name}, {threat_actor_name}." />
              <KV label="{{BLOCK}}" value="Multi-line block — e.g. {{ATTACK_CHAIN}}, {{IOC_TABLE}}, {{OBSERVATIONS}}, {{ACTIONS}}, {{NEXT_STEPS}}." />
            </div>
            <p className="text-xs text-foreground/70 mt-3">Edit the template in <strong>Settings → CTI Report Template</strong>. The default template is pre-loaded — you can make targeted changes or replace it entirely. Rearrange blocks, remove sections you don't need, and add your own static content between tokens.</p>
            <Note type="info">Available blocks: <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">ATTACK_CHAIN</code> · <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">IOC_TABLE</code> · <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">EMAIL_IOCS</code> · <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">ATTACK_TABLE</code> · <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">OBSERVATIONS</code> · <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">ACTIONS</code> · <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">NEXT_STEPS</code> · <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">THREAT_ACTOR</code> · <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">CAMPAIGN_TIMELINE</code> · <code className="font-mono text-[10px] bg-secondary/50 px-1 rounded">AFFECTED_ASSETS_TABLE</code></Note>
          </Section>

          {/* ── Prompt Engineering ── */}
          <Section id="prompts" label="Prompt Engineering" icon={<Brain className="w-4 h-4" />}>
            <p>For advanced users, every AI prompt is overridable from <strong>Settings → Prompt Engineering</strong>.</p>
            <div className="space-y-2 mt-2">
              <KV label="System prompt" value="The global Claude persona and analytical rules. Changes affect both phases." />
              <KV label="Phase 1 instructions" value="Governs technique mapping, IOC extraction, and confidence assignment. The default pre-loads so you can make surgical edits." />
              <KV label="Phase 2 template" value="The brief drafting prompt. Supports {audience}, {date}, {audience_guidance}, {section_guidance}, and {technical_findings} variables." />
            </div>
            <Note type="warn">Phase 1 prompt changes affect the structured JSON schema. Incorrect edits can break parsing. Start by clicking <strong>Edit</strong> to load the default, then make targeted changes. Use <strong>Reset to Default</strong> if something breaks.</Note>
          </Section>

          {/* ── Exports ── */}
          <Section id="exports" label="Export Formats" icon={<Shield className="w-4 h-4" />}>
            <p>All exports are available from the <strong>Review & Export</strong> output panel after a successful analysis.</p>
            <div className="space-y-2 mt-2">
              <KV label=".eml" value="RFC 2822 email file. Opens in any email client (Outlook, Thunderbird, Apple Mail). Contains HTML and plain-text parts. Can include STIX, Navigator, IOC list, and ATT&CK chain diagram as attachments." />
              <KV label=".zip" value="Export All bundle: email brief + STIX 2.1 bundle + ATT&CK Navigator layer + raw analysis JSON + optional IOC list and chain diagram." />
              <KV label="STIX 2.1" value="Machine-readable threat intelligence bundle. Compatible with TAXII feeds, OpenCTI, MISP, and similar platforms." />
              <KV label="Navigator" value="ATT&CK Navigator layer JSON. Color-coded by confidence level. Import directly into the MITRE ATT&CK Navigator web app." />
              <KV label="CTI Report (.md)" value="Full Markdown intelligence report using the configurable template." />
            </div>
            <Note type="tip">You can edit the email brief inline before exporting. Click <strong>Edit</strong> in the email tab, modify any section, and the changes are applied to the .eml and .zip exports. The original AI output is preserved — use <strong>Reset</strong> to revert.</Note>
          </Section>

        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-5 py-3 border-t border-border flex-shrink-0">
          <span className="text-[10px] text-muted-foreground/50">SNR — Signal to Noise</span>
          <button
            onClick={onClose}
            className="text-xs px-3 py-1.5 rounded-md border border-border text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
