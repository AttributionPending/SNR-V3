import { useState, useEffect, useRef, useCallback } from 'react';
import { X, Mail, Save, Loader2, LayoutTemplate, Palette, ListChecks, FileText, Upload, Trash2, Download } from 'lucide-react';
import { cn } from '@/lib/utils';
import * as api from '@/lib/api';
import { parseSections } from '@/lib/sections';
import EmailTemplateEditor from './EmailTemplateEditor';
import RichTextEditor from './RichTextEditor';
import { Button } from './ui/button';
import { AUDIENCE_LABELS } from '@/types';
import type { AnalysisResult, AudienceType, EmailContent, TLPLevel, BriefSection } from '@/types';

// Team-level branding keys edited in the Studio (custom_intro_<audience> added at runtime).
const BRANDING_KEYS = [
  'email_header_text',
  'email_footer_text',
  'email_signature',
  'email_custom_preamble',
  'email_primary_color',
  'email_secondary_color',
  'email_font_family',
  'email_body_font_size',
  'email_logo_data',
] as const;

type StudioTab = 'content' | 'layout' | 'branding' | 'sections';

interface Props {
  open: boolean;
  onClose: () => void;
  sessionId: string;
  result: AnalysisResult;
  audience: string;
  tlp: TLPLevel;
  /** Shared per-session email content (RightPanel's editedEmail). */
  email: EmailContent;
  onContentChange: (key: string, value: string) => void;
  onShowToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
}

export default function EmailStudio({ open, onClose, sessionId, result, audience, tlp, email, onContentChange, onShowToast }: Props) {
  const [tab, setTab] = useState<StudioTab>('content');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Team-level drafts (template / branding / section enablement)
  const [templateDraft, setTemplateDraft] = useState('');
  const [branding, setBranding] = useState<Record<string, string>>({});
  const [sections, setSections] = useState<BriefSection[]>([]);

  const [previewHtml, setPreviewHtml] = useState('');
  const [previewLoading, setPreviewLoading] = useState(false);
  const previewTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const introKey = `custom_intro_${audience}`;

  // Load current team settings when opened.
  useEffect(() => {
    if (!open) return;
    setLoading(true);
    api.fetchSettings()
      .then((s) => {
        setTemplateDraft(s.email_template ?? '');
        const b: Record<string, string> = {};
        for (const k of BRANDING_KEYS) b[k] = s[k] ?? '';
        b[introKey] = s[introKey] ?? '';
        setBranding(b);
        setSections(parseSections(s.report_sections ?? ''));
        setLoading(false);
      })
      .catch(() => { setLoading(false); onShowToast?.('Failed to load email settings', 'error'); });
  }, [open, introKey, onShowToast]);

  // Debounced live preview of the REAL session email with all in-progress edits.
  const refreshPreview = useCallback(() => {
    if (previewTimer.current) clearTimeout(previewTimer.current);
    previewTimer.current = setTimeout(async () => {
      setPreviewLoading(true);
      try {
        const html = await api.fetchEmailStudioPreview({
          session_id: sessionId,
          audience,
          tlp,
          template: templateDraft,
          branding,
          reportSections: JSON.stringify(sections),
          emailContentOverrides: email as unknown as Record<string, string>,
        });
        setPreviewHtml(html);
      } catch (e) {
        onShowToast?.(e instanceof Error ? e.message : 'Preview failed', 'error');
      } finally {
        setPreviewLoading(false);
      }
    }, 250);
  }, [sessionId, audience, tlp, templateDraft, branding, sections, email, onShowToast]);

  useEffect(() => {
    if (open && !loading) refreshPreview();
    return () => { if (previewTimer.current) clearTimeout(previewTimer.current); };
  }, [open, loading, refreshPreview]);

  const setBrandingField = (key: string, value: string) => setBranding((b) => ({ ...b, [key]: value }));

  const toggleSection = (key: string) =>
    setSections((arr) => arr.map((s) => (s.key === key ? { ...s, enabled: !s.enabled } : s)));

  async function handleLogoUpload(file: File) {
    try {
      const dataUri = await api.uploadLogo(file);
      setBrandingField('email_logo_data', dataUri);
      onShowToast?.('Logo uploaded', 'success');
    } catch {
      onShowToast?.('Logo upload failed', 'error');
    }
  }

  async function handleLogoRemove() {
    try {
      await api.deleteLogo();
      setBrandingField('email_logo_data', '');
    } catch {
      onShowToast?.('Failed to remove logo', 'error');
    }
  }

  // Persist: content → per-session analyst overrides (merged with existing);
  // template/branding/sections → team settings.
  async function handleSave() {
    setSaving(true);
    try {
      // Merge content edits into the session's existing overrides (preserve
      // severity_badge / ioc_false_positives, which live in the same blob).
      const current = (await api.fetchSession(sessionId)).analystOverrides ?? {};
      const overrides: Record<string, string> = { ...current };
      const contentKeys = ['subject', ...sections.map((s) => s.key)];
      for (const k of contentKeys) {
        const edited = email[k] as string | undefined;
        const original = result.email_content[k] as string | undefined;
        if (edited !== undefined && edited !== original) overrides[k] = edited;
        else if (k in overrides && edited === original) delete overrides[k];
      }
      await api.saveOverrides(sessionId, overrides);

      await api.saveSettings({
        email_template: templateDraft,
        report_sections: JSON.stringify(sections),
        ...branding,
      });

      onShowToast?.('Email saved', 'success');
    } catch (e) {
      onShowToast?.(e instanceof Error ? e.message : 'Save failed', 'error');
    } finally {
      setSaving(false);
    }
  }

  async function handleDownloadEml() {
    try {
      const overrides: Record<string, string> = {};
      const contentKeys = ['subject', 'severity_badge', ...sections.map((s) => s.key)];
      for (const k of contentKeys) {
        const v = email[k] as string | undefined;
        if (v !== undefined) overrides[k] = v;
      }
      await api.exportEml({ session_id: sessionId, audience, tlp, email_content_overrides: overrides });
    } catch (e) {
      onShowToast?.(e instanceof Error ? e.message : 'Download failed', 'error');
    }
  }

  if (!open) return null;

  const editableSections = sections.filter((s) => s.type === 'text' || s.type === 'bullets' || s.type === 'numbered');

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-navy-950">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Mail className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold text-foreground">Email Studio</h2>
          <span className="text-[11px] text-muted-foreground">
            {AUDIENCE_LABELS[audience as AudienceType] ?? audience} · TLP:{tlp}
          </span>
          {previewLoading && <Loader2 className="w-3 h-3 animate-spin text-muted-foreground" />}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="text-xs h-7 gap-1.5" onClick={handleDownloadEml}>
            <Download className="w-3.5 h-3.5" /> Download .eml
          </Button>
          <Button variant="cyan" size="sm" className="text-xs h-7 gap-1.5" onClick={handleSave} disabled={saving || loading}>
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />} Save
          </Button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors ml-1" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Split body */}
      <div className="flex-1 flex min-h-0">
        {/* Live preview */}
        <div className="flex-1 min-w-0 bg-[#eef0f3] overflow-hidden">
          {previewHtml ? (
            <iframe title="Email preview" srcDoc={previewHtml} sandbox="" className="w-full h-full border-0 bg-white" />
          ) : (
            <div className="w-full h-full flex items-center justify-center text-muted-foreground text-xs">
              {loading ? 'Loading…' : 'Rendering preview…'}
            </div>
          )}
        </div>

        {/* Editor */}
        <div className="w-[440px] flex-shrink-0 border-l border-border flex flex-col bg-navy-900/40">
          {/* Tabs */}
          <div className="grid grid-cols-4 border-b border-border flex-shrink-0">
            {([
              ['content', 'Content', FileText],
              ['layout', 'Layout', LayoutTemplate],
              ['branding', 'Branding', Palette],
              ['sections', 'Sections', ListChecks],
            ] as const).map(([id, label, Icon]) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={cn(
                  'flex items-center justify-center gap-1 py-2 text-[11px] transition-colors',
                  tab === id ? 'text-cyan-300 border-b-2 border-cyan-500 bg-cyan-500/5' : 'text-muted-foreground hover:text-foreground'
                )}
              >
                <Icon className="w-3 h-3" />{label}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-4">
            {loading ? (
              <div className="flex items-center justify-center py-12 text-muted-foreground"><Loader2 className="w-5 h-5 animate-spin" /></div>
            ) : tab === 'content' ? (
              <>
                <Field label="Subject">
                  <input
                    type="text"
                    value={(email.subject as string) ?? ''}
                    onChange={(e) => onContentChange('subject', e.target.value)}
                    className="w-full bg-secondary/40 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                  />
                </Field>
                {editableSections.map((s) => (
                  <Field key={s.key} label={s.label} hint={!s.enabled ? 'hidden in current sections' : undefined}>
                    <RichTextEditor value={(email[s.key] as string) ?? ''} onChange={(v) => onContentChange(s.key, v)} />
                  </Field>
                ))}
                <p className="text-[10px] text-muted-foreground/60">
                  Techniques & IOC tables are auto-generated from the analysis and rendered by their section blocks.
                </p>
              </>
            ) : tab === 'layout' ? (
              <>
                <p className="text-[11px] text-muted-foreground">
                  Body layout (team-wide). Use <code className="font-mono">{'{{BLOCK}}'}</code> tokens for generated content and{' '}
                  <code className="font-mono">{'{field}'}</code> for inline values. Empty = default layout.
                </p>
                <EmailTemplateEditor value={templateDraft} onChange={setTemplateDraft} sections={sections} />
              </>
            ) : tab === 'branding' ? (
              <>
                <Field label="Header Title">
                  <TextInput value={branding.email_header_text} onChange={(v) => setBrandingField('email_header_text', v)} placeholder="SIGNAL TO NOISE" />
                </Field>
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Primary Color"><ColorInput value={branding.email_primary_color || '#1d4ed8'} onChange={(v) => setBrandingField('email_primary_color', v)} /></Field>
                  <Field label="Header / Accent"><ColorInput value={branding.email_secondary_color || '#0a0f1e'} onChange={(v) => setBrandingField('email_secondary_color', v)} /></Field>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <Field label="Font Family"><TextInput value={branding.email_font_family} onChange={(v) => setBrandingField('email_font_family', v)} placeholder="Arial" /></Field>
                  <Field label="Body Font Size"><TextInput value={branding.email_body_font_size} onChange={(v) => setBrandingField('email_body_font_size', v)} placeholder="14" /></Field>
                </div>
                <Field label="Logo">
                  <div className="flex items-center gap-2">
                    {branding.email_logo_data ? (
                      <img src={branding.email_logo_data} alt="logo" className="h-8 max-w-[120px] object-contain bg-navy-800 rounded border border-border" />
                    ) : <span className="text-[10px] text-muted-foreground">No logo</span>}
                    <label className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300 cursor-pointer">
                      <Upload className="w-3 h-3" /> Upload
                      <input type="file" accept="image/*" className="hidden" onChange={(e) => e.target.files?.[0] && handleLogoUpload(e.target.files[0])} />
                    </label>
                    {branding.email_logo_data && (
                      <button onClick={handleLogoRemove} className="flex items-center gap-1 text-[10px] text-red-400/70 hover:text-red-400"><Trash2 className="w-3 h-3" />Remove</button>
                    )}
                  </div>
                </Field>
                <Field label={`Audience Intro (${AUDIENCE_LABELS[audience as AudienceType] ?? audience})`}>
                  <TextArea value={branding[introKey]} onChange={(v) => setBrandingField(introKey, v)} placeholder="Optional fixed opening paragraph for this audience" />
                </Field>
                <Field label="Custom Preamble"><TextArea value={branding.email_custom_preamble} onChange={(v) => setBrandingField('email_custom_preamble', v)} /></Field>
                <Field label="Signature"><TextArea value={branding.email_signature} onChange={(v) => setBrandingField('email_signature', v)} /></Field>
                <Field label="Footer Text"><TextArea value={branding.email_footer_text} onChange={(v) => setBrandingField('email_footer_text', v)} /></Field>
              </>
            ) : (
              <>
                <p className="text-[11px] text-muted-foreground">
                  Which sections appear (team-wide; affects the brief, report, and email). Order/inclusion can also be controlled in the Layout template.
                </p>
                {sections.map((s) => (
                  <label key={s.key} className="flex items-center gap-2 text-xs text-foreground py-1 cursor-pointer">
                    <input type="checkbox" checked={!!s.enabled} onChange={() => toggleSection(s.key)} className="accent-cyan-500" />
                    <span className="flex-1">{s.label}</span>
                    <span className="text-[9px] uppercase text-muted-foreground">{s.type}</span>
                  </label>
                ))}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <div className="text-[10px] uppercase tracking-wide text-cyan-400/70 font-medium">{label}</div>
        {hint && <span className="text-[9px] text-yellow-400/70">{hint}</span>}
      </div>
      {children}
    </div>
  );
}

function TextInput({ value, onChange, placeholder }: { value?: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <input
      type="text"
      value={value ?? ''}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      className="w-full bg-secondary/40 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
    />
  );
}

function TextArea({ value, onChange, placeholder }: { value?: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <textarea
      value={value ?? ''}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      rows={2}
      className="w-full bg-secondary/40 border border-border rounded px-2 py-1.5 text-xs text-foreground resize-y focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
    />
  );
}

function ColorInput({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="flex items-center gap-2">
      <input type="color" value={value} onChange={(e) => onChange(e.target.value)} className="h-7 w-9 bg-transparent border border-border rounded cursor-pointer" />
      <input type="text" value={value} onChange={(e) => onChange(e.target.value)} className="flex-1 bg-secondary/40 border border-border rounded px-2 py-1 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50" />
    </div>
  );
}
