import type { AnalysisResult } from './claude.js';
import { defang } from './defang.js';
import { type BriefSection, DEFAULT_SECTIONS, AUTO_TYPES } from './sections.js';
import { resolveTheme, type EmailTheme } from './email-theme.js';

type TLPLevel = 'CLEAR' | 'GREEN' | 'AMBER' | 'AMBER+STRICT' | 'RED';

const TLP_COLORS: Record<TLPLevel, string> = {
  CLEAR:          '#6b7280',
  GREEN:          '#16a34a',
  AMBER:          '#d97706',
  'AMBER+STRICT': '#ea580c',
  RED:            '#dc2626',
};

const TLP_TEXT_COLORS: Record<TLPLevel, string> = {
  CLEAR:          '#ffffff',
  GREEN:          '#ffffff',
  AMBER:          '#ffffff',
  'AMBER+STRICT': '#ffffff',
  RED:            '#ffffff',
};

const SEVERITY_COLORS: Record<string, string> = {
  Critical:      '#b91c1c',
  High:          '#dc2626',
  Medium:        '#d97706',
  Low:           '#16a34a',
  Informational: '#2563eb',
};

const SEVERITY_BG: Record<string, string> = {
  Critical:      '#fef2f2',
  High:          '#fff1f2',
  Medium:        '#fffbeb',
  Low:           '#f0fdf4',
  Informational: '#eff6ff',
};

const AUDIENCE_LABELS: Record<string, string> = {
  purple_team: 'Purple Team',
  soc:         'SOC',
  red_team:    'Red Team',
  dr:          'Detection & Response',
  general:     'General',
};

// IOC type badge colors
const IOC_TYPE_COLORS: Record<string, { bg: string; fg: string }> = {
  sha256:    { bg: '#fee2e2', fg: '#991b1b' },
  sha1:      { bg: '#fee2e2', fg: '#991b1b' },
  md5:       { bg: '#fee2e2', fg: '#991b1b' },
  hash:      { bg: '#fee2e2', fg: '#991b1b' },
  ip:        { bg: '#ffedd5', fg: '#c2410c' },
  ipv4:      { bg: '#ffedd5', fg: '#c2410c' },
  ipv6:      { bg: '#ffedd5', fg: '#c2410c' },
  domain:    { bg: '#dbeafe', fg: '#1e40af' },
  url:       { bg: '#ede9fe', fg: '#5b21b6' },
  file:      { bg: '#d1fae5', fg: '#065f46' },
  filename:  { bg: '#d1fae5', fg: '#065f46' },
  email:     { bg: '#dcfce7', fg: '#15803d' },
  registry:  { bg: '#f3f4f6', fg: '#374151' },
  mutex:     { bg: '#f3f4f6', fg: '#374151' },
  pipe:      { bg: '#e0f2fe', fg: '#075985' },
  service:   { bg: '#e0f2fe', fg: '#075985' },
  useragent: { bg: '#fef9c3', fg: '#854d0e' },
};

function iocBadgeColors(type: string): { bg: string; fg: string } {
  return IOC_TYPE_COLORS[type.toLowerCase()] ?? { bg: '#f3f4f6', fg: '#374151' };
}

/** @deprecated — replaced by BriefSection.enabled; kept for backward compat */
export interface SectionToggles {
  showObservations?: boolean;
  showTechniques?: boolean;
  showAffectedAssets?: boolean;
  showActions?: boolean;
  showIocs?: boolean;
  showNextSteps?: boolean;
}

interface EmlOptions {
  result: AnalysisResult;
  audience: string;
  tlp: TLPLevel;
  analystEmail: string;
  analystName: string;
  ccMap?: Record<string, string[]>;
  attachments?: Array<{ filename: string; content: Buffer; contentType: string }>;
  headerText?: string;
  footerText?: string;
  signature?: string;
  customPreamble?: string;
  audienceIntro?: string;
  /** Configurable sections — drives rendering order and which sections appear */
  sections?: BriefSection[];
  /** @deprecated use sections[n].enabled = false instead */
  sectionToggles?: SectionToggles;
  /** Branding: primary accent color (section bars, bullet colors) */
  primaryColor?: string;
  /** Branding: secondary color (dark header/footer background) */
  secondaryColor?: string;
  /** Branding: base64 data URI for logo (e.g. data:image/png;base64,...) */
  logoDataUri?: string;
  /** Branding: body font family (whitelisted name, e.g. "Georgia") */
  fontFamily?: string;
  /** Branding: body font size in px (12–16) */
  bodyFontSize?: string;
  /** Email body layout template (token-based). Empty = built-in default layout. */
  template?: string;
  /** Org name, for the {org_name} template field token */
  orgName?: string;
}

export function buildEml(opts: EmlOptions): string {
  const { result, audience, tlp, analystEmail, analystName } = opts;
  const sections = opts.sections ?? DEFAULT_SECTIONS;
  const email = result.email_content;
  const audienceLabel = AUDIENCE_LABELS[audience] ?? audience;
  const tlpColor = TLP_COLORS[tlp as TLPLevel] ?? '#6b7280';
  const tlpTextColor = TLP_TEXT_COLORS[tlp as TLPLevel] ?? '#ffffff';
  const severityColor = SEVERITY_COLORS[email.severity_badge] ?? '#374151';
  const severityBg = SEVERITY_BG[email.severity_badge] ?? '#f9fafb';
  const boundary = `SNR_BOUNDARY_${Date.now()}`;
  const htmlBoundary = `SNR_HTML_${Date.now()}`;

  const ccList = opts.ccMap?.[audience] ?? [];
  const ccHeader = ccList.length > 0 ? `CC: ${ccList.join(', ')}\r\n` : '';

  const primaryColor = opts.primaryColor || '#1d4ed8';
  const secondaryColor = opts.secondaryColor || '#0a0f1e';

  const html = buildHtmlBody({
    email, audienceLabel, tlp, tlpColor, tlpTextColor,
    severityColor, severityBg, result,
    sections,
    headerText: opts.headerText,
    footerText: opts.footerText,
    signature: opts.signature,
    customPreamble: opts.customPreamble,
    audienceIntro: opts.audienceIntro,
    sectionToggles: opts.sectionToggles,
    primaryColor,
    secondaryColor,
    logoDataUri: opts.logoDataUri,
    fontFamily: opts.fontFamily,
    bodyFontSize: opts.bodyFontSize,
    template: opts.template,
    orgName: opts.orgName,
    analystName: opts.analystName,
  });

  const plainText = buildPlainText({
    email, audienceLabel, tlp, result,
    sections,
    headerText: opts.headerText,
    footerText: opts.footerText,
    signature: opts.signature,
    customPreamble: opts.customPreamble,
    audienceIntro: opts.audienceIntro,
  });

  const headers = [
    `MIME-Version: 1.0`,
    `Date: ${new Date().toUTCString()}`,
    `From: ${analystName} <${analystEmail}>`,
    `To: `,
    ccHeader.trim(),
    `Subject: ${email.subject}`,
    `X-Unsent: 1`,
    `X-Mozilla-Draft-Info: internal/draft`,
    `X-SNR-TLP: TLP:${tlp}`,
    `X-SNR-Severity: ${email.severity_badge}`,
    `X-SNR-Audience: ${audienceLabel}`,
  ].filter(Boolean).join('\r\n');

  let body: string;
  if (opts.attachments && opts.attachments.length > 0) {
    const attachmentParts = opts.attachments.map((att) => {
      const b64 = att.content.toString('base64');
      const chunks = b64.match(/.{1,76}/g) ?? [];
      return [
        `--${boundary}`,
        `Content-Type: ${att.contentType}; name="${att.filename}"`,
        `Content-Disposition: attachment; filename="${att.filename}"`,
        `Content-Transfer-Encoding: base64`,
        '',
        chunks.join('\r\n'),
      ].join('\r\n');
    });

    body = [
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      `Content-Type: multipart/alternative; boundary="${htmlBoundary}"`,
      '',
      `--${htmlBoundary}`,
      `Content-Type: text/plain; charset=utf-8`,
      `Content-Transfer-Encoding: quoted-printable`,
      '',
      qpEncode(plainText),
      '',
      `--${htmlBoundary}`,
      `Content-Type: text/html; charset=utf-8`,
      `Content-Transfer-Encoding: quoted-printable`,
      '',
      qpEncode(html),
      '',
      `--${htmlBoundary}--`,
      '',
      ...attachmentParts,
      `--${boundary}--`,
    ].join('\r\n');
  } else {
    body = [
      `Content-Type: multipart/alternative; boundary="${htmlBoundary}"`,
      '',
      `--${htmlBoundary}`,
      `Content-Type: text/plain; charset=utf-8`,
      `Content-Transfer-Encoding: quoted-printable`,
      '',
      qpEncode(plainText),
      '',
      `--${htmlBoundary}`,
      `Content-Type: text/html; charset=utf-8`,
      `Content-Transfer-Encoding: quoted-printable`,
      '',
      qpEncode(html),
      '',
      `--${htmlBoundary}--`,
    ].join('\r\n');
  }

  return `${headers}\r\n${body}`;
}

// ── Content parsers ───────────────────────────────────────────────────────────

/** Split "1. text\n2. text" into individual strings, stripping leading numbers. */
function parseActionItems(text: string): string[] {
  const lines = text.split('\n').map(s => s.trim()).filter(Boolean);
  const isNumbered = lines.some(l => /^\d+\.\s/.test(l));
  if (!isNumbered) return lines;
  const items: string[] = [];
  let current = '';
  for (const line of lines) {
    if (/^\d+\.\s/.test(line)) {
      if (current) items.push(current);
      current = line.replace(/^\d+\.\s*/, '').trim();
    } else {
      current = current ? `${current} ${line}` : line;
    }
  }
  if (current) items.push(current);
  return items;
}

/** Split bullet-prefixed lines into individual strings. */
function parseBulletItems(text: string): string[] {
  return text.split('\n')
    .map(s => s.replace(/^[•\-\*►▸▪◆·]\s*/, '').trim())
    .filter(Boolean);
}

// ── HTML builder ──────────────────────────────────────────────────────────────
// Table-based inline-CSS layout. Compatible with Outlook (Word engine),
// Gmail, Apple Mail, and mobile clients.

function nl2br(text: string): string {
  return esc(text).replace(/\n/g, '<br>');
}

export function buildHtmlBody(opts: {
  email: AnalysisResult['email_content'];
  audienceLabel: string;
  tlp: string;
  tlpColor: string;
  tlpTextColor: string;
  severityColor: string;
  severityBg: string;
  result: AnalysisResult;
  headerText?: string;
  footerText?: string;
  signature?: string;
  customPreamble?: string;
  audienceIntro?: string;
  sections?: BriefSection[];
  /** @deprecated */
  sectionToggles?: SectionToggles;
  primaryColor?: string;
  secondaryColor?: string;
  logoDataUri?: string;
  fontFamily?: string;
  bodyFontSize?: string;
  template?: string;
  orgName?: string;
  analystName?: string;
  /** White-label theme overrides (brand profile). Falls back to the legacy
   * primaryColor/secondaryColor/headerText/footerText/fontFamily opts. */
  theme?: Partial<EmailTheme>;
}): string {
  const { email, audienceLabel, tlp, tlpColor, severityColor, result } = opts;
  const sections = opts.sections ?? DEFAULT_SECTIONS;

  // Resolve the effective theme: legacy opts first, then explicit theme overrides.
  const T = resolveTheme({
    primary: opts.primaryColor,
    secondary: opts.secondaryColor,
    headerTitle: opts.headerText,
    footerText: opts.footerText,
    fontFamily: opts.fontFamily,
    bodyFontSize: opts.bodyFontSize,
    ...(opts.theme ?? {}),
  });
  const primaryColor = T.primary;
  const secondaryColor = T.secondary;

  const headerTitle = T.headerTitle;
  const footerLine = T.footerText.trim()
    ? T.footerText.trim()
    : T.showVendorAttribution
      ? `Generated by SNR &mdash; Signal to Noise &nbsp;&bull;&nbsp; TLP:${esc(tlp)} &nbsp;&bull;&nbsp; Handle per your organization&rsquo;s data classification policy`
      : `TLP:${esc(tlp)} &nbsp;&bull;&nbsp; Handle per your organization&rsquo;s data classification policy`;

  const displayTitle = esc(
    (() => {
      const parts = (email.subject as string).replace(/^\[TLP:[^\]]+\]\s*\[SNR\]\s*/, '').split('|').map(s => s.trim());
      // New format: TLP:X | Severity | Category | Date — grab category (index 2)
      // Old format: Severity | Category | Date — grab category (index 1)
      const category = parts.find((p, i) => i > 0 && !p.startsWith('TLP:') && !['Critical','High','Medium','Low','Informational'].includes(p) && !/^\d{4}-\d{2}-\d{2}$/.test(p));
      return category || parts[0] || 'Security Incident';
    })()
  );

  const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const techCount = result.attack_chain?.length ?? 0;
  const iocCount  = result.iocs?.length ?? 0;

  // ── Section block renderers ───────────────────────────────────────────────

  function renderTextBlock(label: string, content: string, accentColor = primaryColor): string {
    return `
          <table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin-bottom:24px;border:1px solid #e5e7eb;">
            <tr><td height="3" bgcolor="${esc(accentColor)}" style="background-color:${esc(accentColor)};font-size:0;line-height:0;">&nbsp;</td></tr>
            <tr>
              <td bgcolor="#f8fafc" style="padding:12px 18px;background-color:#f8fafc;border-bottom:1px solid #e5e7eb;">
                <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:bold;color:#0f172a;letter-spacing:1.5px;text-transform:uppercase;">${esc(label)}</p>
              </td>
            </tr>
            <tr>
              <td style="padding:18px;">
                <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.8;color:#374151;">${markdownNl2br(content)}</p>
              </td>
            </tr>
          </table>`;
  }

  function renderBulletsBlock(label: string, content: string): string {
    const items = parseBulletItems(content);
    const rows = items.length > 0
      ? items.map((obs, i) => `
    <tr>
      <td style="padding:11px 18px;${i < items.length - 1 ? 'border-bottom:1px solid #f1f5f9;' : ''}">
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
          <tr>
            <td width="18" valign="top" style="padding-top:1px;padding-right:10px;">
              <span style="color:${esc(primaryColor)};font-size:20px;line-height:1;font-family:Arial,Helvetica,sans-serif;">&#8226;</span>
            </td>
            <td valign="top">
              <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.65;color:#374151;">${markdownToHtml(obs)}</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>`).join('')
      : `<tr><td style="padding:16px 18px;"><p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.75;color:#374151;">${markdownNl2br(content)}</p></td></tr>`;
    return `
          <table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin-bottom:24px;border:1px solid #e5e7eb;">
            <tr><td height="3" bgcolor="${esc(primaryColor)}" style="background-color:${esc(primaryColor)};font-size:0;line-height:0;">&nbsp;</td></tr>
            <tr>
              <td bgcolor="#f8fafc" style="padding:12px 18px;background-color:#f8fafc;border-bottom:1px solid #e5e7eb;">
                <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:bold;color:#0f172a;letter-spacing:1.5px;text-transform:uppercase;">${esc(label)}</p>
              </td>
            </tr>
            ${rows}
          </table>`;
  }

  function renderNumberedBlock(label: string, content: string): string {
    const actions = parseActionItems(content);
    const rows = actions.length > 0
      ? actions.map((action, i) => {
          const isImmediate = i === 0 && /^immediate/i.test(action);
          const numBg = isImmediate ? '#b91c1c' : primaryColor;
          const rowBgColor = isImmediate ? '#fff5f5' : (i % 2 === 1 ? '#f9fafb' : '');
          const rowStyle  = isImmediate ? 'background-color:#fff5f5;' : (i % 2 === 1 ? 'background-color:#f9fafb;' : '');
          const isLast = i === actions.length - 1;
          return `
    <tr${rowBgColor ? ` bgcolor="${rowBgColor}"` : ''}>
      <td style="${rowStyle}${isLast ? '' : 'border-bottom:1px solid #f1f5f9;'}">
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
          <tr>
            <td width="52" valign="top" align="center" style="padding:14px 4px 14px 18px;">
              <table border="0" cellpadding="0" cellspacing="0">
                <tr><td align="center" valign="middle" bgcolor="${numBg}" style="background-color:${numBg};width:28px;height:28px;color:#ffffff;font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:bold;text-align:center;">${i + 1}</td></tr>
              </table>
            </td>
            <td valign="middle" style="padding:14px 18px 14px 8px;">
              <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.65;color:#1e293b;">${markdownToHtml(action)}</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>`;
        }).join('')
      : `<tr><td style="padding:16px 18px;"><p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.8;color:#1e293b;">${markdownNl2br(content)}</p></td></tr>`;
    return `
          <table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin-bottom:24px;border:1px solid #e5e7eb;">
            <tr><td height="3" bgcolor="${esc(severityColor)}" style="background-color:${esc(severityColor)};font-size:0;line-height:0;">&nbsp;</td></tr>
            <tr>
              <td bgcolor="${esc(secondaryColor)}" style="padding:12px 18px;background-color:${esc(secondaryColor)};border-bottom:1px solid #1e293b;">
                <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:bold;color:#e2e8f0;letter-spacing:1.5px;text-transform:uppercase;">${esc(label)} &mdash; ${esc(audienceLabel)}</p>
              </td>
            </tr>
            ${rows}
          </table>`;
  }

  function renderTechniquesBlock(label: string): string {
    const chain = result.attack_chain ?? [];
    if (chain.length === 0) return '';
    const rows = chain.map((t, i) => {
      const isLast = i === chain.length - 1;
      return `
    <tr>
      <td style="padding:10px 14px;${isLast ? '' : 'border-bottom:1px solid #f1f5f9;'}white-space:nowrap;vertical-align:top;">
        <span style="font-family:Courier New,Courier,monospace;font-size:12px;color:${esc(primaryColor)};font-weight:bold;">${esc(t.technique_id)}</span>
      </td>
      <td style="padding:10px 14px;${isLast ? '' : 'border-bottom:1px solid #f1f5f9;'}font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:bold;color:#1e293b;vertical-align:top;width:38%;">
        ${esc(t.technique_name)}
      </td>
      <td style="padding:10px 14px;${isLast ? '' : 'border-bottom:1px solid #f1f5f9;'}font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#64748b;vertical-align:top;">
        ${markdownToHtml(t.evidence)}
      </td>
    </tr>`;
    }).join('');
    return `
          <table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin-bottom:24px;border:1px solid #dbeafe;">
            <tr><td height="3" bgcolor="${esc(primaryColor)}" style="background-color:${esc(primaryColor)};font-size:0;line-height:0;">&nbsp;</td></tr>
            <tr>
              <td bgcolor="#1e3a5f" style="padding:12px 18px;background-color:#1e3a5f;border-bottom:1px solid #1e3a5f;">
                <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:bold;color:#bfdbfe;letter-spacing:1.5px;text-transform:uppercase;">${esc(label)}</p>
              </td>
            </tr>
            <tr>
              <td style="padding:0;">
                <table width="100%" border="0" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
                  <tr bgcolor="#f8fafc" style="background-color:#f8fafc;">
                    <th align="left" style="padding:8px 14px;font-family:Arial,Helvetica,sans-serif;font-size:10px;font-weight:bold;color:#64748b;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid #e5e7eb;width:100px;">ID</th>
                    <th align="left" style="padding:8px 14px;font-family:Arial,Helvetica,sans-serif;font-size:10px;font-weight:bold;color:#64748b;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid #e5e7eb;width:38%;">Technique</th>
                    <th align="left" style="padding:8px 14px;font-family:Arial,Helvetica,sans-serif;font-size:10px;font-weight:bold;color:#64748b;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid #e5e7eb;">Evidence</th>
                  </tr>
                  ${rows}
                </table>
              </td>
            </tr>
          </table>`;
  }

  function renderIocsBlock(label: string): string {
    const iocs = result.iocs ?? [];
    if (iocs.length === 0) return '';
    const rows = iocs.map((ioc, i) => {
      const { bg, fg } = iocBadgeColors(ioc.type);
      const isLast = i === iocs.length - 1;
      return `
    <tr>
      <td style="padding:10px 14px;${isLast ? '' : 'border-bottom:1px solid #f1f5f9;'}white-space:nowrap;vertical-align:top;width:90px;">
        <span style="display:inline-block;padding:3px 8px;background-color:${bg};color:${fg};font-family:Arial,Helvetica,sans-serif;font-size:10px;font-weight:bold;letter-spacing:0.5px;text-transform:uppercase;">${esc(ioc.type.toUpperCase())}</span>
      </td>
      <td style="padding:10px 14px;${isLast ? '' : 'border-bottom:1px solid #f1f5f9;'}font-family:Courier New,Courier,monospace;font-size:12px;color:#1e293b;word-break:break-all;vertical-align:top;">
        ${esc(defang(ioc.value, ioc.type))}
      </td>
      <td style="padding:10px 14px;${isLast ? '' : 'border-bottom:1px solid #f1f5f9;'}font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#64748b;vertical-align:top;">
        ${markdownToHtml(ioc.context)}
      </td>
    </tr>`;
    }).join('');
    return `
          <table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin-bottom:24px;border:1px solid #dbeafe;">
            <tr><td height="3" bgcolor="${esc(primaryColor)}" style="background-color:${esc(primaryColor)};font-size:0;line-height:0;">&nbsp;</td></tr>
            <tr>
              <td bgcolor="#1e3a5f" style="padding:12px 18px;background-color:#1e3a5f;border-bottom:1px solid #1e3a5f;">
                <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:bold;color:#bfdbfe;letter-spacing:1.5px;text-transform:uppercase;">${esc(label)}</p>
              </td>
            </tr>
            <tr>
              <td style="padding:0;">
                <table width="100%" border="0" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
                  <tr bgcolor="#f8fafc" style="background-color:#f8fafc;">
                    <th align="left" style="padding:8px 14px;font-family:Arial,Helvetica,sans-serif;font-size:10px;font-weight:bold;color:#64748b;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid #e5e7eb;width:90px;">Type</th>
                    <th align="left" style="padding:8px 14px;font-family:Arial,Helvetica,sans-serif;font-size:10px;font-weight:bold;color:#64748b;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid #e5e7eb;width:44%;">Indicator</th>
                    <th align="left" style="padding:8px 14px;font-family:Arial,Helvetica,sans-serif;font-size:10px;font-weight:bold;color:#64748b;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid #e5e7eb;">Context</th>
                  </tr>
                  ${rows}
                </table>
              </td>
            </tr>
          </table>`;
  }

  // ── Render enabled sections in order ──────────────────────────────────────
  const sectionBlocks = sections
    .filter(s => s.enabled)
    .map(s => {
      const content = (email[s.key] as string) ?? '';
      switch (s.type) {
        case 'text':     return renderTextBlock(s.label, content);
        case 'bullets':  return renderBulletsBlock(s.label, content);
        case 'numbered': return renderNumberedBlock(s.label, content);
        case 'techniques': return renderTechniquesBlock(s.label);
        case 'iocs':       return renderIocsBlock(s.label);
        default: return '';
      }
    })
    .join('');

  // ── Optional framing blocks ───────────────────────────────────────────────
  const preambleBlock = opts.customPreamble?.trim() ? `
          <table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
            <tr>
              <td bgcolor="#f8fafc" style="border-left:4px solid #94a3b8;padding:12px 16px;background-color:#f8fafc;">
                <p style="margin:0;color:#475569;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.65;font-style:italic;">${markdownNl2br(opts.customPreamble.trim())}</p>
              </td>
            </tr>
          </table>` : '';

  const audienceIntroBlock = opts.audienceIntro?.trim() ? `
          <table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
            <tr>
              <td bgcolor="#eff6ff" style="border-left:4px solid #2563eb;padding:12px 16px;background-color:#eff6ff;">
                <p style="margin:0;color:#1d4ed8;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.65;font-style:italic;">${markdownNl2br(opts.audienceIntro.trim())}</p>
              </td>
            </tr>
          </table>` : '';

  const signatureBlock = opts.signature?.trim() ? `
          <table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin-bottom:24px;border-top:1px solid #e5e7eb;">
            <tr>
              <td style="padding-top:20px;">
                <p style="margin:0;color:#64748b;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.65;">${markdownNl2br(opts.signature.trim())}</p>
              </td>
            </tr>
          </table>` : '';

  // ── Content area: token template (if set) or the default composition ──────
  // Default path reproduces the original output byte-for-byte.
  const renderOneSection = (s: BriefSection): string => {
    const content = (email[s.key] as string) ?? '';
    switch (s.type) {
      case 'text':       return renderTextBlock(s.label, content);
      case 'bullets':    return renderBulletsBlock(s.label, content);
      case 'numbered':   return renderNumberedBlock(s.label, content);
      case 'techniques': return renderTechniquesBlock(s.label);
      case 'iocs':       return renderIocsBlock(s.label);
      default:           return '';
    }
  };

  const renderTemplatedContent = (tpl: string): string => {
    const fieldValues: Record<string, string> = {
      date: dateStr,
      tlp,
      severity: String(email.severity_badge ?? ''),
      audience: audienceLabel,
      org_name: opts.orgName ?? '',
      analyst_name: opts.analystName ?? '',
      confidence: result.incident_summary?.confidence ?? '',
      incident_title: result.incident_summary?.title ?? '',
      threat_actor_name: result.threat_actor?.name ?? '',
      ioc_count: String(iocCount),
      technique_count: String(techCount),
    };
    const substituteFields = (text: string): string =>
      text.replace(/\{([a-z_]+)\}/g, (m, k: string) => (k in fieldValues ? fieldValues[k] : m));
    const techLabel = sections.find((s) => s.type === 'techniques')?.label ?? 'MITRE ATT&CK Techniques';
    const iocLabel = sections.find((s) => s.type === 'iocs')?.label ?? 'Indicators of Compromise';

    const out: string[] = [];
    let prose: string[] = [];
    const flushProse = () => {
      const text = substituteFields(prose.join('\n')).trim();
      prose = [];
      if (!text) return;
      out.push(`
          <table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
            <tr><td style="padding:2px;"><p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.7;color:#374151;">${markdownNl2br(text)}</p></td></tr>
          </table>`);
    };

    for (const rawLine of tpl.split('\n')) {
      const line = rawLine.trim();
      const blockMatch = line.match(/^\{\{([A-Z_]+(?::[a-z0-9_]+)?)\}\}$/);
      if (blockMatch) {
        flushProse();
        const tok = blockMatch[1];
        if (tok.startsWith('SECTION:')) {
          const sec = sections.find((s) => s.key === tok.slice(8) && s.enabled);
          if (sec) out.push(renderOneSection(sec));
        } else if (tok === 'SECTIONS') {
          out.push(sectionBlocks);
        } else if (tok === 'TECHNIQUES_TABLE') {
          out.push(renderTechniquesBlock(techLabel));
        } else if (tok === 'IOCS_TABLE') {
          out.push(renderIocsBlock(iocLabel));
        } else if (tok === 'PREAMBLE') {
          out.push(preambleBlock);
        } else if (tok === 'AUDIENCE_INTRO') {
          out.push(audienceIntroBlock);
        } else if (tok === 'SIGNATURE') {
          out.push(signatureBlock);
        } else {
          prose.push(rawLine); // unknown {{TOKEN}} → treat as literal text
        }
        continue;
      }
      if (line === '') { flushProse(); continue; }
      prose.push(rawLine);
    }
    flushProse();
    return out.join('');
  };

  const contentArea = opts.template?.trim()
    ? renderTemplatedContent(opts.template)
    : [preambleBlock, audienceIntroBlock, sectionBlocks, signatureBlock].join('\n          ');

  const htmlOut = `<!DOCTYPE html>
<html lang="${esc(T.lang)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>${displayTitle}</title>
</head>
<body style="margin:0;padding:0;background-color:#eef0f3;font-family:Arial,Helvetica,sans-serif;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
<!--[if mso]><xml><o:OfficeDocumentSettings><o:AllowPNG/><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]-->

<table width="100%" border="0" cellpadding="0" cellspacing="0" bgcolor="#eef0f3" style="background-color:#eef0f3;min-width:100%;">
  <tr>
    <td align="center" valign="top" bgcolor="#eef0f3" style="padding:28px 12px;">
    <!--[if mso]><table width="100%" align="center" cellpadding="0" cellspacing="0"><tr><td><![endif]-->
    <table width="100%" border="0" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="width:100%;background-color:#ffffff;">

      <!-- TLP Classification Banner -->
      <tr>
        <td bgcolor="${esc(tlpColor)}" style="background-color:${esc(tlpColor)};padding:8px 24px;">
          <table width="100%" border="0" cellpadding="0" cellspacing="0">
            <tr>
              <td>
                <span style="color:#ffffff;font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:bold;letter-spacing:2px;">&#9632; TLP:${esc(tlp)}</span>
              </td>
              <td align="right">
                <span style="color:rgba(255,255,255,0.75);font-family:Arial,Helvetica,sans-serif;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;">${esc(T.headerSubtitle)}</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Dark Header -->
      <tr>
        <td bgcolor="${esc(secondaryColor)}" style="background-color:${esc(secondaryColor)};padding:28px 24px 26px 24px;">
          <table width="100%" border="0" cellpadding="0" cellspacing="0">
            <tr>
              <td valign="top">${opts.logoDataUri ? `
                ${T.logoLink ? `<a href="${esc(T.logoLink)}" target="_blank" style="text-decoration:none;">` : ''}<img src="${esc(opts.logoDataUri)}" alt="${esc(T.logoAlt)}" width="${T.logoMaxWidth}" height="${T.logoMaxHeight}" style="width:${T.logoMaxWidth}px;height:auto;max-height:${T.logoMaxHeight}px;max-width:${T.logoMaxWidth}px;display:block;margin-bottom:12px;object-fit:contain;" />${T.logoLink ? '</a>' : ''}` : ''}
                <p style="margin:0 0 8px 0;color:#475569;font-family:Arial,Helvetica,sans-serif;font-size:10px;font-weight:bold;letter-spacing:3px;text-transform:uppercase;">${esc(headerTitle)}</p>
                <p style="margin:0 0 20px 0;color:#f1f5f9;font-family:Arial,Helvetica,sans-serif;font-size:22px;font-weight:bold;line-height:1.3;">${displayTitle}</p>
                <table border="0" cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="padding-right:16px;">
                      <span style="color:#94a3b8;font-family:Arial,Helvetica,sans-serif;font-size:12px;">${esc(dateStr)}</span>
                    </td>
                    <td style="padding:0 16px;border-left:1px solid #1e293b;">
                      <span style="color:#94a3b8;font-family:Arial,Helvetica,sans-serif;font-size:12px;">For: ${esc(audienceLabel)}</span>
                    </td>
                    <td style="padding-left:16px;border-left:1px solid #1e293b;">
                      <span style="color:#94a3b8;font-family:Arial,Helvetica,sans-serif;font-size:12px;">${techCount} Technique${techCount !== 1 ? 's' : ''} &nbsp;&bull;&nbsp; ${iocCount} IOC${iocCount !== 1 ? 's' : ''}</span>
                    </td>
                  </tr>
                </table>
              </td>
              <td valign="top" align="right" width="110" style="padding-left:24px;">
                <table border="0" cellpadding="0" cellspacing="0" align="right">
                  <tr>
                    <td align="center" bgcolor="${esc(severityColor)}" style="background-color:${esc(severityColor)};padding:11px 20px;">
                      <p style="margin:0;color:#ffffff;font-family:Arial,Helvetica,sans-serif;font-size:14px;font-weight:bold;letter-spacing:0.5px;white-space:nowrap;">${esc(email.severity_badge as string)}</p>
                    </td>
                  </tr>
                  <tr>
                    <td align="center" bgcolor="${esc(secondaryColor)}" style="padding-top:7px;">
                      <span style="color:#475569;font-family:Arial,Helvetica,sans-serif;font-size:10px;letter-spacing:1px;text-transform:uppercase;">Severity</span>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Severity stripe -->
      <tr>
        <td height="5" bgcolor="${esc(severityColor)}" style="background-color:${esc(severityColor)};font-size:0;line-height:0;">&nbsp;</td>
      </tr>

      <!-- Main white content -->
      <tr>
        <td bgcolor="#ffffff" style="background-color:#ffffff;padding:28px 24px 4px 24px;">

          ${contentArea}

        </td>
      </tr>

      <!-- Dark Footer -->
      <tr>
        <td bgcolor="${esc(secondaryColor)}" style="background-color:${esc(secondaryColor)};padding:16px 24px;">
          <table width="100%" border="0" cellpadding="0" cellspacing="0">
            <tr>
              <td valign="middle">
                <span style="display:inline-block;background-color:${esc(tlpColor)};color:#ffffff;font-family:Arial,Helvetica,sans-serif;font-size:10px;font-weight:bold;padding:4px 10px;letter-spacing:1.5px;">TLP:${esc(tlp)}</span>
              </td>
              <td align="right" valign="middle">
                <p style="margin:0;color:#475569;font-family:Arial,Helvetica,sans-serif;font-size:11px;line-height:1.5;">${footerLine}</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>

    </table>
    <!--[if mso]></td></tr></table><![endif]-->
    </td>
  </tr>
</table>

</body>
</html>`;

  // Apply theme (brand colors + font) via post-process swaps. Defaults preserve
  // the original template byte-for-byte when no customization is set.
  return applyTheme(htmlOut, T);
}

/** Allowed email-safe font stacks, keyed by display name. */
const EMAIL_FONT_STACKS: Record<string, string> = {
  'Arial': 'Arial,Helvetica,sans-serif',
  'Georgia': 'Georgia,Times New Roman,serif',
  'Verdana': 'Verdana,Geneva,sans-serif',
  'Tahoma': 'Tahoma,Geneva,sans-serif',
  'Trebuchet MS': "'Trebuchet MS',Helvetica,sans-serif",
  'Times New Roman': "'Times New Roman',Times,serif",
};

/**
 * Apply a resolved theme to the rendered HTML via post-process string swaps.
 * Each default equals the literal used in the template, so the SNR default theme
 * leaves the output byte-for-byte identical.
 */
function applyTheme(html: string, theme: EmailTheme): string {
  let out = html;
  const swap = (from: string, to: string) => {
    if (to && to !== from) out = out.split(from).join(to);
  };
  // Brand colors (each hex is single-purpose in the template).
  swap('#eef0f3', theme.pageBg);
  swap('#374151', theme.bodyText);
  swap('#1e3a5f', theme.tableHeaderBg);
  swap('#bfdbfe', theme.tableHeaderText);
  // Typography.
  const stack = EMAIL_FONT_STACKS[theme.fontFamily];
  if (stack && stack !== 'Arial,Helvetica,sans-serif') {
    out = out.split('font-family:Arial,Helvetica,sans-serif').join(`font-family:${stack}`);
  }
  const size = parseInt(theme.bodyFontSize, 10);
  if (!Number.isNaN(size) && size >= 12 && size <= 16 && size !== 14) {
    out = out.split('font-size:14px').join(`font-size:${size}px`);
  }
  return out;
}

// ── Plain text builder ────────────────────────────────────────────────────────

function buildPlainText(opts: {
  email: AnalysisResult['email_content'];
  audienceLabel: string;
  tlp: string;
  result: AnalysisResult;
  sections?: BriefSection[];
  headerText?: string;
  footerText?: string;
  signature?: string;
  customPreamble?: string;
  audienceIntro?: string;
}): string {
  const { email, audienceLabel, tlp, result } = opts;
  const sections = opts.sections ?? DEFAULT_SECTIONS;
  const sep = '='.repeat(72);
  const dash = '-'.repeat(72);
  const headerTitle = opts.headerText?.trim() || 'SIGNAL TO NOISE';
  const footerLine = opts.footerText?.trim() || 'Generated by SNR (Signal-to-Noise)';

  // Strip markdown for plain text output
  const stripMd = (s: string) => s
    .replace(/\*\*\*([^*]+)\*\*\*/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/__([^_]+)__/g, '$1')
    .replace(/_([^_]+)_/g, '$1')
    .replace(/`([^`]+)`/g, '$1');

  const lines: string[] = [
    sep,
    `TLP:${tlp} — Handle per your organization's data classification policy`,
    sep,
    `${headerTitle} — Security Intelligence Brief`,
    `FOR: ${audienceLabel.toUpperCase()} | SEVERITY: ${email.severity_badge}`,
    sep,
    '',
  ];

  if (opts.customPreamble?.trim()) {
    lines.push(stripMd(opts.customPreamble.trim()), '');
  }
  if (opts.audienceIntro?.trim()) {
    lines.push(stripMd(opts.audienceIntro.trim()), '');
  }

  for (const section of sections.filter(s => s.enabled)) {
    if (section.type === 'techniques') {
      if (result.attack_chain.length > 0) {
        lines.push(section.label.toUpperCase(), dash);
        for (const t of result.attack_chain) {
          lines.push(`  ${t.technique_id} — ${t.technique_name}`);
          lines.push(`  Evidence: ${stripMd(t.evidence)}`, '');
        }
      }
    } else if (section.type === 'iocs') {
      if (result.iocs.length > 0) {
        lines.push(section.label.toUpperCase(), dash);
        for (const ioc of result.iocs.slice(0, 15)) {
          lines.push(`  [${ioc.type.toUpperCase()}]  ${defang(ioc.value, ioc.type)}  —  ${ioc.context}`);
        }
        lines.push('');
      }
    } else {
      const content = stripMd((email[section.key] as string) ?? '');
      if (content) {
        lines.push(section.label.toUpperCase(), dash, content, '');
      }
    }
  }

  lines.push(sep);

  if (opts.signature?.trim()) {
    lines.push('', stripMd(opts.signature.trim()), sep);
  }

  lines.push(footerLine);
  return lines.join('\n');
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/** HTML-escape a string (for static/trusted values). Returns '' for null/undefined. */
function esc(str: string | undefined | null): string {
  if (str == null) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Convert simple markdown to HTML with proper HTML escaping.
 * Use for user-generated content (Claude output) that may contain **bold**, *italic*, `code`.
 * Escapes HTML entities FIRST to prevent injection, then converts markdown.
 */
function markdownToHtml(text: string): string {
  // Escape HTML entities first (security: prevents HTML injection)
  const escaped = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
  // Convert markdown patterns to HTML (safe now that entities are escaped)
  return escaped
    .replace(/\*\*\*([^*\n]+)\*\*\*/g, '<strong><em>$1</em></strong>')
    .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*\n]+)\*/g, '<em>$1</em>')
    .replace(/__([^_\n]+)__/g, '<strong>$1</strong>')
    .replace(/_([^_\n]+)_/g, '<em>$1</em>')
    .replace(/`([^`\n]+)`/g, '<code style="font-family:Courier New,Courier,monospace;background-color:#f1f5f9;padding:1px 4px;font-size:12px;">$1</code>')
    // [text](https://url) links — http(s) only, applied after escaping
    .replace(/\[([^\]\n]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2" style="color:#1d4ed8;text-decoration:underline;">$1</a>');
}

/**
 * markdownToHtml + block-level handling: markdown lists ("- item" / "1. item")
 * become real <ul>/<ol> elements; remaining newlines become <br> tags.
 */
function markdownNl2br(text: string): string {
  const lines = text.split('\n');
  const out: string[] = [];
  let listType: 'ul' | 'ol' | null = null;
  let pendingBreak = false;

  const closeList = () => {
    if (listType) {
      out.push(listType === 'ul' ? '</ul>' : '</ol>');
      listType = null;
    }
  };

  for (const line of lines) {
    const bullet = line.match(/^\s*[-*•]\s+(.*)$/);
    const numbered = line.match(/^\s*\d+\.\s+(.*)$/);
    if (bullet || numbered) {
      const wanted: 'ul' | 'ol' = bullet ? 'ul' : 'ol';
      if (listType !== wanted) {
        closeList();
        out.push(wanted === 'ul'
          ? '<ul style="margin:6px 0;padding-left:22px;">'
          : '<ol style="margin:6px 0;padding-left:22px;">');
        listType = wanted;
      }
      out.push(`<li style="margin:3px 0;">${markdownToHtml((bullet ?? numbered)![1])}</li>`);
      pendingBreak = false;
    } else {
      closeList();
      if (pendingBreak) out.push('<br>');
      out.push(markdownToHtml(line));
      pendingBreak = true;
    }
  }
  closeList();
  return out.join('');
}

/**
 * Quoted-Printable encoder (RFC 2045).
 * - Encodes '=' as =3D and any byte outside printable ASCII
 * - Wraps lines at 75 chars with soft line break '=' + CRLF
 * - Preserves hard line breaks as CRLF
 */
function qpEncode(text: string): string {
  // Step 1: encode '=' first (must come before other encoding to avoid double-encoding)
  // Step 2: encode characters outside printable ASCII (0x20–0x7E), keeping tab/CR/LF
  const encoded = text
    .replace(/=/g, '=3D')
    .replace(/[^\x09\x20-\x7e\r\n]/g, (ch) => {
      return `=${ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`;
    });

  // Step 3: wrap lines at 75 chars using soft line break (=\r\n) per RFC 2045
  const inputLines = encoded.split(/\r?\n/);
  const result: string[] = [];

  for (const line of inputLines) {
    if (line.length <= 76) {
      result.push(line);
      continue;
    }
    let rem = line;
    while (rem.length > 76) {
      // Cut at position 75 to leave room for the '=' soft-break character
      let cut = 75;
      // Never split inside a =XX sequence (always exactly 3 chars)
      if (cut >= 1 && rem[cut - 1] === '=') cut -= 1;
      else if (cut >= 2 && rem[cut - 2] === '=') cut -= 2;
      result.push(rem.slice(0, cut) + '=');
      rem = rem.slice(cut);
    }
    result.push(rem);
  }

  return result.join('\r\n');
}
