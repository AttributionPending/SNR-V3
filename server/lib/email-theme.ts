/**
 * Email theme model for white-label branding.
 *
 * A theme is the visual identity applied to a rendered email. SNR_DEFAULT_THEME
 * holds the exact values the renderer used before theming existed, so the default
 * theme reproduces the original output byte-for-byte. Brand profiles supply a
 * partial theme that overrides these via resolveTheme().
 */

export interface EmailTheme {
  // Brand colors
  primary: string;          // accent bars, bullets, technique IDs
  secondary: string;        // dark header background + numbered-section header
  pageBg: string;           // outer page background
  bodyText: string;         // body paragraph text
  tableHeaderBg: string;    // technique/IOC table header background
  tableHeaderText: string;  // technique/IOC table header text
  // Chrome / text
  headerTitle: string;      // small uppercase eyebrow above the title
  headerSubtitle: string;   // top-right banner label (was hardcoded)
  footerText: string;       // '' => use the default (vendor-attribution-aware)
  showVendorAttribution: boolean; // when false, the default footer omits "SNR"
  // Logo
  logoDataUri: string;      // per-profile logo image ('' => fall back to the legacy logo opt)
  logoAlt: string;
  logoLink: string;         // '' => image is not wrapped in a link
  logoMaxWidth: number;
  logoMaxHeight: number;
  // Typography (fontFamily is a display-name key in EMAIL_FONT_STACKS)
  fontFamily: string;
  bodyFontSize: string;
  lang: string;
}

export const SNR_DEFAULT_THEME: EmailTheme = {
  primary: '#1d4ed8',
  secondary: '#0a0f1e',
  pageBg: '#eef0f3',
  bodyText: '#374151',
  tableHeaderBg: '#1e3a5f',
  tableHeaderText: '#bfdbfe',
  headerTitle: 'SIGNAL TO NOISE',
  headerSubtitle: 'Security Intelligence Brief',
  footerText: '',
  showVendorAttribution: true,
  logoDataUri: '',
  logoAlt: 'Logo',
  logoLink: '',
  logoMaxWidth: 240,
  logoMaxHeight: 80,
  fontFamily: 'Arial',
  bodyFontSize: '14',
  lang: 'en',
};

// Empty strings fall back to the default for identity fields, but are meaningful
// (kept) for footerText / logoLink.
const KEEP_EMPTY = new Set<keyof EmailTheme>(['footerText', 'logoLink']);

/** Merge a partial theme over the SNR default, ignoring undefined/blank values. */
export function resolveTheme(partial?: Partial<EmailTheme> | null): EmailTheme {
  const out: EmailTheme = { ...SNR_DEFAULT_THEME };
  if (!partial) return out;
  for (const [k, v] of Object.entries(partial) as [keyof EmailTheme, unknown][]) {
    if (v === undefined || v === null) continue;
    if (typeof v === 'string' && v.trim() === '' && !KEEP_EMPTY.has(k)) continue;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (out as any)[k] = v;
  }
  return out;
}
