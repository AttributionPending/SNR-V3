/**
 * Default email body template used by the Email Template editor (Settings) and
 * as the server-side fallback. Controls the email's CONTENT AREA only — the
 * TLP banner, dark header, severity badge, and footer remain branded chrome
 * driven by the Email Branding settings.
 *
 * Field tokens (single inline values):
 *   {date} {tlp} {severity} {audience} {org_name} {analyst_name}
 *   {confidence} {incident_title} {threat_actor_name} {ioc_count} {technique_count}
 *
 * Block tokens (replaced with rendered HTML blocks):
 *   {{SECTIONS}}          — all enabled brief sections, in Brief-Sections order
 *   {{SECTION:key}}       — one specific section by its config key
 *   {{TECHNIQUES_TABLE}}  — the ATT&CK techniques table
 *   {{IOCS_TABLE}}        — the IOC table
 *   {{PREAMBLE}}          — the custom preamble block (Email Branding)
 *   {{AUDIENCE_INTRO}}    — the audience-specific intro block
 *   {{SIGNATURE}}         — the signature block (Email Branding)
 *
 * Any text between tokens is rendered as a styled paragraph, with {field}
 * tokens substituted inline.
 *
 * The default below reproduces the current hardcoded content area exactly:
 * preamble → audience intro → all sections → signature.
 */
export const DEFAULT_EMAIL_TEMPLATE = `{{PREAMBLE}}
{{AUDIENCE_INTRO}}
{{SECTIONS}}
{{SIGNATURE}}
`;

export const EMAIL_FIELD_TOKENS = [
  'date', 'tlp', 'severity', 'audience', 'org_name', 'analyst_name',
  'confidence', 'incident_title', 'threat_actor_name', 'ioc_count', 'technique_count',
] as const;

export const EMAIL_BLOCK_TOKENS = [
  'SECTIONS', 'TECHNIQUES_TABLE', 'IOCS_TABLE', 'PREAMBLE', 'AUDIENCE_INTRO', 'SIGNATURE',
] as const;

export type EmailFieldToken = typeof EMAIL_FIELD_TOKENS[number];
export type EmailBlockToken = typeof EMAIL_BLOCK_TOKENS[number];
