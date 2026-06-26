/**
 * Deterministic References extraction.
 *
 * The References section of a brief must list ONLY what the analyst actually
 * provided in the input — never anything the LLM invents. It pulls three kinds
 * of citation from the raw input:
 *   • URLs (http/https)
 *   • CVE identifiers
 *   • explicit `Reference:` / `Source:` lines the analyst wrote
 *
 * SAFETY: CTI input is full of *malicious* URLs/IPs that are indicators (IOCs),
 * not citations. Any candidate URL that matches an extracted IOC (by full value
 * or host) is dropped, so C2/phishing URLs never end up in References. Output is
 * emitted as BARE urls (never markdown links) so the email/report renderer leaves
 * them as plain, non-clickable text.
 */

export const NO_REFERENCES = 'No external references provided.';

/** Strip scheme, leading www., and trailing slash; lowercase. For IOC matching. */
function normalizeHost(value: string): string {
  let v = value.trim().toLowerCase();
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // scheme://
  v = v.replace(/^www\./, '');
  v = v.replace(/\/.*$/, ''); // path onwards → keep host only
  v = v.replace(/:\d+$/, ''); // strip port
  return v;
}

/** Full-URL normalization for dedupe/compare: lowercase, drop trailing slash. */
function normalizeUrl(value: string): string {
  return value.trim().toLowerCase().replace(/\/+$/, '');
}

/**
 * Build the deterministic References block from raw analyst input.
 *
 * @param rawInput  Combined analyst-provided text (siem + log + notes).
 * @param iocValues IOC values extracted in Phase 1 — used to exclude indicators.
 */
export function extractReferences(rawInput: string, iocValues: string[] = []): string {
  const text = rawInput ?? '';

  // Normalized IOC set: each IOC's full value + its host form.
  const iocSet = new Set<string>();
  for (const v of iocValues) {
    if (!v) continue;
    iocSet.add(normalizeUrl(v));
    iocSet.add(normalizeHost(v));
  }

  const seen = new Set<string>();
  const refLines: string[] = [];
  const urls: string[] = [];
  const cves: string[] = [];

  // Explicit Reference:/Source: lines (user-authored — always safe to include).
  const refLineRe = /^[ \t]*(?:references?|sources?)[ \t]*[:\-][ \t]*(.+)$/gim;
  let m: RegExpExecArray | null;
  while ((m = refLineRe.exec(text)) !== null) {
    const val = m[1].trim();
    const key = `ref:${val.toLowerCase()}`;
    if (val && !seen.has(key)) { seen.add(key); refLines.push(val); }
  }

  // URLs (http/https only — defanged IOCs like hxxp / [.] never match).
  const urlRe = /\bhttps?:\/\/[^\s<>"'(){}\[\]]+/gi;
  while ((m = urlRe.exec(text)) !== null) {
    const cleaned = m[0].replace(/[.,;:'")\]}>]+$/, ''); // strip trailing punctuation
    // SAFETY: skip anything flagged as an IOC (C2 / phishing / indicator).
    if (iocSet.has(normalizeUrl(cleaned)) || iocSet.has(normalizeHost(cleaned))) continue;
    const key = `url:${normalizeUrl(cleaned)}`;
    if (!seen.has(key)) { seen.add(key); urls.push(cleaned); }
  }

  // CVE identifiers.
  const cveRe = /\bCVE-\d{4}-\d{4,7}\b/gi;
  while ((m = cveRe.exec(text)) !== null) {
    const cve = m[0].toUpperCase();
    const key = `cve:${cve}`;
    if (!seen.has(key)) { seen.add(key); cves.push(cve); }
  }

  const all = [...refLines, ...urls, ...cves];
  return all.length > 0 ? all.join('\n') : NO_REFERENCES;
}
