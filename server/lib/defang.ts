/**
 * Defang network IOC values so recipients can't accidentally navigate to
 * malicious infrastructure. Applied in human-readable outputs (email, report)
 * but NOT in machine-readable formats (STIX, Navigator).
 *
 * Transformations:
 *   ipv4      →  dots wrapped:  192[.]168[.]1[.]1
 *   ipv6      →  colons wrapped: 2001[:]db8[:]:[:]1
 *   domain    →  dots wrapped:  evil[.]com
 *   url       →  scheme + dots: hxxps[:]//evil[.]com/path
 *   email     →  @ and dots:   user[@]evil[.]com
 *   (others)  →  unchanged
 */

const NETWORK_TYPES = new Set(['ipv4', 'ipv6', 'domain', 'url', 'email']);

export function defang(value: string, type: string): string {
  const t = type.toLowerCase();
  if (!NETWORK_TYPES.has(t)) return value;

  if (t === 'url') {
    return value
      .replace(/^https:\/\//i, 'hxxps[:]//') // scheme
      .replace(/^http:\/\//i,  'hxxp[:]//') // scheme
      .replace(/\./g, '[.]');               // dots in host + path
  }

  if (t === 'email') {
    return value
      .replace(/@/g, '[@]')
      .replace(/\./g, '[.]');
  }

  if (t === 'ipv4' || t === 'domain') {
    return value.replace(/\./g, '[.]');
  }

  if (t === 'ipv6') {
    return value.replace(/:/g, '[:]');
  }

  return value;
}

/**
 * Reverse common defang notations back to a canonical, machine-usable value.
 * Analysts and feeds routinely submit indicators defanged (evil[.]com,
 * hxxps://evil[.]com, user[@]evil[.]com); left as-is they fail format
 * validation and are dropped from STIX/Navigator/CSV exports. Refang at
 * ingestion so the stored value is canonical — the UI re-defangs for display.
 *
 * Applied to network types only, so a literal '[.]' inside a filename/registry
 * value is never touched. Conservative: only well-known bracket/word notations.
 */
export function refang(value: string, type: string): string {
  const t = type.toLowerCase();
  if (!NETWORK_TYPES.has(t)) return value;

  let v = value.trim();
  // Scheme: hxxp / hXXp / hxxps → http / https
  v = v.replace(/h[xX]{2}p(s?)(?=:|\[:)/g, 'http$1');
  v = v.replace(/h[xX]{2}p(s?):/g, 'http$1:');
  // Dot: [.] (.) {.} [dot] (dot) — with or without surrounding spaces
  v = v.replace(/\s*[[({]\s*(?:\.|dot)\s*[\])}]\s*/gi, '.');
  // Colon: [:] (:)
  v = v.replace(/[[(]\s*:\s*[\])]/g, ':');
  // At-sign: [@] (@) [at]
  v = v.replace(/\s*[[(]\s*(?:@|at)\s*[\])]\s*/gi, '@');
  // Scheme separator: [://]
  v = v.replace(/[[(]\s*:\/\/\s*[\])]/g, '://');
  return v;
}
