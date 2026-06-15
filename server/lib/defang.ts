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
