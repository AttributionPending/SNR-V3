/**
 * IOC defanging — render indicators safe for pasting into tickets, emails,
 * and chat without creating live links. Display/copy/export transform only;
 * stored IOC values are never modified.
 */

/** Defang a single IOC value based on its type. */
export function defangIoc(type: string, value: string): string {
  const t = type.toLowerCase();

  if (t === 'ip' || t === 'ipv4' || t === 'ipv6' || t === 'ip_address') {
    // 192.168.1.1 → 192[.]168[.]1[.]1
    return value.replace(/\./g, '[.]');
  }

  if (t === 'url') {
    // https://evil.com/path → hxxps[://]evil[.]com/path
    return value
      .replace(/^http/i, 'hxxp')
      .replace(/:\/\//, '[://]')
      .replace(/\./g, '[.]');
  }

  if (t === 'domain' || t === 'hostname' || t === 'fqdn') {
    // evil.example.com → evil[.]example[.]com
    return value.replace(/\./g, '[.]');
  }

  if (t === 'email' || t === 'email_address') {
    // user@evil.com → user[@]evil[.]com
    return value.replace(/@/g, '[@]').replace(/\./g, '[.]');
  }

  // Hashes, filenames, registry keys, etc. — no defang needed
  return value;
}

/** Types whose values change when defanged (used to show the toggle only when useful). */
export function isDefangableType(type: string): boolean {
  const t = type.toLowerCase();
  return ['ip', 'ipv4', 'ipv6', 'ip_address', 'url', 'domain', 'hostname', 'fqdn', 'email', 'email_address'].includes(t);
}
