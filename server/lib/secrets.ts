/**
 * Secret resolution with Docker/Kubernetes file-secret support.
 *
 * For each secret we prefer a `${NAME}_FILE` env var pointing at a mounted file
 * (the standard container-secrets convention) and fall back to the plain
 * `${NAME}` env var. This keeps secrets out of `.env` and process listings on
 * hardened on-prem hosts.
 */
import fs from 'fs';

/**
 * Resolve a secret by name. Returns the trimmed file contents of `${name}_FILE`
 * if that env var is set and the file is readable; otherwise `process.env[name]`;
 * otherwise undefined.
 */
export function readSecret(name: string): string | undefined {
  const filePath = process.env[`${name}_FILE`];
  if (filePath) {
    try {
      const v = fs.readFileSync(filePath, 'utf-8').trim();
      if (v) return v;
    } catch {
      // Fall through to the plain env var if the file can't be read
    }
  }
  const direct = process.env[name];
  return direct && direct.length > 0 ? direct : undefined;
}
