import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatTimestamp(ms: number): string {
  const d = new Date(ms);
  return d.toLocaleDateString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export function severityDot(severity: string): string {
  const map: Record<string, string> = {
    Critical: 'bg-red-500',
    High: 'bg-red-400',
    Medium: 'bg-orange-400',
    Low: 'bg-green-400',
    Informational: 'bg-blue-400',
  };
  return map[severity] ?? 'bg-gray-400';
}

export function truncate(str: string, n: number): string {
  return str.length > n ? str.slice(0, n) + '…' : str;
}
