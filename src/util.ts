/** Small shared helpers. No dependencies. */
import { randomUUID } from 'node:crypto';

/** Unique id for correlating audit records, metrics and error responses. */
export function newRequestId(): string {
  return randomUUID();
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Rejects with `label` after ms; clears the timer when the promise settles. */
export function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

/** Truncate a string, appending a marker so truncation is visible. */
export function truncate(s: string, maxChars: number): { text: string; truncated: boolean } {
  if (s.length <= maxChars) return { text: s, truncated: false };
  return { text: s.slice(0, maxChars) + '…[truncated]', truncated: true };
}

/** JSON.stringify that never throws (circular refs -> placeholder). */
export function safeJsonStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? 'null';
  } catch {
    return '"[unserializable]"';
  }
}

export function nowIso(): string {
  return new Date().toISOString();
}

/**
 * Glob match where only `*` is special (matches any run of characters).
 * Everything else is matched literally, so patterns can never ReDoS.
 */
export function globMatch(pattern: string, value: string): boolean {
  const escaped = pattern.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'));
  return new RegExp(`^${escaped.join('.*')}$`).test(value);
}
