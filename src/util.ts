/** Small shared helpers. No dependencies. */
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';

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

const sha = (s: string): Buffer => createHash('sha256').update(s, 'utf8').digest();

/**
 * Constant-time bearer-key lookup. Compares SHA-256 digests (always 32 bytes)
 * and scans every key, so neither the presented key's length nor the position
 * of the matching key leaks through timing.
 */
export function matchKey<K extends { key: string; keyHash?: string; expiresAt?: number }>(keys: K[], presented: string, now: number = Date.now()): K | null {
  const p = sha(presented);
  let found: K | null = null;
  for (const k of keys) {
    const stored = k.keyHash !== undefined ? Buffer.from(k.keyHash.slice('sha256:'.length), 'hex') : sha(k.key);
    // Expiry is checked after the comparison and never changes how long it takes.
    if (timingSafeEqual(p, stored) && found === null && (k.expiresAt === undefined || now < k.expiresAt)) found = k;
  }
  return found;
}

/** The value to put in `keyHash:` for a key. */
export function hashKey(key: string): string {
  return 'sha256:' + sha(key).toString('hex');
}

/**
 * Strip terminal-control, bidi-override and zero-width characters from
 * untrusted text (tool descriptions, server names in logs). Replaced with a
 * visible U+FFFD so tampering is evident, not silent.
 */
// eslint-disable-next-line no-control-regex
const HOSTILE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;
export function stripHostile(s: string): { text: string; changed: boolean } {
  const text = s.replace(HOSTILE, '\ufffd');
  return { text, changed: text !== s };
}

/**
 * Escape (do not remove) terminal-control, bidi and zero-width characters in an
 * already-serialized JSON line as \uXXXX. The line parses back to exactly the
 * same data, but `cat`/`less` can no longer be spoofed by what is inside it.
 */
// eslint-disable-next-line no-control-regex
const HOSTILE_IN_JSON = /[\u0080-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;
export function escapeHostileJson(line: string): string {
  return line.replace(HOSTILE_IN_JSON, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

/** Deepest nesting a tool-call argument may have. Real arguments are a few levels deep. */
export const MAX_ARG_DEPTH = 100;

/**
 * True when `value` nests objects/arrays deeper than `max`. Iterative on purpose:
 * a recursive walk is exactly what a 60,000-deep payload would crash.
 */
export function exceedsDepth(value: unknown, max: number = MAX_ARG_DEPTH): boolean {
  if (value === null || typeof value !== 'object') return false;
  const nodes: object[] = [value as object];
  const depths: number[] = [1];
  while (nodes.length > 0) {
    const node = nodes.pop() as object;
    const depth = depths.pop() as number;
    if (depth > max) return true;
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const c: unknown = node[i];
        if (typeof c === 'object' && c !== null) {
          nodes.push(c);
          depths.push(depth + 1);
        }
      }
    } else {
      for (const k in node) {
        const c: unknown = (node as Record<string, unknown>)[k];
        if (typeof c === 'object' && c !== null) {
          nodes.push(c);
          depths.push(depth + 1);
        }
      }
    }
  }
  return false;
}

/**
 * Token of an `Authorization: Bearer <token>` header, or null. The scheme name is
 * case-insensitive (RFC 7235 section 2.1), so `bearer` and `BEARER` are accepted.
 */
export function bearerToken(header: unknown): string | null {
  if (typeof header !== 'string') return null;
  const m = /^bearer +(.*)$/is.exec(header);
  return m === null ? null : (m[1] as string);
}
