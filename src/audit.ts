/**
 * Centralized audit log: append-only JSONL, one record per tool call.
 *
 * Safety properties (scrutiny-relevant):
 *  - Every record is a single JSON-encoded line: args containing newlines can
 *    never break the JSONL framing (log injection impossible by construction).
 *  - Secret-looking argument values are redacted by key-name substring match
 *    (recursive); serialized args are capped with a visible truncation marker.
 *  - The writer NEVER throws into the request path: failures are counted and
 *    exposed via /healthz.
 *  - Size-based rotation with a bounded number of kept files: the audit log
 *    can never fill the disk unboundedly.
 */
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { nowIso, safeJsonStringify, truncate } from './util.js';
import type { AuditConfig } from './config.js';

export type AuditStatus = 'ok' | 'error' | 'denied' | 'rate_limited' | 'timeout' | 'blocked' | 'auth_failed';

export interface AuditRecord {
  ts: string;
  reqId: string;
  sessionId?: string;
  keyId?: string;
  tool: string;
  server: string;
  originalTool: string;
  durationMs: number;
  status: AuditStatus;
  errorCode?: string;
  errorMessage?: string;
  /** redacted + truncated args (omitted when logArgs=false) */
  args?: unknown;
  argsTruncated?: boolean;
  /** sha256 of the canonical args JSON — present when logArgs=false */
  argsHash?: string;
  policyReason?: string;
  redactions?: number;
}

const REDACTED = '[REDACTED]';

export class AuditLogger {
  private bytesWritten = 0;
  private maxBytes: number;
  errors = 0;

  constructor(
    private cfg: AuditConfig,
    private onError?: () => void,
  ) {
    this.maxBytes = cfg.maxSizeMB * 1024 * 1024;
  }

  /** Count a write failure and notify the metrics registry (never throws). */
  private fail(): void {
    this.errors += 1;
    try {
      this.onError?.();
    } catch {
      /* metrics must never break the audit path */
    }
  }

  /** Append one record. Never throws. */
  log(record: AuditRecord): void {
    try {
      this.ensureOpen();
      const line = safeJsonStringify(this.prepare(record)) + '\n';
      appendFileSync(this.cfg.path, line, { encoding: 'utf8' });
      this.bytesWritten += Buffer.byteLength(line);
      if (this.bytesWritten >= this.maxBytes) this.rotate();
    } catch {
      this.fail();
    }
  }

  close(): void {
    // appendFileSync opens/closes per write; nothing to flush.
  }

  private ensureOpen(): void {
    try {
      this.bytesWritten = statSync(this.cfg.path).size;
    } catch {
      this.bytesWritten = 0;
      // Prove the path is writable now rather than failing silently forever.
      try {
        writeFileSync(this.cfg.path, '', { flag: 'a' });
      } catch {
        throw new Error(`cannot write audit log at ${this.cfg.path}`);
      }
    }
  }

  private prepare(record: AuditRecord): AuditRecord {
    const out: AuditRecord = { ...record, ts: record.ts || nowIso() };
    if (this.cfg.logArgs && record.args !== undefined) {
      const redacted = redactDeep(record.args, this.cfg.redactKeys);
      const serialized = safeJsonStringify(redacted);
      const { text, truncated } = truncate(serialized, this.cfg.maxArgsChars);
      // Store the (possibly truncated) JSON string form: re-parsing truncated
      // JSON would be lossy and could throw, so keep it as a string.
      out.args = text;
      out.argsTruncated = truncated || undefined;
    } else if (!this.cfg.logArgs && record.args !== undefined) {
      out.argsHash = 'sha256:' + createHash('sha256').update(safeJsonStringify(record.args)).digest('hex');
      delete out.args;
    }
    return out;
  }

  private rotate(): void {
    try {
      // mcpgateway-audit.jsonl -> .1 (newest), shift older ones, drop beyond keep.
      for (let i = this.cfg.keepFiles - 1; i >= 1; i--) {
        const older = `${this.cfg.path}.${i}`;
        const newer = `${this.cfg.path}.${i + 1}`;
        if (existsSync(older)) {
          if (i + 1 > this.cfg.keepFiles) unlinkSync(older);
          else renameSync(older, newer);
        }
      }
      if (existsSync(this.cfg.path)) renameSync(this.cfg.path, `${this.cfg.path}.1`);
      // Drop the file that would exceed keepFiles (the loop above leaves
      // .keepFiles+1 only when keepFiles files already existed; clean it).
      const overflow = `${this.cfg.path}.${this.cfg.keepFiles + 1}`;
      if (existsSync(overflow)) unlinkSync(overflow);
      this.bytesWritten = 0;
    } catch {
      this.fail();
    }
  }
}

/** Recursively redact values whose key contains a redact substring (case-insensitive). */
export function redactDeep(value: unknown, redactKeys: string[]): unknown {
  const lowered = redactKeys.map((k) => k.toLowerCase());
  const shouldRedact = (key: string): boolean => {
    const lk = key.toLowerCase();
    return lowered.some((rk) => rk.length > 0 && lk.includes(rk));
  };
  const walk = (v: unknown, depth: number): unknown => {
    if (depth > 50) return REDACTED; // pathological nesting guard
    if (Array.isArray(v)) return v.map((item) => walk(item, depth + 1));
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v)) {
        out[k] = shouldRedact(k) ? REDACTED : walk(val, depth + 1);
      }
      return out;
    }
    return v;
  };
  return walk(value, 0);
}

/**
 * Collect the actual secret VALUES from a call's args (values of keys that
 * matched the redact list). Used to scrub those values out of downstream
 * error messages, which otherwise echo secrets into the audit log and the
 * agent-facing error. Only values >= 8 chars are collected, so redacting
 * them elsewhere can never nuke ordinary words.
 */
export function collectSecretValues(args: unknown, redactKeys: string[]): string[] {
  const lowered = redactKeys.map((k) => k.toLowerCase()).filter((k) => k.length > 0);
  const values = new Set<string>();
  const walk = (v: unknown, depth: number): void => {
    if (depth > 50 || values.size >= 100) return;
    if (Array.isArray(v)) {
      for (const item of v) walk(item, depth + 1);
      return;
    }
    if (v !== null && typeof v === 'object') {
      for (const [k, val] of Object.entries(v)) {
        const lk = k.toLowerCase();
        if (typeof val === 'string' && val.length >= 8 && lowered.some((rk) => lk.includes(rk))) {
          values.add(val);
        } else {
          walk(val, depth + 1);
        }
      }
    }
  };
  walk(args, 0);
  return [...values];
}

/** Replace every occurrence of each secret value with [REDACTED]. */
export function redactSecretValues(text: string, secrets: string[]): string {
  let out = text;
  for (const s of secrets) {
    if (s.length === 0) continue;
    let idx = out.indexOf(s);
    while (idx !== -1) {
      out = out.slice(0, idx) + REDACTED + out.slice(idx + s.length);
      idx = out.indexOf(s, idx + REDACTED.length);
    }
  }
  return out;
}
