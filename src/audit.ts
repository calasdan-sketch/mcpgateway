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
import { createHash, createHmac } from 'node:crypto';
import { appendFileSync, closeSync, existsSync, openSync, readFileSync, readSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
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
  /** hash chain (audit.chain): monotonically increasing sequence number */
  seq?: number;
  /** hash of the previous record */
  prev?: string;
  /** hash over this record (excluding this field) chained to prev */
  hash?: string;
}

const REDACTED = '[REDACTED]';

export class AuditLogger {
  private bytesWritten = 0;
  private maxBytes: number;
  errors = 0;
  private seq = 0;
  private lastHash = 'genesis';
  private chainLoaded = false;

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
      let prepared = this.prepare(record);
      if (this.cfg.chain === true) prepared = this.chain(prepared);
      const line = safeJsonStringify(prepared) + '\n';
      appendFileSync(this.cfg.path, line, { encoding: 'utf8' });
      // Commit chain state only after the write succeeded, so a transient disk
      // error cannot leave a phantom link that later reads as tampering.
      if (this.cfg.chain === true && prepared.seq !== undefined && prepared.hash !== undefined) {
        this.seq = prepared.seq;
        this.lastHash = prepared.hash;
      }
      this.bytesWritten += Buffer.byteLength(line);
      if (this.bytesWritten >= this.maxBytes) this.rotate();
    } catch {
      this.fail();
    }
  }

  /** Current chain head (for external anchoring). */
  head(): { seq: number; hash: string } {
    if (this.cfg.chain === true && !this.chainLoaded) this.loadChainHead();
    return { seq: this.seq, hash: this.lastHash };
  }

  private chain(rec: AuditRecord): AuditRecord {
    if (!this.chainLoaded) this.loadChainHead();
    const body: AuditRecord = { ...rec, seq: this.seq + 1, prev: this.lastHash };
    const hash = chainHash(this.cfg.chainKey, safeJsonStringify(body));
    return { ...body, hash };
  }

  /** Resume the chain from the tail of the current file, else the newest rotated file. */
  private loadChainHead(): void {
    this.chainLoaded = true;
    for (const f of [this.cfg.path, `${this.cfg.path}.1`]) {
      const tail = lastLine(f);
      if (tail === null) continue;
      try {
        const r = JSON.parse(tail) as AuditRecord;
        if (typeof r.seq === 'number' && typeof r.hash === 'string') {
          this.seq = r.seq;
          this.lastHash = r.hash;
          return;
        }
      } catch {
        /* unparsable tail: start a visibly-broken new segment */
      }
      this.lastHash = 'unverified-tail';
      return;
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

function chainHash(key: string | undefined, text: string): string {
  const h = key !== undefined ? createHmac('sha256', key) : createHash('sha256');
  return (key !== undefined ? 'hmac-sha256:' : 'sha256:') + h.update(text).digest('hex');
}

/** Last non-empty line of a file, reading only the tail. null if missing/empty. */
function lastLine(path: string): string | null {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    return null;
  }
  try {
    const size = statSync(path).size;
    if (size === 0) return null;
    const len = Math.min(size, 65536);
    const buf = Buffer.alloc(len);
    readSync(fd, buf, 0, len, size - len);
    const lines = buf.toString('utf8').split('\n').filter((l) => l.length > 0);
    return lines.length > 0 ? (lines[lines.length - 1] as string) : null;
  } finally {
    closeSync(fd);
  }
}

export interface VerifyResult {
  ok: boolean;
  records: number;
  /** hash the first verified record chained from (anchor for external comparison) */
  anchor?: string;
  head?: { seq: number; hash: string };
  failure?: { file: string; line: number; reason: string };
}

/**
 * Verify a hash chain across files given OLDEST FIRST. Detects edited,
 * reordered, inserted or deleted-in-the-middle records. It cannot detect
 * truncation of the newest records on its own: compare `head` with a value
 * you stored elsewhere (GET /v1/audit/head).
 */
export function verifyChain(files: string[], key?: string): VerifyResult {
  let prev: string | undefined;
  let seq: number | undefined;
  let records = 0;
  let anchor: string | undefined;
  for (const file of files) {
    let text: string;
    try {
      text = readFileSync(file, 'utf8');
    } catch (e) {
      return { ok: false, records, failure: { file, line: 0, reason: `cannot read: ${(e as Error).message}` } };
    }
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i] as string;
      if (raw.length === 0) continue;
      const fail = (reason: string): VerifyResult => ({ ok: false, records, anchor, failure: { file, line: i + 1, reason } });
      let rec: AuditRecord;
      try {
        rec = JSON.parse(raw) as AuditRecord;
      } catch {
        return fail('line is not valid JSON');
      }
      if (typeof rec.seq !== 'number' || typeof rec.prev !== 'string' || typeof rec.hash !== 'string') return fail('record has no chain fields');
      if (prev === undefined) {
        anchor = rec.prev;
      } else {
        if (rec.prev !== prev) return fail('prev hash does not match the preceding record (record removed, inserted or reordered)');
        if (seq !== undefined && rec.seq !== seq + 1) return fail(`sequence jumps from ${seq} to ${rec.seq}`);
      }
      const { hash, ...body } = rec;
      if (key === undefined && hash.startsWith('hmac-sha256:')) return fail('log is HMAC-chained; supply the key');
      if (chainHash(key, safeJsonStringify(body)) !== hash) return fail('hash mismatch (record was modified)');
      prev = hash;
      seq = rec.seq;
      records += 1;
    }
  }
  const result: VerifyResult = { ok: true, records };
  if (anchor !== undefined) result.anchor = anchor;
  if (prev !== undefined && seq !== undefined) result.head = { seq, hash: prev };
  return result;
}
