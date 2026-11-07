/**
 * Tool pinning ("rug-pull" defense).
 *
 * An MCP server controls its own tool descriptions and schemas, and may change
 * them after you approved the server (a tools/list_changed notification is all
 * it takes). Descriptions are read by the model as instructions, so a silent
 * change is a prompt-injection channel. The gateway records a SHA-256 over each
 * tool's description + inputSchema the first time it sees it (trust on first
 * use). A later mismatch is a violation:
 *   warn  — log + metric + audit, keep serving
 *   block — quarantine the tool (hidden and uncallable) until an operator
 *           accepts the new definition (POST /v1/pins/accept, admin scope)
 *
 * Pins are keyed by `<server>:<original tool name>` so renames in the public
 * namespace do not invalidate them. In block mode a missing/corrupt pin file
 * is a startup error, never "trust everything again" (fail closed).
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import type { PinningConfig } from './config.js';
import { safeJsonStringify } from './util.js';

export interface PinInput {
  server: string;
  originalName: string;
  description?: string;
  inputSchema?: unknown;
  /** covered since 0.3.1: a flipped readOnlyHint is as dangerous as a changed description */
  annotations?: unknown;
  outputSchema?: unknown;
  title?: string;
}

export interface PinReport {
  /** keys pinned for the first time this evaluation */
  added: string[];
  /** keys whose definition changed since pinned */
  changed: string[];
  /** pinned keys no longer offered by the server (informational) */
  missing: string[];
}

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(',')}}`;
  }
  return safeJsonStringify(v);
}

export function pinKey(server: string, originalName: string): string {
  return `${server}:${originalName}`;
}

function hasExtras(t: PinInput): boolean {
  return t.annotations !== undefined || t.outputSchema !== undefined || t.title !== undefined;
}

/** Hash over description + inputSchema only (the 0.3.0 definition, kept for pin-file upgrades). */
export function legacyDefinitionHash(t: PinInput): string {
  return 'sha256:' + createHash('sha256').update(canonical({ d: t.description ?? '', s: t.inputSchema ?? null })).digest('hex');
}

/**
 * Description + inputSchema + (when present) annotations, outputSchema, title.
 * A tool without extras hashes exactly as in 0.3.0, so existing pin files stay valid.
 */
export function definitionHash(t: PinInput): string {
  if (!hasExtras(t)) return legacyDefinitionHash(t);
  const x = { a: t.annotations ?? null, o: t.outputSchema ?? null, t: t.title ?? null };
  return 'sha256:' + createHash('sha256').update(canonical({ d: t.description ?? '', s: t.inputSchema ?? null, x })).digest('hex');
}

export class PinRegistry {
  private pins = new Map<string, string>();
  /** keys currently in violation (hash differs from the pin) */
  private violations = new Map<string, string>();
  private latest = new Map<string, string>();
  /** pin file written by 0.3.0 (hashes cover description + schema only) */
  private legacyFile = false;

  constructor(private cfg: PinningConfig) {
    if (cfg.mode === 'off' || cfg.file === undefined) return;
    if (!existsSync(cfg.file)) return; // first run: TOFU will create it
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(cfg.file, 'utf8'));
    } catch (e) {
      throw new Error(`policy.pinning.file "${cfg.file}" is unreadable or not valid JSON (${(e as Error).message}) — refusing to start rather than re-trust every tool`);
    }
    const pins = (parsed as { pins?: unknown } | null)?.pins;
    if (pins === null || typeof pins !== 'object' || Array.isArray(pins)) {
      throw new Error(`policy.pinning.file "${cfg.file}" has no "pins" object — refusing to start`);
    }
    this.legacyFile = (parsed as { version?: unknown }).version === 1;
    for (const [k, v] of Object.entries(pins as Record<string, unknown>)) {
      if (typeof v !== 'string' || !v.startsWith('sha256:')) throw new Error(`policy.pinning.file "${cfg.file}": bad hash for "${k}"`);
      this.pins.set(k, v);
    }
  }

  get mode(): PinningConfig['mode'] {
    return this.cfg.mode;
  }

  evaluate(tools: PinInput[]): PinReport {
    const report: PinReport = { added: [], changed: [], missing: [] };
    if (this.cfg.mode === 'off') return report;
    this.violations.clear();
    this.latest.clear();
    const seen = new Set<string>();
    for (const t of tools) {
      const key = pinKey(t.server, t.originalName);
      seen.add(key);
      const h = definitionHash(t);
      this.latest.set(key, h);
      const pinned = this.pins.get(key);
      if (pinned === undefined) {
        this.pins.set(key, h);
        report.added.push(key);
      } else if (pinned !== h && this.legacyFile && hasExtras(t) && pinned === legacyDefinitionHash(t)) {
        // One-time upgrade of a 0.3.0 pin file: description + schema still match,
        // the annotations are simply new to the pin. Trusted on first sight, then
        // the file is rewritten as version 2 and this path closes for good.
        this.pins.set(key, h);
        report.added.push(key);
      } else if (pinned !== h) {
        this.violations.set(key, h);
        report.changed.push(key);
      }
    }
    for (const k of this.pins.keys()) if (!seen.has(k)) report.missing.push(k);
    // The upgrade window is exactly one evaluation; rewrite as version 2 and close it.
    if (report.added.length > 0 || this.legacyFile) this.save();
    this.legacyFile = false;
    return report;
  }

  /** Should this tool be withheld right now? Only in block mode. */
  quarantined(server: string, originalName: string): boolean {
    return this.cfg.mode === 'block' && this.violations.has(pinKey(server, originalName));
  }

  violationKeys(): string[] {
    return [...this.violations.keys()];
  }

  /** Accept the current definition of one tool (or all violations). Returns accepted keys. */
  accept(key?: string): string[] {
    const accepted: string[] = [];
    for (const k of [...this.violations.keys()]) {
      if (key !== undefined && k !== key) continue;
      const h = this.latest.get(k);
      if (h !== undefined) {
        this.pins.set(k, h);
        this.violations.delete(k);
        accepted.push(k);
      }
    }
    if (accepted.length > 0) this.save();
    return accepted;
  }

  private save(): void {
    if (this.cfg.file === undefined) return;
    const tmp = `${this.cfg.file}.tmp`;
    const body = JSON.stringify({ version: 2, pins: Object.fromEntries([...this.pins].sort(([a], [b]) => (a < b ? -1 : 1))) }, null, 2);
    writeFileSync(tmp, body, { encoding: 'utf8', mode: 0o600 });
    renameSync(tmp, this.cfg.file);
  }
}

/**
 * Heuristic scan for instruction-like content in tool descriptions. This is a
 * tripwire for obvious poisoning, NOT a guarantee — pinning is the control.
 */
const SUSPICIOUS: Array<[RegExp, string]> = [
  [/<\s*(important|system|instructions?)\s*>/i, 'pseudo-tag addressed to the model'],
  [/ignore (all |any )?(previous|prior|above) (instructions|rules)/i, 'override-instructions phrase'],
  [/do not (tell|inform|mention|reveal)[^.]{0,40}\buser\b/i, 'conceal-from-user phrase'],
  [/\.(ssh|aws)\/|id_rsa|\.env\b/i, 'references credential files'],
];

export function suspiciousDescription(description: string | undefined): string[] {
  if (description === undefined) return [];
  const hits: string[] = [];
  for (const [re, label] of SUSPICIOUS) if (re.test(description)) hits.push(label);
  if (description.length > 4000) hits.push('unusually long description (>4000 chars)');
  return hits;
}
