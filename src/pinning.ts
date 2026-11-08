/**
 * Tool-definition pinning (rug-pull guard).
 *
 * A pin is the sha256 of a tool's canonical definition (name, title,
 * description, inputSchema, outputSchema, annotations; keys sorted
 * recursively), keyed "<server>:<originalName>". Pins come from a file written
 * by `mcpgateway pin`, or are taken on first sight at startup (TOFU).
 *
 * Pinning detects definition changes. It cannot detect a server that keeps its
 * definition and changes behaviour.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { AuditLogger } from './audit.js';
import type { Metrics } from './metrics.js';
import { newRequestId } from './util.js';

export type PinningMode = 'off' | 'warn' | 'quarantine';

const PINNED_FIELDS = ['name', 'title', 'description', 'inputSchema', 'outputSchema', 'annotations'] as const;

function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical);
  if (v !== null && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) out[k] = canonical((v as Record<string, unknown>)[k]);
    return out;
  }
  return v;
}

const sha = (v: unknown): string => createHash('sha256').update(JSON.stringify(canonical(v)) ?? 'null').digest('hex');

function definition(tool: Tool): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of PINNED_FIELDS) if ((tool as Record<string, unknown>)[f] !== undefined) out[f] = (tool as Record<string, unknown>)[f];
  return out;
}

export function fingerprint(tool: Tool): string {
  return sha(definition(tool));
}

/** Bytes of a pins file: sorted keys, trailing newline (stable for diffs). */
export function pinsFileContent(catalogs: Array<{ server: string; tools: Tool[] }>): string {
  const pins: Record<string, string> = {};
  for (const c of catalogs) for (const t of c.tools) pins[`${c.server}:${t.name}`] = fingerprint(t);
  return JSON.stringify({ version: 1, pins: canonical(pins) }, null, 2) + '\n';
}

export function loadPinsFile(path: string): Map<string, string> {
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as { version?: unknown; pins?: unknown };
  const pins = parsed.pins;
  if (parsed.version !== 1 || pins === null || typeof pins !== 'object' || !Object.values(pins).every((v) => typeof v === 'string')) {
    throw new Error(`${path}: not a version-1 pins file (regenerate with \`mcpgateway pin\`)`);
  }
  return new Map(Object.entries(pins as Record<string, string>));
}

export class PinGuard {
  private pins: Map<string, string>;
  /** definitions seen matching their pin, so a later change can name its fields */
  private pinnedDefs = new Map<string, Record<string, unknown>>();
  /** last hash reported per tool, so rebuilds don't repeat the same event */
  private reported = new Map<string, string>();
  private tofuPending: boolean;
  private mismatched = new Set<string>();

  constructor(
    private mode: PinningMode,
    file: string | undefined,
    private audit: AuditLogger,
    private metrics: Metrics,
  ) {
    this.pins = file !== undefined ? loadPinsFile(file) : new Map();
    this.tofuPending = file === undefined;
  }

  /** Tools currently not matching their pin. */
  get mismatchCount(): number {
    return this.mismatched.size;
  }

  /**
   * Compare every tool with its pin; audit + count changes. Returns the
   * "<server>\0<name>" keys to hold back (quarantine mode only).
   */
  check(catalogs: Array<{ server: string; tools: Tool[] }>): Set<string> {
    const held = new Set<string>();
    if (this.mode === 'off') return held;
    const tofu = this.tofuPending;
    this.tofuPending = false;
    this.mismatched.clear();
    for (const { server, tools } of catalogs) {
      for (const tool of tools) {
        const key = `${server}:${tool.name}`;
        const def = definition(tool);
        const hash = sha(def);
        const pin = this.pins.get(key);
        if (pin === undefined && tofu) {
          this.pins.set(key, hash);
          this.pinnedDefs.set(key, def);
          continue;
        }
        if (pin === hash) {
          this.pinnedDefs.set(key, def);
          this.reported.delete(key);
          continue;
        }
        if (this.mode === 'quarantine') held.add(`${server}\0${tool.name}`);
        if (pin !== undefined) this.mismatched.add(key);
        if (this.reported.get(key) === hash) continue;
        this.reported.set(key, hash);
        const old = this.pinnedDefs.get(key);
        const fields = old === undefined ? undefined
          : PINNED_FIELDS.filter((f) => sha(old[f]) !== sha(def[f]));
        if (pin !== undefined) this.metrics.pinMismatch.inc({ server });
        this.audit.log({
          ts: new Date().toISOString(),
          reqId: newRequestId(),
          tool: tool.name,
          server,
          originalTool: tool.name,
          durationMs: 0,
          status: pin === undefined ? 'pin_new' : 'pin_mismatch',
          policyReason: this.mode === 'quarantine' ? 'quarantined' : undefined,
          pin: { old: pin, new: hash, fields },
        });
      }
    }
    return held;
  }
}
