/**
 * Invisible-character check on tool metadata: Unicode tag block, zero-width,
 * bidi overrides/isolates, word joiners, BOM. Text hidden this way reaches the
 * model but not a human reviewer.
 *
 * Flags invisible characters; does not judge visible text.
 */
import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { AuditLogger } from './audit.js';
import type { Metrics } from './metrics.js';
import { newRequestId } from './util.js';

const HIDDEN = /[\u{E0000}-\u{E007F}\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/gu;

export interface HiddenHit {
  path: string;
  codePoints: string[];
}

export function findHiddenChars(s: string): string[] {
  return [...s.matchAll(HIDDEN)].map((m) => 'U+' + (m[0].codePointAt(0) as number).toString(16).toUpperCase().padStart(4, '0'));
}

/** Scan name, title, description and every string inside inputSchema. */
export function scanTool(tool: Tool): HiddenHit[] {
  const hits: HiddenHit[] = [];
  const walk = (v: unknown, path: string, depth: number): void => {
    if (depth > 50) return;
    if (typeof v === 'string') {
      const codePoints = findHiddenChars(v);
      if (codePoints.length > 0) hits.push({ path, codePoints });
    } else if (Array.isArray(v)) {
      v.forEach((x, i) => walk(x, `${path}[${i}]`, depth + 1));
    } else if (v !== null && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`, depth + 1);
    }
  };
  for (const f of ['name', 'title', 'description'] as const) walk(tool[f], f, 0);
  walk(tool.inputSchema, 'inputSchema', 0);
  return hits;
}

export class HiddenCharGuard {
  /** last findings reported per tool, so rebuilds don't repeat the same event */
  private reported = new Map<string, string>();

  constructor(
    private hide: boolean,
    private audit: AuditLogger,
    private metrics: Metrics,
  ) {}

  /** Audit flagged tools; returns "<server>\0<name>" keys to hide (hideSuspicious only). */
  check(catalogs: Array<{ server: string; tools: Tool[] }>): Set<string> {
    const held = new Set<string>();
    let flagged = 0;
    for (const { server, tools } of catalogs) {
      for (const tool of tools) {
        const hits = scanTool(tool);
        const key = `${server}:${tool.name}`;
        if (hits.length === 0) {
          this.reported.delete(key);
          continue;
        }
        flagged += 1;
        if (this.hide) held.add(`${server}\0${tool.name}`);
        const sig = JSON.stringify(hits);
        if (this.reported.get(key) === sig) continue;
        this.reported.set(key, sig);
        this.audit.log({
          ts: new Date().toISOString(),
          reqId: newRequestId(),
          tool: tool.name,
          server,
          originalTool: tool.name,
          durationMs: 0,
          status: 'hidden_chars',
          policyReason: this.hide ? 'hide_suspicious' : undefined,
          hiddenChars: hits,
        });
      }
    }
    this.metrics.hiddenCharsTools.set({}, flagged);
    return held;
  }
}
