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
import { safeJsonStringify } from './util.js';
function canonical(v) {
    if (Array.isArray(v))
        return `[${v.map(canonical).join(',')}]`;
    if (v !== null && typeof v === 'object') {
        const o = v;
        return `{${Object.keys(o)
            .sort()
            .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
            .join(',')}}`;
    }
    return safeJsonStringify(v);
}
export function pinKey(server, originalName) {
    return `${server}:${originalName}`;
}
export function definitionHash(t) {
    return 'sha256:' + createHash('sha256').update(canonical({ d: t.description ?? '', s: t.inputSchema ?? null })).digest('hex');
}
export class PinRegistry {
    cfg;
    pins = new Map();
    /** keys currently in violation (hash differs from the pin) */
    violations = new Map();
    latest = new Map();
    constructor(cfg) {
        this.cfg = cfg;
        if (cfg.mode === 'off' || cfg.file === undefined)
            return;
        if (!existsSync(cfg.file))
            return; // first run: TOFU will create it
        let parsed;
        try {
            parsed = JSON.parse(readFileSync(cfg.file, 'utf8'));
        }
        catch (e) {
            throw new Error(`policy.pinning.file "${cfg.file}" is unreadable or not valid JSON (${e.message}) — refusing to start rather than re-trust every tool`);
        }
        const pins = parsed?.pins;
        if (pins === null || typeof pins !== 'object' || Array.isArray(pins)) {
            throw new Error(`policy.pinning.file "${cfg.file}" has no "pins" object — refusing to start`);
        }
        for (const [k, v] of Object.entries(pins)) {
            if (typeof v !== 'string' || !v.startsWith('sha256:'))
                throw new Error(`policy.pinning.file "${cfg.file}": bad hash for "${k}"`);
            this.pins.set(k, v);
        }
    }
    get mode() {
        return this.cfg.mode;
    }
    evaluate(tools) {
        const report = { added: [], changed: [], missing: [] };
        if (this.cfg.mode === 'off')
            return report;
        this.violations.clear();
        this.latest.clear();
        const seen = new Set();
        for (const t of tools) {
            const key = pinKey(t.server, t.originalName);
            seen.add(key);
            const h = definitionHash(t);
            this.latest.set(key, h);
            const pinned = this.pins.get(key);
            if (pinned === undefined) {
                this.pins.set(key, h);
                report.added.push(key);
            }
            else if (pinned !== h) {
                this.violations.set(key, h);
                report.changed.push(key);
            }
        }
        for (const k of this.pins.keys())
            if (!seen.has(k))
                report.missing.push(k);
        if (report.added.length > 0)
            this.save();
        return report;
    }
    /** Should this tool be withheld right now? Only in block mode. */
    quarantined(server, originalName) {
        return this.cfg.mode === 'block' && this.violations.has(pinKey(server, originalName));
    }
    violationKeys() {
        return [...this.violations.keys()];
    }
    /** Accept the current definition of one tool (or all violations). Returns accepted keys. */
    accept(key) {
        const accepted = [];
        for (const k of [...this.violations.keys()]) {
            if (key !== undefined && k !== key)
                continue;
            const h = this.latest.get(k);
            if (h !== undefined) {
                this.pins.set(k, h);
                this.violations.delete(k);
                accepted.push(k);
            }
        }
        if (accepted.length > 0)
            this.save();
        return accepted;
    }
    save() {
        if (this.cfg.file === undefined)
            return;
        const tmp = `${this.cfg.file}.tmp`;
        const body = JSON.stringify({ version: 1, pins: Object.fromEntries([...this.pins].sort(([a], [b]) => (a < b ? -1 : 1))) }, null, 2);
        writeFileSync(tmp, body, { encoding: 'utf8', mode: 0o600 });
        renameSync(tmp, this.cfg.file);
    }
}
/**
 * Heuristic scan for instruction-like content in tool descriptions. This is a
 * tripwire for obvious poisoning, NOT a guarantee — pinning is the control.
 */
const SUSPICIOUS = [
    [/<\s*(important|system|instructions?)\s*>/i, 'pseudo-tag addressed to the model'],
    [/ignore (all |any )?(previous|prior|above) (instructions|rules)/i, 'override-instructions phrase'],
    [/do not (tell|inform|mention|reveal)[^.]{0,40}\buser\b/i, 'conceal-from-user phrase'],
    [/\.(ssh|aws)\/|id_rsa|\.env\b/i, 'references credential files'],
];
export function suspiciousDescription(description) {
    if (description === undefined)
        return [];
    const hits = [];
    for (const [re, label] of SUSPICIOUS)
        if (re.test(description))
            hits.push(label);
    if (description.length > 4000)
        hits.push('unusually long description (>4000 chars)');
    return hits;
}
//# sourceMappingURL=pins.js.map