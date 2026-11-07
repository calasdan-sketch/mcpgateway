/** Small shared helpers. No dependencies. */
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
/** Unique id for correlating audit records, metrics and error responses. */
export function newRequestId() {
    return randomUUID();
}
export function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
/** Rejects with `label` after ms; clears the timer when the promise settles. */
export function withTimeout(promise, ms, label) {
    let timer;
    const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    });
    return Promise.race([promise, timeout]).finally(() => {
        if (timer !== undefined)
            clearTimeout(timer);
    });
}
/** Truncate a string, appending a marker so truncation is visible. */
export function truncate(s, maxChars) {
    if (s.length <= maxChars)
        return { text: s, truncated: false };
    return { text: s.slice(0, maxChars) + '…[truncated]', truncated: true };
}
/** JSON.stringify that never throws (circular refs -> placeholder). */
export function safeJsonStringify(value) {
    try {
        return JSON.stringify(value) ?? 'null';
    }
    catch {
        return '"[unserializable]"';
    }
}
export function nowIso() {
    return new Date().toISOString();
}
/**
 * Glob match where only `*` is special (matches any run of characters).
 * Everything else is matched literally, so patterns can never ReDoS.
 */
export function globMatch(pattern, value) {
    const escaped = pattern.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&'));
    return new RegExp(`^${escaped.join('.*')}$`).test(value);
}
const sha = (s) => createHash('sha256').update(s, 'utf8').digest();
/**
 * Constant-time bearer-key lookup. Compares SHA-256 digests (always 32 bytes)
 * and scans every key, so neither the presented key's length nor the position
 * of the matching key leaks through timing.
 */
export function matchKey(keys, presented, now = Date.now()) {
    const p = sha(presented);
    let found = null;
    for (const k of keys) {
        const stored = k.keyHash !== undefined ? Buffer.from(k.keyHash.slice('sha256:'.length), 'hex') : sha(k.key);
        // Expiry is checked after the comparison and never changes how long it takes.
        if (timingSafeEqual(p, stored) && found === null && (k.expiresAt === undefined || now < k.expiresAt))
            found = k;
    }
    return found;
}
/** The value to put in `keyHash:` for a key. */
export function hashKey(key) {
    return 'sha256:' + sha(key).toString('hex');
}
/**
 * Strip terminal-control, bidi-override and zero-width characters from
 * untrusted text (tool descriptions, server names in logs). Replaced with a
 * visible U+FFFD so tampering is evident, not silent.
 */
// eslint-disable-next-line no-control-regex
const HOSTILE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;
export function stripHostile(s) {
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
export function escapeHostileJson(line) {
    return line.replace(HOSTILE_IN_JSON, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}
//# sourceMappingURL=util.js.map