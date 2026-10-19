/** Small shared helpers. No dependencies. */
import { randomUUID } from 'node:crypto';
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
//# sourceMappingURL=util.js.map