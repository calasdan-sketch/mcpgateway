/** Unique id for correlating audit records, metrics and error responses. */
export declare function newRequestId(): string;
export declare function sleep(ms: number): Promise<void>;
/** Rejects with `label` after ms; clears the timer when the promise settles. */
export declare function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T>;
/** Truncate a string, appending a marker so truncation is visible. */
export declare function truncate(s: string, maxChars: number): {
    text: string;
    truncated: boolean;
};
/** JSON.stringify that never throws (circular refs -> placeholder). */
export declare function safeJsonStringify(value: unknown): string;
export declare function nowIso(): string;
/**
 * Glob match where only `*` is special (matches any run of characters).
 * Everything else is matched literally, so patterns can never ReDoS.
 */
export declare function globMatch(pattern: string, value: string): boolean;
//# sourceMappingURL=util.d.ts.map