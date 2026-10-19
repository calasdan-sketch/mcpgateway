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
export declare class AuditLogger {
    private cfg;
    private onError?;
    private bytesWritten;
    private maxBytes;
    errors: number;
    constructor(cfg: AuditConfig, onError?: (() => void) | undefined);
    /** Count a write failure and notify the metrics registry (never throws). */
    private fail;
    /** Append one record. Never throws. */
    log(record: AuditRecord): void;
    close(): void;
    private ensureOpen;
    private prepare;
    private rotate;
}
/** Recursively redact values whose key contains a redact substring (case-insensitive). */
export declare function redactDeep(value: unknown, redactKeys: string[]): unknown;
/**
 * Collect the actual secret VALUES from a call's args (values of keys that
 * matched the redact list). Used to scrub those values out of downstream
 * error messages, which otherwise echo secrets into the audit log and the
 * agent-facing error. Only values >= 8 chars are collected, so redacting
 * them elsewhere can never nuke ordinary words.
 */
export declare function collectSecretValues(args: unknown, redactKeys: string[]): string[];
/** Replace every occurrence of each secret value with [REDACTED]. */
export declare function redactSecretValues(text: string, secrets: string[]): string;
//# sourceMappingURL=audit.d.ts.map