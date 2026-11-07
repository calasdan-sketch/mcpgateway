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
export declare class AuditLogger {
    private cfg;
    private onError?;
    private bytesWritten;
    private maxBytes;
    errors: number;
    private seq;
    private lastHash;
    private chainLoaded;
    constructor(cfg: AuditConfig, onError?: (() => void) | undefined);
    /** Count a write failure and notify the metrics registry (never throws). */
    private fail;
    /** Append one record. Never throws. */
    log(record: AuditRecord): void;
    /** Current chain head (for external anchoring). */
    head(): {
        seq: number;
        hash: string;
    };
    private chain;
    /** Resume the chain from the tail of the current file, else the newest rotated file. */
    private loadChainHead;
    close(): void;
    private ensureOpen;
    private prepare;
    private rotate;
}
/** Replace known credential shapes inside free text. */
export declare function redactText(text: string): string;
/** Recursively redact values whose key contains a redact substring (case-insensitive). */
export declare function redactDeep(value: unknown, redactKeys: string[], shapes?: boolean): unknown;
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
export interface VerifyResult {
    ok: boolean;
    records: number;
    /** hash the first verified record chained from (anchor for external comparison) */
    anchor?: string;
    head?: {
        seq: number;
        hash: string;
    };
    failure?: {
        file: string;
        line: number;
        reason: string;
    };
}
/**
 * Verify a hash chain across files given OLDEST FIRST. Detects edited,
 * reordered, inserted or deleted-in-the-middle records. It cannot detect
 * truncation of the newest records on its own: compare `head` with a value
 * you stored elsewhere (GET /v1/audit/head).
 */
export declare function verifyChain(files: string[], key?: string): VerifyResult;
//# sourceMappingURL=audit.d.ts.map