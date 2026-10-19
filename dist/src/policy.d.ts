import type { PolicyConfig } from './config.js';
export type ToolDecision = 'allow' | 'deny';
export interface ToolVerdict {
    decision: ToolDecision;
    /** machine-readable reason: allow|deny_list|not_allow_listed|arg_deny|arg_allow_miss */
    reason: string;
    detail: string;
}
export interface ResponseVerdict {
    action: 'pass' | 'block';
    /** result after structured redaction (null when blocked) */
    result: unknown;
    redactions: number;
    warnings: string[];
    blockedBy?: string;
}
/** Is the tool visible in listings? Hidden tools are also denied on call. */
export declare function isHidden(policy: PolicyConfig, publicToolName: string): boolean;
export declare function checkToolCall(policy: PolicyConfig, publicToolName: string, args: unknown): ToolVerdict;
/**
 * Scan a tool result per response rules.
 *
 * Detection (warn/block) runs over the JSON-encoded result, bounded to the
 * first `scanWindowChars` characters (a 10MB result must not stall the
 * gateway). Redaction walks the STRUCTURED value and rewrites string keys
 * and values — never the serialized JSON text, so redaction can never
 * produce invalid JSON (scrutiny finding: a pattern landing inside a JSON
 * escape sequence used to break JSON.parse).
 */
export declare function checkResponse(policy: PolicyConfig, result: unknown): ResponseVerdict;
//# sourceMappingURL=policy.d.ts.map