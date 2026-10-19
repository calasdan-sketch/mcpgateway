/**
 * Fleet-wide policy engine — mcp-jail semantics applied at the gateway.
 *
 * Division of labor (blueprint D4):
 *   gateway policy = WHICH tools exist fleet-wide, WHO may call them, HOW OFTEN
 *   mcp-jail      = per-server deep policy (arg shapes, human approvals)
 * They compose; the gateway never duplicates jail's approval flow.
 *
 * Precedence: deny_tools wins over allow_tools. hide_tools removes tools from
 * listings (agents can't see what they can't call). argRules are SUBSTRING
 * matchers on the JSON-encoded arguments (deliberately not regex — ReDoS).
 * response rules scan the JSON-encoded result (bounded window).
 */
import { globMatch, safeJsonStringify } from './util.js';
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

const REDACTED = '[REDACTED]';

/** Is the tool visible in listings? Hidden tools are also denied on call. */
export function isHidden(policy: PolicyConfig, publicToolName: string): boolean {
  return matchesAnyGlob(policy.hideTools, publicToolName);
}

export function checkToolCall(policy: PolicyConfig, publicToolName: string, args: unknown): ToolVerdict {
  // Hidden tools are denied outright (defense in depth: listing filter + call gate).
  if (isHidden(policy, publicToolName)) {
    return { decision: 'deny', reason: 'deny_list', detail: `tool "${publicToolName}" is hidden by policy` };
  }
  if (matchesAnyGlob(policy.denyTools, publicToolName)) {
    return { decision: 'deny', reason: 'deny_list', detail: `tool "${publicToolName}" is denied by policy` };
  }
  if (!matchesAnyGlob(policy.allowTools, publicToolName)) {
    return { decision: 'deny', reason: 'not_allow_listed', detail: `tool "${publicToolName}" is not on the policy allow list` };
  }
  // Argument rules: find the most specific matching rule set (exact name beats glob).
  const rule = findArgRule(policy, publicToolName);
  if (rule !== undefined) {
    const argsJson = safeJsonStringify(args);
    if (rule.deny !== undefined) {
      for (const pat of rule.deny) {
        if (argsJson.includes(pat)) {
          return { decision: 'deny', reason: 'arg_deny', detail: `arguments matched deny pattern for "${publicToolName}"` };
        }
      }
    }
    if (rule.allow !== undefined && rule.allow.length > 0) {
      const ok = rule.allow.some((pat) => argsJson.includes(pat));
      if (!ok) {
        return { decision: 'deny', reason: 'arg_allow_miss', detail: `arguments matched no allow pattern for "${publicToolName}"` };
      }
    }
  }
  return { decision: 'allow', reason: 'allow', detail: '' };
}

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
export function checkResponse(policy: PolicyConfig, result: unknown): ResponseVerdict {
  const window = safeJsonStringify(result).slice(0, policy.scanWindowChars);
  const warnings: string[] = [];
  for (const pat of policy.responseWarn) {
    if (pat.length > 0 && window.includes(pat)) warnings.push('response matched warn pattern');
  }
  for (const pat of policy.responseBlock) {
    if (pat.length > 0 && window.includes(pat)) {
      return { action: 'block', result: null, redactions: 0, warnings, blockedBy: 'response_block' };
    }
  }
  let redactions = 0;
  const redactPatterns = policy.responseRedact.filter((p) => p.length > 0);
  const redactString = (s: string): string => {
    let out = s;
    for (const pat of redactPatterns) {
      let idx = out.indexOf(pat);
      while (idx !== -1) {
        redactions += 1;
        out = out.slice(0, idx) + REDACTED + out.slice(idx + pat.length);
        idx = out.indexOf(pat, idx + REDACTED.length);
      }
    }
    return out;
  };
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') return redactString(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v)) out[redactString(k)] = walk(val);
      return out;
    }
    return v;
  };
  return { action: 'pass', result: walk(result), redactions, warnings };
}

function matchesAnyGlob(patterns: string[], value: string): boolean {
  return patterns.some((p) => globMatch(p, value));
}

function findArgRule(policy: PolicyConfig, publicToolName: string) {
  // Exact match first, then first glob match (config order).
  const exact = policy.argRules[publicToolName];
  if (exact !== undefined) return exact;
  for (const [pattern, rule] of Object.entries(policy.argRules)) {
    if (globMatch(pattern, publicToolName)) return rule;
  }
  return undefined;
}
