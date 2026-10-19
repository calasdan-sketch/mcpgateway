/**
 * Upstream: the agent-facing side of the gateway. The gateway presents as ONE
 * MCP server (stdio and/or Streamable HTTP) and routes every tools/call,
 * resources/read, and prompts/get to the owning downstream server.
 *
 * Tool-call pipeline (in order):
 *   1. route lookup            — unknown tool -> InvalidParams
 *   2. fleet policy verdict    — enforce: deny -> audit + McpError;
 *                                observe: forward anyway, audit the would-be verdict
 *   3. per-tool rate limit     — token bucket; exhausted -> audit + McpError
 *   4. global in-flight cap    — protects the gateway itself from collapse
 *   5. downstream call         — breaker + semaphore + timeout live downstream
 *   6. response egress rules   — block -> McpError; redact -> rewritten result
 *   7. audit + metrics         — every outcome lands in both
 *
 * Resources and prompts are routed (namespaced) and audited; fleet policy
 * and rate limits apply to tools in v1 (blueprint D2).
 */
import { type IncomingMessage, type Server as HttpServer } from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { type Prompt, type Resource } from '@modelcontextprotocol/sdk/types.js';
import type { DownstreamServer } from './downstream.js';
import type { ToolEntry } from './namespace.js';
import type { AuditLogger } from './audit.js';
import type { Metrics } from './metrics.js';
import type { RateLimiter } from './ratelimit.js';
import type { AuthKey, PolicyConfig, RateLimitRule } from './config.js';
export interface RouteTarget {
    server: DownstreamServer;
    /** original tool/prompt name, or original resource uri */
    original: string;
}
export interface PromptEntry {
    publicName: string;
    server: string;
    originalName: string;
    description?: string;
    args?: Prompt['arguments'];
}
export interface RoutingTable {
    tools: Map<string, RouteTarget>;
    toolMeta: Map<string, ToolEntry>;
    prompts: Map<string, RouteTarget>;
    promptMeta: Map<string, PromptEntry>;
    /** public uri -> target (original = original uri) */
    resources: Map<string, RouteTarget>;
    resourceMeta: Map<string, Resource>;
}
export declare const RESOURCE_SCHEME = "mcpgateway";
export declare function publicResourceUri(server: string, originalUri: string): string;
export declare function parsePublicResourceUri(publicUri: string): {
    server: string;
    originalUri: string;
} | null;
export interface UpstreamAuth {
    disabled: boolean;
    keys: AuthKey[];
}
export interface UpstreamDeps {
    getTable: () => RoutingTable;
    policy: PolicyConfig;
    rateLimiter: RateLimiter;
    defaultRateLimit: RateLimitRule;
    perToolRateLimits: Record<string, RateLimitRule>;
    audit: AuditLogger;
    /** audit config (redact keys) — separate so error scrubbing stays consistent */
    auditCfg: {
        redactKeys: string[];
    };
    metrics: Metrics;
    globalMaxInflight: number;
    /** drop results larger than this (chars of JSON) — OOM guard */
    maxResultChars: number;
    /** max concurrent Streamable HTTP sessions — abandoned sessions can't grow forever */
    httpMaxSessions: number;
    auth: UpstreamAuth;
}
interface AuthedKey {
    keyId: string;
    scopes: string[];
}
export declare class GatewayUpstream {
    private deps;
    private inflight;
    constructor(deps: UpstreamDeps);
    /** Create the agent-facing MCP server. Handlers always read the CURRENT routing table. */
    createMcpServer(): Server;
    connectStdio(): Promise<void>;
    listenHttp(host: string, port: number): Promise<HttpServer>;
    private handleHttp;
    /** Bearer auth for the HTTP upstream. Returns null when rejected. */
    authenticateHttp(req: IncomingMessage): AuthedKey | null;
    private handleToolCall;
    private handleResourceRead;
    private handlePromptGet;
}
/** Map an MCP method to the scope required to call it (null = any authed key). */
export declare function scopeForMethod(method: string): string | null;
export {};
//# sourceMappingURL=upstream.d.ts.map