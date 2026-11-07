import { globMatch } from './util.js';
export declare class ConfigError extends Error {
    readonly problems: string[];
    constructor(problems: string[]);
}
export interface ServerConfig {
    name: string;
    transport: 'stdio' | 'http';
    command?: string;
    args?: string[];
    env?: Record<string, string>;
    cwd?: string;
    url?: string;
    headers?: Record<string, string>;
    timeoutMs: number;
    concurrency: number;
    failureThreshold: number;
    breakerCooldownMs: number;
    healthCheckMs: number;
}
export type NamespaceStrategy = 'prefix' | 'priority' | 'explicit';
export interface NamespaceConfig {
    strategy: NamespaceStrategy;
    separator: string;
    priority: string[];
    mappings: Record<string, string>;
    aliases: Record<string, string>;
}
export interface RateLimitRule {
    rps: number;
    burst: number;
}
export interface ArgRule {
    allow?: string[];
    deny?: string[];
}
export interface PolicyConfig {
    mode: 'enforce' | 'observe';
    allowTools: string[];
    denyTools: string[];
    hideTools: string[];
    argRules: Record<string, ArgRule>;
    responseRedact: string[];
    responseBlock: string[];
    responseWarn: string[];
    scanWindowChars: number;
    /** Rug-pull defense: pin each tool's description+schema hash (trust on first use). */
    pinning?: PinningConfig;
}
export interface PinningConfig {
    /** off: nothing; warn: log+metric on change; block: quarantine changed tools until accepted */
    mode: 'off' | 'warn' | 'block';
    /** JSON file the pins persist in (omit = in-memory, lost on restart) */
    file?: string;
}
export interface AuthKey {
    id: string;
    key: string;
    scopes: string[];
    /** per-key tool visibility (globs over public names); deny wins. Omitted = everything policy allows. */
    allowTools?: string[];
    denyTools?: string[];
    /** per-key budget across ALL tools, so one noisy agent cannot starve the others */
    rateLimit?: RateLimitRule;
}
export interface ExposureConfig {
    /** full: every tool in tools/list (default). search: two meta-tools + alwaysExpose. */
    mode: 'full' | 'search';
    /** globs of public tool names that stay listed directly in search mode */
    alwaysExpose: string[];
}
export interface AuditConfig {
    path: string;
    logArgs: boolean;
    redactKeys: string[];
    maxArgsChars: number;
    maxSizeMB: number;
    keepFiles: number;
    /** tamper-evident hash chain over records (see `mcpgateway audit-verify`) */
    chain?: boolean;
    /** optional HMAC secret for the chain; without it an attacker who can rewrite the file can recompute hashes */
    chainKey?: string;
}
export interface AdminConfig {
    enabled: boolean;
    host: string;
    port: number;
    allowPublicAdmin: boolean;
}
export interface UpstreamConfig {
    stdio: {
        enabled: boolean;
    };
    http: {
        enabled: boolean;
        host: string;
        port: number;
        maxSessions: number;
        allowedHosts: string[];
        allowedOrigins: string[];
    };
}
export interface GatewayConfig {
    name: string;
    servers: ServerConfig[];
    namespace: NamespaceConfig;
    defaultRateLimit: RateLimitRule;
    perToolRateLimits: Record<string, RateLimitRule>;
    policy: PolicyConfig;
    auth: {
        disabled: boolean;
        keys: AuthKey[];
    };
    audit: AuditConfig;
    admin: AdminConfig;
    upstream: UpstreamConfig;
    exposure: ExposureConfig;
    globalMaxInflight: number;
    maxResultChars: number;
}
export declare const VALID_SCOPES: readonly ["tools:call", "tools:list", "resources:*", "prompts:*", "admin"];
/** Expand ${VAR} and ${VAR:-default}; throws naming the variable when unset. */
export declare function interpolateEnv(value: string, context: string): string;
export type Raw = Record<string, unknown>;
export interface LoadOptions {
    /** Skip reachability/command-exists checks (offline validation). */
    noNetwork?: boolean;
}
export declare function loadConfigFile(path: string, opts?: LoadOptions): GatewayConfig;
export declare function validateConfig(raw: Raw, source: string, opts?: LoadOptions): GatewayConfig;
/** Warnings collected during validation (unknown keys etc.). Non-fatal. */
export declare function configWarnings(cfg: GatewayConfig): string[];
/** Does this public tool name match any allow/deny-style glob list? Exported for policy use. */
export declare function matchesAny(patterns: string[], value: string): boolean;
export { globMatch };
//# sourceMappingURL=config.d.ts.map