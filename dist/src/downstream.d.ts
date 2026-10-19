import { type CallToolResult, type GetPromptResult, type Prompt, type ReadResourceResult, type Resource, type Tool } from '@modelcontextprotocol/sdk/types.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { ServerConfig } from './config.js';
export interface ServerCatalogs {
    tools: Tool[];
    resources: Resource[];
    prompts: Prompt[];
}
type BreakerState = 'closed' | 'open' | 'half-open';
export interface DownstreamHooks {
    /** Catalogs changed (list_changed notification): rebuild the namespace. */
    onCatalogChanged: (server: DownstreamServer) => void;
}
export declare class DownstreamServer {
    private cfg;
    private hooks;
    /** Injected transport for tests (skips spawning/connecting real servers). */
    private transportOverride?;
    readonly name: string;
    private client;
    private transport;
    private catalogs;
    private semaphore;
    private breakerState;
    private consecutiveFailures;
    private breakerOpenedAt;
    private healthTimer;
    private refreshTimer;
    private closed;
    lastPingOk: boolean | null;
    lastError: string | null;
    constructor(cfg: ServerConfig, hooks: DownstreamHooks, 
    /** Injected transport for tests (skips spawning/connecting real servers). */
    transportOverride?: Transport | undefined);
    get inFlight(): number;
    get healthy(): boolean;
    get circuitState(): BreakerState;
    getCatalogs(): ServerCatalogs;
    connect(): Promise<void>;
    private createTransport;
    private registerCatalogWatchers;
    private refreshCatalogs;
    private startHealthChecks;
    private ping;
    /**
     * Call a tool on this server. Enforces the circuit breaker, concurrency
     * bound, and per-call timeout. Throws on failure (caller maps to JSON-RPC).
     */
    callTool(originalName: string, args: unknown): Promise<CallToolResult>;
    private onSuccess;
    /** Read a resource by its ORIGINAL uri. Same breaker/timeout discipline as tools. */
    readResource(originalUri: string): Promise<ReadResourceResult>;
    /** Get a prompt by its ORIGINAL name. Same breaker/timeout discipline as tools. */
    getPrompt(originalName: string, args: Record<string, string>): Promise<GetPromptResult>;
    private onFailure;
    close(): Promise<void>;
}
export {};
//# sourceMappingURL=downstream.d.ts.map