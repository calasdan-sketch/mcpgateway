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
    /** A dead connection was re-established (stdio child restarted, etc.). */
    onReconnected?: (server: DownstreamServer) => void;
}
/** Test hook: a transport, or a factory producing a fresh one per (re)connect. */
export type TransportOverride = Transport | (() => Transport);
/**
 * Did the server ANSWER, with an error that is the caller's fault? Such errors
 * (bad arguments, unknown method) prove the server is alive and must never
 * count toward the circuit breaker — otherwise any key holding tools:call
 * could trip the breaker for the whole fleet with five malformed calls.
 */
export declare function isClientFault(e: unknown): boolean;
export declare class DownstreamServer {
    private cfg;
    private hooks;
    /** Injected transport for tests (skips spawning/connecting real servers). */
    private transportOverride?;
    readonly name: string;
    private client;
    private transport;
    private reconnectTimer;
    private reconnectAttempt;
    reconnects: number;
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
    transportOverride?: TransportOverride | undefined);
    get inFlight(): number;
    get healthy(): boolean;
    get circuitState(): BreakerState;
    getCatalogs(): ServerCatalogs;
    private newClient;
    private nextTransport;
    /**
     * The connection died underneath us (stdio child exited, socket closed).
     * Open the breaker so callers fail fast, then reconnect with capped
     * exponential backoff. Before this, a crashed stdio server stayed dead until
     * the gateway was restarted.
     */
    private handleClose;
    private scheduleReconnect;
    private reconnect;
    /** Re-fetch every catalog from the live server (admin reload). */
    refresh(): Promise<void>;
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