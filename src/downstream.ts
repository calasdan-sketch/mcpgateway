/**
 * Downstream server manager: one MCP client per configured server.
 *
 * Reliability per blueprint §5:
 *  - bounded concurrency semaphore (stdio defaults to 1: most stdio servers
 *    are single-threaded and collapse under parallel calls)
 *  - per-call timeout (timeout rejects the call; the server is left alone)
 *  - circuit breaker: failureThreshold consecutive failures -> open for
 *    breakerCooldownMs (fail fast), then a half-open ping probe
 *  - periodic ping health checks; catalog refresh on list_changed
 *    notifications (debounced; routing table swapped atomically upstream)
 *
 * Child processes are spawned with shell:false and an argv array taken from
 * the trusted config file. Server-initiated requests (sampling/elicitation)
 * are NOT proxied (blueprint D2): the SDK answers them with a standard
 * "method not found" error, which can never crash the gateway.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {
  CallToolResultSchema,
  PromptListChangedNotificationSchema,
  ResourceListChangedNotificationSchema,
  ToolListChangedNotificationSchema,
  type CallToolResult,
  type GetPromptResult,
  type Prompt,
  type ReadResourceResult,
  type Resource,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { VERSION } from './version.js';
import { sleep, withTimeout } from './util.js';
import type { ServerConfig } from './config.js';

export interface ServerCatalogs {
  tools: Tool[];
  resources: Resource[];
  prompts: Prompt[];
}

type BreakerState = 'closed' | 'open' | 'half-open';

class Semaphore {
  private active = 0;
  private queue: Array<() => void> = [];
  constructor(private max: number) {}
  get inFlight(): number {
    return this.active;
  }
  async acquire(): Promise<() => void> {
    if (this.active < this.max) {
      this.active += 1;
      return () => this.release();
    }
    return new Promise<() => void>((resolve) => {
      this.queue.push(() => {
        this.active += 1;
        resolve(() => this.release());
      });
    });
  }
  private release(): void {
    this.active -= 1;
    const next = this.queue.shift();
    if (next) next();
  }
}

export interface DownstreamHooks {
  /** Catalogs changed (list_changed notification): rebuild the namespace. */
  onCatalogChanged: (server: DownstreamServer) => void;
}

export class DownstreamServer {
  readonly name: string;
  private client: Client;
  private transport: Transport | null = null;
  private catalogs: ServerCatalogs = { tools: [], resources: [], prompts: [] };
  private semaphore: Semaphore;
  private breakerState: BreakerState = 'closed';
  private consecutiveFailures = 0;
  private breakerOpenedAt = 0;
  private healthTimer: NodeJS.Timeout | null = null;
  private refreshTimer: NodeJS.Timeout | null = null;
  private closed = false;
  lastPingOk: boolean | null = null;
  lastError: string | null = null;

  constructor(
    private cfg: ServerConfig,
    private hooks: DownstreamHooks,
    /** Injected transport for tests (skips spawning/connecting real servers). */
    private transportOverride?: Transport,
  ) {
    this.name = cfg.name;
    this.client = new Client({ name: 'mcpgateway', version: VERSION }, { capabilities: {} });
    this.semaphore = new Semaphore(cfg.concurrency);
  }

  get inFlight(): number {
    return this.semaphore.inFlight;
  }

  get healthy(): boolean {
    return this.breakerState !== 'open' && this.lastPingOk !== false;
  }

  get circuitState(): BreakerState {
    return this.breakerState;
  }

  getCatalogs(): ServerCatalogs {
    return this.catalogs;
  }

  async connect(): Promise<void> {
    const transport = this.transportOverride ?? this.createTransport();
    this.transport = transport;
    // If the server binary is missing or hangs, fail fast instead of hanging serve.
    await withTimeout(this.client.connect(transport), 30_000, `connect to server "${this.name}"`);
    this.registerCatalogWatchers();
    await this.refreshCatalogs();
    this.startHealthChecks();
  }

  private createTransport(): Transport {
    if (this.cfg.transport === 'stdio') {
      return new StdioClientTransport({
        command: this.cfg.command as string,
        args: this.cfg.args ?? [],
        env: this.cfg.env ?? {},
        cwd: this.cfg.cwd,
        // inherit (not pipe): the SDK creates an undrained PassThrough for
        // 'pipe', so a chatty server would block forever on a full stderr
        // buffer. In stdio upstream mode stderr is our log channel anyway.
        stderr: 'inherit',
      });
    }
    return new StreamableHTTPClientTransport(new URL(this.cfg.url as string), {
      requestInit: { headers: this.cfg.headers ?? {} },
    });
  }

  private registerCatalogWatchers(): void {
    const schedule = () => {
      if (this.closed) return;
      if (this.refreshTimer) clearTimeout(this.refreshTimer);
      this.refreshTimer = setTimeout(() => void this.refreshCatalogs(true), 500);
    };
    // setNotificationHandler exists on Client (Protocol). Schemas imported above.
    this.client.setNotificationHandler(ToolListChangedNotificationSchema, schedule);
    this.client.setNotificationHandler(ResourceListChangedNotificationSchema, schedule);
    this.client.setNotificationHandler(PromptListChangedNotificationSchema, schedule);
  }

  private async refreshCatalogs(notify = false): Promise<void> {
    try {
      const [tools, resources, prompts] = await Promise.all([
        this.client.listTools().catch(() => ({ tools: [] as Tool[] })),
        this.client.listResources().catch(() => ({ resources: [] as Resource[] })),
        this.client.listPrompts().catch(() => ({ prompts: [] as Prompt[] })),
      ]);
      this.catalogs = { tools: tools.tools, resources: resources.resources, prompts: prompts.prompts };
      if (notify) this.hooks.onCatalogChanged(this);
    } catch (e) {
      this.lastError = (e as Error).message;
    }
  }

  private startHealthChecks(): void {
    this.healthTimer = setInterval(() => void this.ping(), this.cfg.healthCheckMs);
    this.healthTimer.unref?.();
  }

  private async ping(): Promise<void> {
    if (this.closed) return;
    if (this.breakerState === 'open') {
      if (Date.now() - this.breakerOpenedAt < this.cfg.breakerCooldownMs) return;
      // Half-open probe: a successful ping lets the next real call through,
      // so recovery doesn't wait for user traffic.
      try {
        await withTimeout(this.client.ping(), 10_000, `ping server "${this.name}"`);
        this.breakerState = 'half-open';
        this.consecutiveFailures = 0;
        this.lastPingOk = true;
      } catch {
        this.breakerOpenedAt = Date.now(); // extend the cooldown
        this.lastPingOk = false;
      }
      return;
    }
    try {
      await withTimeout(this.client.ping(), 10_000, `ping server "${this.name}"`);
      this.lastPingOk = true;
    } catch {
      this.lastPingOk = false;
    }
  }

  /**
   * Call a tool on this server. Enforces the circuit breaker, concurrency
   * bound, and per-call timeout. Throws on failure (caller maps to JSON-RPC).
   */
  async callTool(originalName: string, args: unknown): Promise<CallToolResult> {
    if (this.closed) throw new Error(`server "${this.name}" is closed`);

    // Circuit breaker.
    if (this.breakerState === 'open') {
      if (Date.now() - this.breakerOpenedAt >= this.cfg.breakerCooldownMs) {
        this.breakerState = 'half-open';
      } else {
        throw new Error(`server "${this.name}" circuit breaker is open (too many failures)`);
      }
    }

    const release = await this.semaphore.acquire();
    try {
      const result = (await withTimeout(
        this.client.callTool({ name: originalName, arguments: (args ?? {}) as Record<string, unknown> }, CallToolResultSchema, {
          timeout: this.cfg.timeoutMs,
        }),
        this.cfg.timeoutMs + 5_000,
        `tool "${originalName}" on server "${this.name}"`,
      )) as CallToolResult;
      this.onSuccess();
      return result;
    } catch (e) {
      this.onFailure();
      throw e;
    } finally {
      release();
    }
  }

  private onSuccess(): void {
    this.consecutiveFailures = 0;
    if (this.breakerState === 'half-open') this.breakerState = 'closed';
    this.lastError = null;
  }

  /** Read a resource by its ORIGINAL uri. Same breaker/timeout discipline as tools. */
  async readResource(originalUri: string): Promise<ReadResourceResult> {
    if (this.closed) throw new Error(`server "${this.name}" is closed`);
    if (this.breakerState === 'open') throw new Error(`server "${this.name}" circuit breaker is open (too many failures)`);
    const release = await this.semaphore.acquire();
    try {
      const result = await withTimeout(
        this.client.readResource({ uri: originalUri }, { timeout: this.cfg.timeoutMs }),
        this.cfg.timeoutMs + 5_000,
        `resource "${originalUri}" on server "${this.name}"`,
      );
      this.onSuccess();
      return result;
    } catch (e) {
      this.onFailure();
      throw e;
    } finally {
      release();
    }
  }

  /** Get a prompt by its ORIGINAL name. Same breaker/timeout discipline as tools. */
  async getPrompt(originalName: string, args: Record<string, string>): Promise<GetPromptResult> {
    if (this.closed) throw new Error(`server "${this.name}" is closed`);
    if (this.breakerState === 'open') throw new Error(`server "${this.name}" circuit breaker is open (too many failures)`);
    const release = await this.semaphore.acquire();
    try {
      const result = await withTimeout(
        this.client.getPrompt({ name: originalName, arguments: args }, { timeout: this.cfg.timeoutMs }),
        this.cfg.timeoutMs + 5_000,
        `prompt "${originalName}" on server "${this.name}"`,
      );
      this.onSuccess();
      return result;
    } catch (e) {
      this.onFailure();
      throw e;
    } finally {
      release();
    }
  }

  private onFailure(): void {
    this.consecutiveFailures += 1;
    if (this.breakerState === 'half-open' || this.consecutiveFailures >= this.cfg.failureThreshold) {
      this.breakerState = 'open';
      this.breakerOpenedAt = Date.now();
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    if (this.healthTimer) clearInterval(this.healthTimer);
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    try {
      await this.client.close();
    } catch {
      /* already gone */
    }
    // Give the child a moment, then make sure a stuck stdio server dies with us.
    await sleep(50);
  }
}
