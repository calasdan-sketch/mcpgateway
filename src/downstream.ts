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
  ErrorCode,
  McpError,
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
import { sleep, stripHostile, withTimeout } from './util.js';
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
  /** Wait for a slot. An aborted signal leaves the queue immediately (a cancelled caller must not hold a place). */
  async acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) throw new Error('request cancelled');
    if (this.active < this.max) {
      this.active += 1;
      return () => this.release();
    }
    return new Promise<() => void>((resolve, reject) => {
      const entry = () => {
        signal?.removeEventListener('abort', onAbort);
        this.active += 1;
        resolve(() => this.release());
      };
      const onAbort = () => {
        const i = this.queue.indexOf(entry);
        if (i !== -1) this.queue.splice(i, 1);
        reject(new Error('request cancelled'));
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      this.queue.push(entry);
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
  /** A dead connection was re-established (stdio child restarted, etc.). */
  onReconnected?: (server: DownstreamServer) => void;
  /** A sanitized line a stdio child wrote to stderr. Default: process.stderr. */
  onChildStderr?: (server: string, line: string) => void;
}

/** Hard bounds so a server cannot make catalog fetching loop or balloon forever. */
const MAX_CATALOG_PAGES = 200;
const MAX_CATALOG_ITEMS = 20_000;
const STDERR_LINE_MAX = 2_000;
const STDERR_BUDGET_LINES = 1_000;
const STDERR_BUDGET_WINDOW_MS = 10_000;
const KILL_GRACE_MS = 2_000;

/** Follow nextCursor to the end (bounded; a repeated cursor ends the walk). */
export async function collectPages<T>(fetchPage: (cursor?: string) => Promise<{ items: T[]; nextCursor?: string | undefined }>): Promise<T[]> {
  const out: T[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let page = 0; page < MAX_CATALOG_PAGES; page++) {
    const r = await fetchPage(cursor);
    out.push(...r.items);
    if (out.length >= MAX_CATALOG_ITEMS) return out.slice(0, MAX_CATALOG_ITEMS);
    if (r.nextCursor === undefined || r.nextCursor === '' || seen.has(r.nextCursor)) return out;
    seen.add(r.nextCursor);
    cursor = r.nextCursor;
  }
  return out;
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** Test hook: a transport, or a factory producing a fresh one per (re)connect. */
export type TransportOverride = Transport | (() => Transport);

const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;

/**
 * Did the server ANSWER, with an error that is the caller's fault? Such errors
 * (bad arguments, unknown method) prove the server is alive and must never
 * count toward the circuit breaker — otherwise any key holding tools:call
 * could trip the breaker for the whole fleet with five malformed calls.
 */
export function isClientFault(e: unknown): boolean {
  return (
    e instanceof McpError &&
    (e.code === ErrorCode.InvalidParams || e.code === ErrorCode.MethodNotFound || e.code === ErrorCode.InvalidRequest || e.code === ErrorCode.ParseError)
  );
}

/** The caller gave up (client sent notifications/cancelled). The server did nothing wrong. */
export function isCancellation(e: unknown): boolean {
  return e instanceof Error && (e.message === 'request cancelled' || e.name === 'AbortError' || /^(MCP error -?\d+: )*(AbortError|This operation was aborted|Request cancelled)/i.test(e.message) || e.message === 'The operation was aborted.' || e.message === 'This operation was aborted');
}

export class DownstreamServer {
  readonly name: string;
  private client: Client;
  private transport: Transport | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private reconnectAttempt = 0;
  reconnects = 0;
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
    private transportOverride?: TransportOverride,
  ) {
    this.name = cfg.name;
    this.client = this.newClient();
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

  private newClient(): Client {
    const client = new Client({ name: 'mcpgateway', version: VERSION }, { capabilities: {} });
    client.onclose = () => this.handleClose(client);
    return client;
  }

  private nextTransport(): Transport {
    const o = this.transportOverride;
    if (o === undefined) return this.createTransport();
    return typeof o === 'function' ? o() : o;
  }

  /**
   * The connection died underneath us (stdio child exited, socket closed).
   * Open the breaker so callers fail fast, then reconnect with capped
   * exponential backoff. Before this, a crashed stdio server stayed dead until
   * the gateway was restarted.
   */
  private handleClose(client: Client): void {
    if (this.closed || client !== this.client) return;
    this.breakerState = 'open';
    this.breakerOpenedAt = Date.now();
    this.lastPingOk = false;
    this.lastError = 'connection closed';
    this.scheduleReconnect();
  }

  private scheduleReconnect(): void {
    if (this.closed || this.reconnectTimer !== null) return;
    const delay = Math.min(RECONNECT_BASE_MS * 2 ** this.reconnectAttempt, RECONNECT_MAX_MS);
    this.reconnectAttempt += 1;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.reconnect();
    }, delay);
    this.reconnectTimer.unref?.();
  }

  private async reconnect(): Promise<void> {
    if (this.closed) return;
    const old = this.client;
    old.onclose = undefined;
    try {
      await old.close();
    } catch {
      /* already gone */
    }
    if (this.closed) return;
    const client = this.newClient();
    this.client = client;
    try {
      const transport = this.nextTransport();
      this.transport = transport;
      await withTimeout(client.connect(transport), 30_000, `reconnect to server "${this.name}"`);
      this.registerCatalogWatchers();
      await this.refreshCatalogs(false);
      this.breakerState = 'closed';
      this.consecutiveFailures = 0;
      this.lastPingOk = true;
      this.lastError = null;
      this.reconnectAttempt = 0;
      this.reconnects += 1;
      this.hooks.onReconnected?.(this);
      this.hooks.onCatalogChanged(this);
    } catch (e) {
      this.lastError = (e as Error).message;
      client.onclose = undefined;
      await client.close().catch(() => undefined);
      this.client = this.newClient();
      this.scheduleReconnect();
    }
  }

  /** Re-fetch every catalog from the live server (admin reload). */
  async refresh(): Promise<void> {
    await this.refreshCatalogs(false);
  }

  async connect(): Promise<void> {
    const transport = this.nextTransport();
    this.transport = transport;
    // If the server binary is missing or hangs, fail fast instead of hanging serve.
    await withTimeout(this.client.connect(transport), 30_000, `connect to server "${this.name}"`);
    this.registerCatalogWatchers();
    await this.refreshCatalogs();
    this.startHealthChecks();
  }

  private createTransport(): Transport {
    if (this.cfg.transport === 'stdio') {
      const t = new StdioClientTransport({
        command: this.cfg.command as string,
        args: this.cfg.args ?? [],
        env: this.cfg.env ?? {},
        cwd: this.cfg.cwd,
        // Piped, always drained, and sanitized: a server's stderr is untrusted
        // text and must not reach the operator's terminal raw (escape
        // sequences can rewrite the screen or hide lines).
        stderr: 'pipe',
      });
      this.pumpStderr(t);
      return t;
    }
    return new StreamableHTTPClientTransport(new URL(this.cfg.url as string), {
      requestInit: { headers: this.cfg.headers ?? {} },
    });
  }

  private pumpStderr(t: StdioClientTransport): void {
    const stream = t.stderr as import('node:stream').Readable | null | undefined;
    if (stream === null || stream === undefined) return;
    let partial = '';
    let windowStart = Date.now();
    let lines = 0;
    let suppressed = 0;
    const emit = (raw: string) => {
      const now = Date.now();
      if (now - windowStart > STDERR_BUDGET_WINDOW_MS) {
        if (suppressed > 0) this.writeChildLine(`[${suppressed} stderr line(s) suppressed]`);
        windowStart = now;
        lines = 0;
        suppressed = 0;
      }
      if (lines >= STDERR_BUDGET_LINES) {
        suppressed += 1;
        return;
      }
      lines += 1;
      const clipped = raw.length > STDERR_LINE_MAX ? raw.slice(0, STDERR_LINE_MAX) + '…[truncated]' : raw;
      this.writeChildLine(stripHostile(clipped).text.replace(/[\r\n]+/g, ' ⏎ '));
    };
    stream.setEncoding('utf8');
    stream.on('data', (chunk: string) => {
      partial += chunk;
      let nl = partial.indexOf('\n');
      while (nl !== -1) {
        emit(partial.slice(0, nl).replace(/\r$/, ''));
        partial = partial.slice(nl + 1);
        nl = partial.indexOf('\n');
      }
      if (partial.length > STDERR_LINE_MAX * 2) {
        emit(partial);
        partial = '';
      }
    });
    stream.on('error', () => undefined);
  }

  private writeChildLine(line: string): void {
    if (this.hooks.onChildStderr) this.hooks.onChildStderr(this.name, line);
    else process.stderr.write(`[${this.name}] ${line}\n`);
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
      const caps = this.client.getServerCapabilities() ?? {};
      // Listing is attempted whether or not the server declared the capability
      // (some servers forget to); "method not found" just means empty. Any other
      // failure on a kind the server DID declare KEEPS the previous catalog: one
      // transient error must not make a server's tools vanish from every agent.
      const prev = this.catalogs;
      const errors: string[] = [];
      const grab = async <T>(advertised: boolean, previous: T[], label: string, fetchPage: (cursor?: string) => Promise<{ items: T[]; nextCursor?: string | undefined }>): Promise<T[]> => {
        try {
          return await collectPages(fetchPage);
        } catch (e) {
          if (e instanceof McpError && e.code === ErrorCode.MethodNotFound) return [];
          if (!advertised) return [];
          errors.push(`${label}: ${(e as Error).message}`);
          return previous;
        }
      };
      const [tools, resources, prompts] = await Promise.all([
        grab(caps.tools !== undefined, prev.tools, 'tools/list', async (cursor) => {
          const r = await this.client.listTools(cursor === undefined ? {} : { cursor });
          return { items: r.tools, nextCursor: r.nextCursor };
        }),
        grab(caps.resources !== undefined, prev.resources, 'resources/list', async (cursor) => {
          const r = await this.client.listResources(cursor === undefined ? {} : { cursor });
          return { items: r.resources, nextCursor: r.nextCursor };
        }),
        grab(caps.prompts !== undefined, prev.prompts, 'prompts/list', async (cursor) => {
          const r = await this.client.listPrompts(cursor === undefined ? {} : { cursor });
          return { items: r.prompts, nextCursor: r.nextCursor };
        }),
      ]);
      this.catalogs = { tools, resources, prompts };
      if (errors.length > 0) this.lastError = `catalog refresh kept previous data (${errors.join('; ')})`;
      else if (this.lastError?.startsWith('catalog refresh kept')) this.lastError = null;
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
  async callTool(originalName: string, args: unknown, signal?: AbortSignal): Promise<CallToolResult> {
    if (this.closed) throw new Error(`server "${this.name}" is closed`);

    // Circuit breaker.
    if (this.breakerState === 'open') {
      if (Date.now() - this.breakerOpenedAt >= this.cfg.breakerCooldownMs) {
        this.breakerState = 'half-open';
      } else {
        throw new Error(`server "${this.name}" circuit breaker is open (too many failures)`);
      }
    }

    const release = await this.semaphore.acquire(signal);
    try {
      const result = (await withTimeout(
        this.client.callTool({ name: originalName, arguments: (args ?? {}) as Record<string, unknown> }, CallToolResultSchema, {
          timeout: this.cfg.timeoutMs,
          ...(signal !== undefined ? { signal } : {}),
        }),
        this.cfg.timeoutMs + 5_000,
        `tool "${originalName}" on server "${this.name}"`,
      )) as CallToolResult;
      this.onSuccess();
      return result;
    } catch (e) {
      this.onFailure(e);
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
      this.onFailure(e);
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
      this.onFailure(e);
      throw e;
    } finally {
      release();
    }
  }

  private onFailure(e: unknown): void {
    if (isClientFault(e) || isCancellation(e)) {
      // The server answered; it is alive. Don't count it, and let a half-open
      // probe close the breaker.
      this.onSuccess();
      return;
    }
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
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    const pid = this.transport instanceof StdioClientTransport ? this.transport.pid : null;
    try {
      await this.client.close();
    } catch {
      /* already gone */
    }
    // The SDK only sends SIGTERM. Give the child a grace period, then SIGKILL
    // so a server that ignores SIGTERM cannot outlive the gateway as an orphan.
    if (pid !== null && pid !== undefined) {
      const deadline = Date.now() + KILL_GRACE_MS;
      while (isAlive(pid) && Date.now() < deadline) await sleep(25);
      if (isAlive(pid)) {
        try {
          process.kill(pid, 'SIGKILL');
        } catch {
          /* gone between check and kill */
        }
      }
    } else {
      await sleep(50);
    }
  }
}
