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
import { CallToolResultSchema, ErrorCode, McpError, PromptListChangedNotificationSchema, ResourceListChangedNotificationSchema, ToolListChangedNotificationSchema, } from '@modelcontextprotocol/sdk/types.js';
import { VERSION } from './version.js';
import { sleep, withTimeout } from './util.js';
class Semaphore {
    max;
    active = 0;
    queue = [];
    constructor(max) {
        this.max = max;
    }
    get inFlight() {
        return this.active;
    }
    async acquire() {
        if (this.active < this.max) {
            this.active += 1;
            return () => this.release();
        }
        return new Promise((resolve) => {
            this.queue.push(() => {
                this.active += 1;
                resolve(() => this.release());
            });
        });
    }
    release() {
        this.active -= 1;
        const next = this.queue.shift();
        if (next)
            next();
    }
}
const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;
/**
 * Did the server ANSWER, with an error that is the caller's fault? Such errors
 * (bad arguments, unknown method) prove the server is alive and must never
 * count toward the circuit breaker — otherwise any key holding tools:call
 * could trip the breaker for the whole fleet with five malformed calls.
 */
export function isClientFault(e) {
    return (e instanceof McpError &&
        (e.code === ErrorCode.InvalidParams || e.code === ErrorCode.MethodNotFound || e.code === ErrorCode.InvalidRequest || e.code === ErrorCode.ParseError));
}
export class DownstreamServer {
    cfg;
    hooks;
    transportOverride;
    name;
    client;
    transport = null;
    reconnectTimer = null;
    reconnectAttempt = 0;
    reconnects = 0;
    catalogs = { tools: [], resources: [], prompts: [] };
    semaphore;
    breakerState = 'closed';
    consecutiveFailures = 0;
    breakerOpenedAt = 0;
    healthTimer = null;
    refreshTimer = null;
    closed = false;
    lastPingOk = null;
    lastError = null;
    constructor(cfg, hooks, 
    /** Injected transport for tests (skips spawning/connecting real servers). */
    transportOverride) {
        this.cfg = cfg;
        this.hooks = hooks;
        this.transportOverride = transportOverride;
        this.name = cfg.name;
        this.client = this.newClient();
        this.semaphore = new Semaphore(cfg.concurrency);
    }
    get inFlight() {
        return this.semaphore.inFlight;
    }
    get healthy() {
        return this.breakerState !== 'open' && this.lastPingOk !== false;
    }
    get circuitState() {
        return this.breakerState;
    }
    getCatalogs() {
        return this.catalogs;
    }
    newClient() {
        const client = new Client({ name: 'mcpgateway', version: VERSION }, { capabilities: {} });
        client.onclose = () => this.handleClose(client);
        return client;
    }
    nextTransport() {
        const o = this.transportOverride;
        if (o === undefined)
            return this.createTransport();
        return typeof o === 'function' ? o() : o;
    }
    /**
     * The connection died underneath us (stdio child exited, socket closed).
     * Open the breaker so callers fail fast, then reconnect with capped
     * exponential backoff. Before this, a crashed stdio server stayed dead until
     * the gateway was restarted.
     */
    handleClose(client) {
        if (this.closed || client !== this.client)
            return;
        this.breakerState = 'open';
        this.breakerOpenedAt = Date.now();
        this.lastPingOk = false;
        this.lastError = 'connection closed';
        this.scheduleReconnect();
    }
    scheduleReconnect() {
        if (this.closed || this.reconnectTimer !== null)
            return;
        const delay = Math.min(RECONNECT_BASE_MS * 2 ** this.reconnectAttempt, RECONNECT_MAX_MS);
        this.reconnectAttempt += 1;
        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            void this.reconnect();
        }, delay);
        this.reconnectTimer.unref?.();
    }
    async reconnect() {
        if (this.closed)
            return;
        const old = this.client;
        old.onclose = undefined;
        try {
            await old.close();
        }
        catch {
            /* already gone */
        }
        if (this.closed)
            return;
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
        }
        catch (e) {
            this.lastError = e.message;
            client.onclose = undefined;
            await client.close().catch(() => undefined);
            this.client = this.newClient();
            this.scheduleReconnect();
        }
    }
    /** Re-fetch every catalog from the live server (admin reload). */
    async refresh() {
        await this.refreshCatalogs(false);
    }
    async connect() {
        const transport = this.nextTransport();
        this.transport = transport;
        // If the server binary is missing or hangs, fail fast instead of hanging serve.
        await withTimeout(this.client.connect(transport), 30_000, `connect to server "${this.name}"`);
        this.registerCatalogWatchers();
        await this.refreshCatalogs();
        this.startHealthChecks();
    }
    createTransport() {
        if (this.cfg.transport === 'stdio') {
            return new StdioClientTransport({
                command: this.cfg.command,
                args: this.cfg.args ?? [],
                env: this.cfg.env ?? {},
                cwd: this.cfg.cwd,
                // inherit (not pipe): the SDK creates an undrained PassThrough for
                // 'pipe', so a chatty server would block forever on a full stderr
                // buffer. In stdio upstream mode stderr is our log channel anyway.
                stderr: 'inherit',
            });
        }
        return new StreamableHTTPClientTransport(new URL(this.cfg.url), {
            requestInit: { headers: this.cfg.headers ?? {} },
        });
    }
    registerCatalogWatchers() {
        const schedule = () => {
            if (this.closed)
                return;
            if (this.refreshTimer)
                clearTimeout(this.refreshTimer);
            this.refreshTimer = setTimeout(() => void this.refreshCatalogs(true), 500);
        };
        // setNotificationHandler exists on Client (Protocol). Schemas imported above.
        this.client.setNotificationHandler(ToolListChangedNotificationSchema, schedule);
        this.client.setNotificationHandler(ResourceListChangedNotificationSchema, schedule);
        this.client.setNotificationHandler(PromptListChangedNotificationSchema, schedule);
    }
    async refreshCatalogs(notify = false) {
        try {
            const [tools, resources, prompts] = await Promise.all([
                this.client.listTools().catch(() => ({ tools: [] })),
                this.client.listResources().catch(() => ({ resources: [] })),
                this.client.listPrompts().catch(() => ({ prompts: [] })),
            ]);
            this.catalogs = { tools: tools.tools, resources: resources.resources, prompts: prompts.prompts };
            if (notify)
                this.hooks.onCatalogChanged(this);
        }
        catch (e) {
            this.lastError = e.message;
        }
    }
    startHealthChecks() {
        this.healthTimer = setInterval(() => void this.ping(), this.cfg.healthCheckMs);
        this.healthTimer.unref?.();
    }
    async ping() {
        if (this.closed)
            return;
        if (this.breakerState === 'open') {
            if (Date.now() - this.breakerOpenedAt < this.cfg.breakerCooldownMs)
                return;
            // Half-open probe: a successful ping lets the next real call through,
            // so recovery doesn't wait for user traffic.
            try {
                await withTimeout(this.client.ping(), 10_000, `ping server "${this.name}"`);
                this.breakerState = 'half-open';
                this.consecutiveFailures = 0;
                this.lastPingOk = true;
            }
            catch {
                this.breakerOpenedAt = Date.now(); // extend the cooldown
                this.lastPingOk = false;
            }
            return;
        }
        try {
            await withTimeout(this.client.ping(), 10_000, `ping server "${this.name}"`);
            this.lastPingOk = true;
        }
        catch {
            this.lastPingOk = false;
        }
    }
    /**
     * Call a tool on this server. Enforces the circuit breaker, concurrency
     * bound, and per-call timeout. Throws on failure (caller maps to JSON-RPC).
     */
    async callTool(originalName, args) {
        if (this.closed)
            throw new Error(`server "${this.name}" is closed`);
        // Circuit breaker.
        if (this.breakerState === 'open') {
            if (Date.now() - this.breakerOpenedAt >= this.cfg.breakerCooldownMs) {
                this.breakerState = 'half-open';
            }
            else {
                throw new Error(`server "${this.name}" circuit breaker is open (too many failures)`);
            }
        }
        const release = await this.semaphore.acquire();
        try {
            const result = (await withTimeout(this.client.callTool({ name: originalName, arguments: (args ?? {}) }, CallToolResultSchema, {
                timeout: this.cfg.timeoutMs,
            }), this.cfg.timeoutMs + 5_000, `tool "${originalName}" on server "${this.name}"`));
            this.onSuccess();
            return result;
        }
        catch (e) {
            this.onFailure(e);
            throw e;
        }
        finally {
            release();
        }
    }
    onSuccess() {
        this.consecutiveFailures = 0;
        if (this.breakerState === 'half-open')
            this.breakerState = 'closed';
        this.lastError = null;
    }
    /** Read a resource by its ORIGINAL uri. Same breaker/timeout discipline as tools. */
    async readResource(originalUri) {
        if (this.closed)
            throw new Error(`server "${this.name}" is closed`);
        if (this.breakerState === 'open')
            throw new Error(`server "${this.name}" circuit breaker is open (too many failures)`);
        const release = await this.semaphore.acquire();
        try {
            const result = await withTimeout(this.client.readResource({ uri: originalUri }, { timeout: this.cfg.timeoutMs }), this.cfg.timeoutMs + 5_000, `resource "${originalUri}" on server "${this.name}"`);
            this.onSuccess();
            return result;
        }
        catch (e) {
            this.onFailure(e);
            throw e;
        }
        finally {
            release();
        }
    }
    /** Get a prompt by its ORIGINAL name. Same breaker/timeout discipline as tools. */
    async getPrompt(originalName, args) {
        if (this.closed)
            throw new Error(`server "${this.name}" is closed`);
        if (this.breakerState === 'open')
            throw new Error(`server "${this.name}" circuit breaker is open (too many failures)`);
        const release = await this.semaphore.acquire();
        try {
            const result = await withTimeout(this.client.getPrompt({ name: originalName, arguments: args }, { timeout: this.cfg.timeoutMs }), this.cfg.timeoutMs + 5_000, `prompt "${originalName}" on server "${this.name}"`);
            this.onSuccess();
            return result;
        }
        catch (e) {
            this.onFailure(e);
            throw e;
        }
        finally {
            release();
        }
    }
    onFailure(e) {
        if (isClientFault(e)) {
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
    async close() {
        this.closed = true;
        if (this.healthTimer)
            clearInterval(this.healthTimer);
        if (this.refreshTimer)
            clearTimeout(this.refreshTimer);
        if (this.reconnectTimer)
            clearTimeout(this.reconnectTimer);
        try {
            await this.client.close();
        }
        catch {
            /* already gone */
        }
        // Give the child a moment, then make sure a stuck stdio server dies with us.
        await sleep(50);
    }
}
//# sourceMappingURL=downstream.js.map