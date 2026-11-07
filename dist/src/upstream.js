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
import { createServer as createHttpServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, GetPromptRequestSchema, ListPromptsRequestSchema, ListResourcesRequestSchema, ListToolsRequestSchema, McpError, ReadResourceRequestSchema, ErrorCode, } from '@modelcontextprotocol/sdk/types.js';
import { isCancellation } from './downstream.js';
import { collectSecretValues, redactSecretValues, redactText } from './audit.js';
import { checkResponse, checkToolCall, isHidden } from './policy.js';
import { globMatch, matchKey, newRequestId, safeJsonStringify, stripHostile, truncate } from './util.js';
import { VERSION } from './version.js';
export const RESOURCE_SCHEME = 'mcpgateway';
export function publicResourceUri(server, originalUri) {
    return `${RESOURCE_SCHEME}://${server}/${encodeURIComponent(originalUri)}`;
}
export function parsePublicResourceUri(publicUri) {
    const prefix = `${RESOURCE_SCHEME}://`;
    if (!publicUri.startsWith(prefix))
        return null;
    const rest = publicUri.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash === -1)
        return null;
    try {
        return { server: rest.slice(0, slash), originalUri: decodeURIComponent(rest.slice(slash + 1)) };
    }
    catch {
        return null;
    }
}
/** Already audited; the catch blocks must not audit it a second time. */
class PolicyBlockError extends McpError {
    constructor(message) {
        super(-32000, message);
    }
}
export const META_SEARCH = 'gateway_search_tools';
export const META_CALL = 'gateway_call_tool';
const SESSION_IDLE_MS = 30 * 60 * 1000;
const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]', '::1'];
/** Hostname part of a Host header or URL host (port stripped, IPv6 brackets kept). */
export function hostnameOf(hostHeader) {
    const h = hostHeader.trim().toLowerCase();
    if (h.startsWith('[')) {
        const end = h.indexOf(']');
        return end === -1 ? h : h.slice(0, end + 1);
    }
    const colon = h.lastIndexOf(':');
    return colon === -1 ? h : h.slice(0, colon);
}
/**
 * DNS-rebinding / cross-origin check required by the MCP Streamable HTTP spec.
 * Returns an error string or null. Without configuration it protects loopback
 * binds (the case where a browser on the same machine is the threat); a public
 * bind needs allowedHosts/allowedOrigins to be set to be checked.
 */
export function checkHostOrigin(cfg, hostHeader, originHeader) {
    const bindIsLoopback = LOOPBACK_HOSTS.includes(cfg.host.toLowerCase()) || cfg.host.toLowerCase().endsWith('.localhost');
    const hosts = cfg.allowedHosts.length > 0 ? cfg.allowedHosts.map(hostnameOf) : bindIsLoopback ? LOOPBACK_HOSTS : [];
    if (hosts.length > 0) {
        if (hostHeader === undefined || !hosts.includes(hostnameOf(hostHeader)))
            return 'host header not allowed';
    }
    if (originHeader !== undefined) {
        const origin = originHeader.toLowerCase();
        if (cfg.allowedOrigins.length > 0) {
            if (!cfg.allowedOrigins.includes(origin))
                return 'origin not allowed';
        }
        else if (hosts.length > 0) {
            let originHost;
            try {
                originHost = hostnameOf(new URL(origin).host);
            }
            catch {
                return 'origin not allowed';
            }
            if (!hosts.includes(originHost))
                return 'origin not allowed';
        }
    }
    return null;
}
// ---------------------------------------------------------------------------
// Gateway
// ---------------------------------------------------------------------------
const MAX_BODY_BYTES = 10 * 1024 * 1024;
/** JSON-RPC batch cap: processing cost grew faster than linearly (5,000 pings took 4 s). */
const MAX_BATCH = 100;
export class GatewayUpstream {
    deps;
    inflight = 0;
    constructor(deps) {
        this.deps = deps;
    }
    // -- MCP server factory (one instance per transport/session) ----------------
    /** Create the agent-facing MCP server. Handlers always read the CURRENT routing table. */
    createMcpServer() {
        const server = new Server({ name: 'mcpgateway', version: VERSION }, { capabilities: { tools: {}, resources: {}, prompts: {} } });
        const ctxOf = () => sessionContext.get(server) ?? { sessionId: 'stdio', keyId: undefined };
        server.setRequestHandler(ListToolsRequestSchema, async () => {
            const table = this.deps.getTable();
            const keyId = ctxOf().keyId;
            const tools = [];
            if (this.deps.exposure?.mode === 'search') {
                tools.push(...metaTools());
            }
            for (const entry of table.toolMeta.values()) {
                if (this.visibleTo(keyId, entry) === false)
                    continue;
                if (this.deps.exposure?.mode === 'search' && !this.deps.exposure.alwaysExpose.some((g) => globMatch(g, entry.publicName)))
                    continue;
                tools.push(toolForClient(entry));
            }
            return { tools };
        });
        server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
            const name = request.params.name;
            const signal = extra.signal;
            const args = request.params.arguments ?? {};
            if (this.deps.exposure?.mode === 'search') {
                if (name === META_SEARCH)
                    return this.handleSearch(args, ctxOf());
                if (name === META_CALL) {
                    const a = args;
                    if (typeof a.name !== 'string' || a.name.length === 0)
                        throw new McpError(ErrorCode.InvalidParams, `${META_CALL} needs a string "name"`);
                    if (a.name === META_CALL || a.name === META_SEARCH)
                        throw new McpError(ErrorCode.InvalidParams, 'meta-tools cannot call themselves');
                    if (a.arguments !== undefined && (a.arguments === null || typeof a.arguments !== 'object' || Array.isArray(a.arguments))) {
                        throw new McpError(ErrorCode.InvalidParams, `${META_CALL} "arguments" must be an object`);
                    }
                    return this.handleToolCall(a.name, a.arguments ?? {}, ctxOf(), signal);
                }
            }
            return this.handleToolCall(name, args, ctxOf(), signal);
        });
        server.setRequestHandler(ListResourcesRequestSchema, async () => {
            const table = this.deps.getTable();
            const keyId = ctxOf().keyId;
            const resources = [...table.resourceMeta.entries()]
                .filter(([uri]) => this.serverAllowed(keyId, table.resources.get(uri)?.server.name))
                .map(([, r]) => r);
            return { resources };
        });
        server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
            return this.handleResourceRead(request.params.uri, ctxOf());
        });
        server.setRequestHandler(ListPromptsRequestSchema, async () => {
            const table = this.deps.getTable();
            const prompts = [];
            const keyId = ctxOf().keyId;
            for (const meta of table.promptMeta.values()) {
                if (!this.serverAllowed(keyId, meta.server))
                    continue;
                prompts.push({ name: meta.publicName, description: meta.description, arguments: meta.args });
            }
            return { prompts };
        });
        server.setRequestHandler(GetPromptRequestSchema, async (request) => {
            return this.handlePromptGet(request.params.name, (request.params.arguments ?? {}), ctxOf());
        });
        return server;
    }
    // -- stdio upstream ----------------------------------------------------------
    async connectStdio() {
        const server = this.createMcpServer();
        const transport = new StdioServerTransport();
        await server.connect(transport);
    }
    // -- Streamable HTTP upstream -------------------------------------------------
    listenHttp(host, port) {
        const sessions = new Map();
        const httpServer = createHttpServer((req, res) => {
            void this.handleHttp(req, res, sessions).catch((e) => {
                this.deps.metrics.upstreamErrors.inc({});
                if (!res.headersSent) {
                    res.writeHead(500, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ error: 'internal error' }));
                }
                void e;
            });
        });
        return new Promise((resolve, reject) => {
            httpServer.on('error', reject);
            httpServer.listen(port, host, () => resolve(httpServer));
        });
    }
    async handleHttp(req, res, sessions) {
        const url = new URL(req.url ?? '/', 'http://localhost');
        if (url.pathname !== '/mcp') {
            res.writeHead(404, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: 'not found (MCP endpoint is POST /mcp)' }));
            return;
        }
        // DNS-rebinding / cross-origin defense (MCP spec: servers MUST validate Origin).
        const hostProblem = checkHostOrigin(this.deps.http ?? { host: '127.0.0.1', allowedHosts: [], allowedOrigins: [] }, req.headers['host'], typeof req.headers['origin'] === 'string' ? req.headers['origin'] : undefined);
        if (hostProblem !== null) {
            this.authFailure('bad_host', req, hostProblem);
            res.writeHead(403, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ error: hostProblem }));
            return;
        }
        // Edge auth for every HTTP request (GET/POST/DELETE alike).
        const authed = this.authenticateHttp(req);
        if (authed === null) {
            this.authFailure('bad_key', req, 'missing, invalid or expired bearer token');
            res.writeHead(401, { 'content-type': 'application/json', 'www-authenticate': 'Bearer' });
            res.end(JSON.stringify({ error: 'missing or invalid bearer token' }));
            return;
        }
        if (req.method === 'POST') {
            const parsedBody = await readBody(req, res);
            if (parsedBody === FAILED)
                return; // error already written
            const body = parsedBody;
            const items = Array.isArray(body) ? body : [body];
            if (items.length > MAX_BATCH) {
                res.writeHead(413, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: `batch of ${items.length} messages exceeds the limit of ${MAX_BATCH}` }));
                return;
            }
            if (items.length === 0 || items.some((m) => m === null || typeof m !== 'object' || Array.isArray(m))) {
                res.writeHead(400, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: 'body must be a JSON-RPC message or a non-empty array of them' }));
                return;
            }
            const methods = items.map((m) => m.method);
            for (const method of methods) {
                const scope = scopeForMethod(typeof method === 'string' ? method : '');
                if (scope !== null && !authed.scopes.includes(scope)) {
                    this.authFailure('missing_scope', req, `key "${authed.keyId}" lacks scope "${scope}"`, authed.keyId);
                    res.writeHead(403, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ error: `key "${authed.keyId}" lacks scope "${scope}"` }));
                    return;
                }
            }
            const sessionId = req.headers['mcp-session-id'];
            const existing = sessionId !== undefined ? sessions.get(sessionId) : undefined;
            if (existing !== undefined && existing.keyId !== authed.keyId) {
                // A session belongs to the key that opened it.
                this.authFailure('wrong_session_key', req, 'session belongs to a different key', authed.keyId);
                res.writeHead(403, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: 'session belongs to a different key' }));
                return;
            }
            if (existing !== undefined)
                existing.lastSeen = Date.now();
            let transport = existing?.transport;
            if (transport === undefined) {
                if (sessionId !== undefined) {
                    res.writeHead(400, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ error: 'unknown mcp-session-id' }));
                    return;
                }
                // Bound the session table: clients that never DELETE would otherwise
                // grow it without limit.
                // Abandoned sessions expire, and no single key may hold more than half
                // the table (otherwise one key could lock every other agent out).
                await this.sweepSessions(sessions);
                const perKeyCap = Math.max(1, Math.floor(this.deps.httpMaxSessions / 2));
                const mine = [...sessions.values()].filter((x) => x.keyId === authed.keyId).length;
                if (sessions.size >= this.deps.httpMaxSessions || mine >= perKeyCap) {
                    res.writeHead(429, { 'content-type': 'application/json' });
                    res.end(JSON.stringify({ error: 'too many sessions' }));
                    return;
                }
                const server = this.createMcpServer();
                const newTransport = new StreamableHTTPServerTransport({
                    sessionIdGenerator: () => randomUUID(),
                    onsessioninitialized: (id) => {
                        sessions.set(id, { transport: newTransport, keyId: authed.keyId, lastSeen: Date.now() });
                        // Real session id for audit records on this session's calls.
                        sessionContext.set(server, { sessionId: id, keyId: authed.keyId });
                    },
                    onsessionclosed: (id) => {
                        sessions.delete(id);
                    },
                });
                await server.connect(newTransport);
                transport = newTransport;
            }
            await transport.handleRequest(req, res, body);
            return;
        }
        if (req.method === 'GET' || req.method === 'DELETE') {
            const sessionId = req.headers['mcp-session-id'];
            const entry = sessionId !== undefined ? sessions.get(sessionId) : undefined;
            if (entry === undefined) {
                res.writeHead(400, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: 'unknown mcp-session-id' }));
                return;
            }
            if (entry.keyId !== authed.keyId) {
                this.authFailure('wrong_session_key', req, 'session belongs to a different key', authed.keyId);
                res.writeHead(403, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error: 'session belongs to a different key' }));
                return;
            }
            entry.lastSeen = Date.now();
            await entry.transport.handleRequest(req, res);
            return;
        }
        res.writeHead(405, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'method not allowed' }));
    }
    async sweepSessions(sessions) {
        const ttl = this.deps.http?.sessionIdleMs ?? SESSION_IDLE_MS;
        const now = Date.now();
        for (const [id, s] of [...sessions]) {
            if (now - s.lastSeen > ttl) {
                sessions.delete(id);
                await s.transport.close().catch(() => undefined);
            }
        }
    }
    // -- per-key access --------------------------------------------------------------
    keyOf(keyId) {
        return keyId === undefined ? undefined : this.deps.auth.keys.find((k) => k.id === keyId);
    }
    /** Is this server inside the key's allowServers? (no key / no restriction = yes) */
    serverAllowed(keyId, server) {
        const k = this.keyOf(keyId);
        if (k?.allowServers === undefined)
            return true;
        return server !== undefined && k.allowServers.some((g) => globMatch(g, server));
    }
    /** May this key see/call this tool? (no key = stdio/anonymous = unrestricted here) */
    visibleTo(keyId, entry) {
        const publicName = entry.publicName;
        if (isHidden(this.deps.policy, publicName))
            return false;
        const k = this.keyOf(keyId);
        if (k === undefined)
            return true;
        if (k.denyTools?.some((g) => globMatch(g, publicName)))
            return false;
        if (k.allowTools !== undefined && !k.allowTools.some((g) => globMatch(g, publicName)))
            return false;
        if (!this.serverAllowed(keyId, entry.server))
            return false;
        // Fail closed: a tool is read-only only if its server said so explicitly.
        if (k.readOnly === true && entry.annotations?.['readOnlyHint'] !== true)
            return false;
        return true;
    }
    authFailWindowStart = 0;
    authFailLogged = 0;
    authFailSuppressed = 0;
    /**
     * Record a rejected request. Counted always; written to the audit log at
     * most 30 times a minute (a flood of bad keys must not fill the log), with
     * a summary record of what was dropped when the window rolls over.
     */
    authFailure(reason, req, detail, keyId) {
        this.deps.metrics.authFailures.inc({ reason });
        const now = Date.now();
        if (now - this.authFailWindowStart > 60_000) {
            if (this.authFailSuppressed > 0) {
                this.deps.audit.log({
                    ts: new Date().toISOString(), reqId: newRequestId(), tool: '(edge)', server: 'gateway', originalTool: '(edge)', durationMs: 0,
                    status: 'auth_failed', errorCode: 'suppressed', errorMessage: `${this.authFailSuppressed} further rejected request(s) not logged in the previous minute`,
                });
            }
            this.authFailWindowStart = now;
            this.authFailLogged = 0;
            this.authFailSuppressed = 0;
        }
        if (this.authFailLogged >= 30) {
            this.authFailSuppressed += 1;
            return;
        }
        this.authFailLogged += 1;
        this.deps.audit.log({
            ts: new Date(now).toISOString(), reqId: newRequestId(), keyId, tool: '(edge)', server: 'gateway', originalTool: '(edge)', durationMs: 0,
            status: 'auth_failed', errorCode: reason, errorMessage: `${detail} (from ${req.socket.remoteAddress ?? 'unknown'})`,
        });
    }
    /** Per-key budget across all tools/resources/prompts. true = allowed. */
    keyBudgetOk(keyId) {
        const k = this.keyOf(keyId);
        if (k?.rateLimit === undefined)
            return true;
        return this.deps.rateLimiter.tryAcquire(`key\0${k.id}`, k.rateLimit);
    }
    // -- search meta-tool ------------------------------------------------------------
    handleSearch(args, ctx) {
        const a = (args ?? {});
        if (typeof a.query !== 'string' || a.query.length === 0 || a.query.length > 500) {
            throw new McpError(ErrorCode.InvalidParams, `${META_SEARCH} needs a "query" string (1-500 chars)`);
        }
        const limit = typeof a.limit === 'number' && Number.isFinite(a.limit) ? Math.min(25, Math.max(1, Math.floor(a.limit))) : 8;
        if (!this.keyBudgetOk(ctx.keyId))
            throw new McpError(-32000, 'rate limit exceeded for this key', { retryable: true });
        const tokens = a.query.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 0).slice(0, 20);
        const scored = [];
        for (const entry of this.deps.getTable().toolMeta.values()) {
            if (!this.visibleTo(ctx.keyId, entry))
                continue;
            const name = entry.publicName.toLowerCase();
            const desc = (entry.description ?? '').toLowerCase();
            let score = 0;
            for (const t of tokens) {
                if (name === t)
                    score += 6;
                else if (name.includes(t))
                    score += 3;
                if (desc.includes(t))
                    score += 1;
            }
            if (score > 0)
                scored.push({ score, entry });
        }
        scored.sort((x, y) => y.score - x.score || (x.entry.publicName < y.entry.publicName ? -1 : 1));
        const results = scored.slice(0, limit).map(({ entry }) => {
            const t = toolForClient(entry);
            return { name: t.name, description: t.description, inputSchema: t.inputSchema, ...(t.annotations ? { annotations: t.annotations } : {}) };
        });
        this.deps.audit.log({
            ts: new Date().toISOString(),
            reqId: newRequestId(),
            sessionId: ctx.sessionId,
            keyId: ctx.keyId,
            tool: META_SEARCH,
            server: 'gateway',
            originalTool: META_SEARCH,
            durationMs: 0,
            status: 'ok',
            args,
        });
        return { content: [{ type: 'text', text: JSON.stringify({ matches: results, total: scored.length }) }] };
    }
    // -- authentication ------------------------------------------------------------
    /** Bearer auth for the HTTP upstream. Returns null when rejected. */
    authenticateHttp(req) {
        if (this.deps.auth.disabled)
            return { keyId: 'anonymous', scopes: [...VALID_UPSTREAM_SCOPES] };
        const header = req.headers['authorization'];
        if (typeof header !== 'string' || !header.startsWith('Bearer '))
            return null;
        const presented = header.slice('Bearer '.length);
        const k = matchKey(this.deps.auth.keys, presented);
        return k === null ? null : { keyId: k.id, scopes: k.scopes };
    }
    // -- tool call pipeline ----------------------------------------------------------
    async handleToolCall(publicName, args, ctx, signal) {
        const { metrics, audit } = this.deps;
        const reqId = newRequestId();
        const t0 = Date.now();
        const table = this.deps.getTable();
        const target = table.tools.get(publicName);
        if (target === undefined) {
            // Recon probes for tool names are worth an audit record too. The
            // metric label stays fixed ('unknown'): the name is caller-controlled
            // and must never become a metric label (cardinality DoS).
            audit.log({
                ts: new Date().toISOString(),
                reqId,
                sessionId: ctx.sessionId,
                keyId: ctx.keyId,
                tool: publicName,
                server: 'unknown',
                originalTool: publicName,
                durationMs: Date.now() - t0,
                status: 'error',
                errorCode: 'unknown_tool',
                errorMessage: `unknown tool "${truncateName(publicName)}"`,
                args,
            });
            metrics.toolCalls.inc({ server: 'unknown', tool: 'unknown', status: 'error' });
            throw new McpError(ErrorCode.InvalidParams, `unknown tool "${truncateName(publicName)}"`);
        }
        const finish = (status, extra = {}) => {
            const durationMs = Date.now() - t0;
            audit.log({
                ts: new Date().toISOString(),
                reqId,
                sessionId: ctx.sessionId,
                keyId: ctx.keyId,
                tool: publicName,
                server: target.server.name,
                originalTool: target.original,
                durationMs,
                status,
                args,
                ...extra,
            });
            metrics.toolCalls.inc({ server: target.server.name, tool: publicName, status });
            metrics.keyCalls.inc({ key: ctx.keyId ?? 'none', status });
            metrics.toolDuration.observe({ server: target.server.name, tool: publicName }, durationMs / 1000);
        };
        // 2. Hidden tools are denied unconditionally: hiding is access control,
        // not a policy verdict — observe mode must not forward what agents
        // cannot even see. The caller gets the same "unknown tool" error as for
        // unmapped names: confirming a hidden tool's existence would defeat the
        // hiding (existence oracle). The audit record keeps the real reason for
        // the operator.
        if (isHidden(this.deps.policy, publicName)) {
            metrics.policyDenials.inc({ tool: publicName, reason: 'hidden' });
            finish('denied', { policyReason: 'hidden', errorMessage: `tool "${publicName}" is hidden by policy` });
            throw new McpError(ErrorCode.InvalidParams, `unknown tool "${truncateName(publicName)}"`);
        }
        // 2b. Per-key ACL: a key that may not see a tool gets the same masked
        // "unknown tool" error as for a hidden one.
        const meta = table.toolMeta.get(publicName);
        if (meta === undefined || !this.visibleTo(ctx.keyId, meta)) {
            metrics.policyDenials.inc({ tool: publicName, reason: 'key_acl' });
            finish('denied', { policyReason: 'key_acl', errorMessage: `tool "${publicName}" is not permitted for key "${ctx.keyId ?? ''}"` });
            throw new McpError(ErrorCode.InvalidParams, `unknown tool "${truncateName(publicName)}"`);
        }
        // 3. Fleet policy.
        const verdict = checkToolCall(this.deps.policy, publicName, args);
        if (verdict.decision === 'deny' && this.deps.policy.mode === 'enforce') {
            metrics.policyDenials.inc({ tool: publicName, reason: verdict.reason });
            finish('denied', { policyReason: verdict.reason, errorMessage: verdict.detail });
            throw new McpError(-32000, `tool call denied by policy: ${verdict.detail}`, { reason: verdict.reason });
        }
        const wouldDeny = verdict.decision === 'deny' ? verdict.reason : undefined;
        // 3. Rate limit: per-key budget first (so one agent cannot starve the rest), then per-tool.
        if (!this.keyBudgetOk(ctx.keyId)) {
            metrics.rateLimitHits.inc({ tool: publicName });
            finish('rate_limited', { errorMessage: `key "${ctx.keyId ?? ''}" exceeded its rate limit` });
            throw new McpError(-32000, 'rate limit exceeded for this key', { retryable: true });
        }
        const rule = this.deps.perToolRateLimits[publicName] ?? this.deps.defaultRateLimit;
        if (!this.deps.rateLimiter.tryAcquire(publicName, rule)) {
            metrics.rateLimitHits.inc({ tool: publicName });
            finish('rate_limited', {
                policyReason: wouldDeny !== undefined ? `would_deny:${wouldDeny}` : undefined,
                errorMessage: `rate limit exceeded for "${publicName}" (${rule.rps} rps, burst ${rule.burst})`,
            });
            throw new McpError(-32000, `rate limit exceeded for tool "${publicName}"`, { retryable: true });
        }
        // 4. Global in-flight cap — the gateway must never be what falls over.
        if (this.inflight >= this.deps.globalMaxInflight) {
            finish('error', { errorCode: 'gateway_overloaded', errorMessage: 'gateway at max in-flight capacity' });
            throw new McpError(-32000, 'gateway overloaded: too many in-flight tool calls', { retryable: true });
        }
        // 5. Downstream call.
        this.inflight += 1;
        metrics.gatewayInflight.inc({});
        metrics.serverInflight.inc({ server: target.server.name });
        // Secret values from this call's args, for scrubbing downstream errors.
        const secrets = collectSecretValues(args, this.deps.auditCfg.redactKeys);
        const scrub = (s) => redactSecretValues(s, secrets);
        // Set before any throw that has already been audited (policy/size/block),
        // so the catch below doesn't audit twice — but downstream McpErrors must
        // still be audited and scrubbed (the SDK wraps them in McpError too).
        let alreadyAudited = false;
        try {
            const result = await target.server.callTool(target.original, args, signal);
            // 5b. Result-size guard: a malicious or buggy server must not OOM the
            // gateway with a giant payload. (Servers are operator-trusted, but
            // bugs happen; fail the call, not the process.)
            const resultJson = safeJsonStringify(result);
            const resultSize = resultJson.length;
            if (resultSize > this.deps.maxResultChars) {
                finish('error', {
                    policyReason: wouldDeny !== undefined ? `would_deny:${wouldDeny}` : undefined,
                    errorCode: 'result_too_large',
                    errorMessage: `tool result was ${resultSize} chars (max ${this.deps.maxResultChars})`,
                });
                alreadyAudited = true;
                throw new McpError(-32000, `tool result exceeded the ${this.deps.maxResultChars}-char limit`, { retryable: false });
            }
            // 6. Response egress rules (structured redaction — never breaks JSON).
            const checked = checkResponse(this.deps.policy, result, resultJson);
            if (checked.action === 'block') {
                finish('blocked', {
                    policyReason: wouldDeny !== undefined ? `would_deny:${wouldDeny}` : undefined,
                    errorMessage: 'tool result blocked by policy response rules',
                });
                alreadyAudited = true;
                throw new McpError(-32000, 'tool result blocked by policy');
            }
            finish('ok', {
                policyReason: wouldDeny !== undefined ? `would_deny:${wouldDeny}` : undefined,
                redactions: checked.redactions || undefined,
            });
            return checked.result;
        }
        catch (e) {
            if (e instanceof McpError && alreadyAudited)
                throw e;
            const message = (e instanceof Error ? e.message : String(e)).replace(/^(MCP error -?\d+: )+/, '');
            const scrubbed = redactText(scrub(message));
            const cancelled = signal?.aborted === true || isCancellation(e);
            if (cancelled) {
                metrics.cancelled.inc({});
                finish('error', { errorCode: 'cancelled', errorMessage: 'cancelled by the client' });
                throw new McpError(-32000, `tool "${publicName}" was cancelled`);
            }
            const timedOut = /timed out/i.test(scrubbed);
            // Preserve the downstream JSON-RPC code when there is one (more
            // truthful than flattening everything to -32000).
            const code = !timedOut && e instanceof McpError ? e.code : -32000;
            const { text } = truncate(scrubbed, 1000);
            finish(timedOut ? 'timeout' : 'error', {
                policyReason: wouldDeny !== undefined ? `would_deny:${wouldDeny}` : undefined,
                errorCode: timedOut ? 'timeout' : 'downstream_error',
                errorMessage: text,
            });
            throw new McpError(code, `tool "${publicName}" failed: ${truncate(scrubbed, 500).text}`);
        }
        finally {
            this.inflight -= 1;
            metrics.gatewayInflight.dec({});
            metrics.serverInflight.dec({ server: target.server.name });
        }
    }
    async handleResourceRead(publicUri, ctx) {
        const reqId = newRequestId();
        const t0 = Date.now();
        const parsed = parsePublicResourceUri(publicUri);
        const table = this.deps.getTable();
        const target = parsed !== null ? table.resources.get(publicUri) : undefined;
        if (target === undefined || parsed === null) {
            throw new McpError(ErrorCode.InvalidParams, `unknown resource "${truncateName(publicUri)}"`);
        }
        if (!this.serverAllowed(ctx.keyId, target.server.name)) {
            throw new McpError(ErrorCode.InvalidParams, `unknown resource "${truncateName(publicUri)}"`);
        }
        if (!this.keyBudgetOk(ctx.keyId))
            throw new McpError(-32000, 'rate limit exceeded for this key', { retryable: true });
        try {
            const raw = await target.server.readResource(parsed.originalUri);
            // Egress rules apply to resources exactly as to tool results.
            const checked = checkResponse(this.deps.policy, raw);
            if (checked.action === 'block') {
                this.deps.audit.log({
                    ts: new Date().toISOString(),
                    reqId,
                    sessionId: ctx.sessionId,
                    keyId: ctx.keyId,
                    tool: `resource:${publicUri}`,
                    server: target.server.name,
                    originalTool: parsed.originalUri,
                    durationMs: Date.now() - t0,
                    status: 'blocked',
                    errorMessage: 'resource blocked by policy response rules',
                });
                throw new PolicyBlockError('resource blocked by policy');
            }
            const result = checked.result;
            this.deps.audit.log({
                ts: new Date().toISOString(),
                reqId,
                sessionId: ctx.sessionId,
                keyId: ctx.keyId,
                tool: `resource:${publicUri}`,
                server: target.server.name,
                originalTool: parsed.originalUri,
                durationMs: Date.now() - t0,
                status: 'ok',
                redactions: checked.redactions || undefined,
            });
            return result;
        }
        catch (e) {
            if (e instanceof PolicyBlockError)
                throw e;
            const message = e instanceof Error ? e.message : String(e);
            this.deps.audit.log({
                ts: new Date().toISOString(),
                reqId,
                sessionId: ctx.sessionId,
                keyId: ctx.keyId,
                tool: `resource:${publicUri}`,
                server: target.server.name,
                originalTool: parsed.originalUri,
                durationMs: Date.now() - t0,
                status: 'error',
                errorCode: 'downstream_error',
                errorMessage: truncate(message, 1000).text,
            });
            throw new McpError(-32000, `resource read failed: ${truncate(message, 500).text}`);
        }
    }
    async handlePromptGet(publicName, args, ctx) {
        const reqId = newRequestId();
        const t0 = Date.now();
        const table = this.deps.getTable();
        const target = table.prompts.get(publicName);
        if (target === undefined) {
            throw new McpError(ErrorCode.InvalidParams, `unknown prompt "${truncateName(publicName)}"`);
        }
        if (!this.serverAllowed(ctx.keyId, target.server.name)) {
            throw new McpError(ErrorCode.InvalidParams, `unknown prompt "${truncateName(publicName)}"`);
        }
        if (!this.keyBudgetOk(ctx.keyId))
            throw new McpError(-32000, 'rate limit exceeded for this key', { retryable: true });
        try {
            const raw = await target.server.getPrompt(target.original, args);
            const checked = checkResponse(this.deps.policy, raw);
            if (checked.action === 'block') {
                this.deps.audit.log({
                    ts: new Date().toISOString(),
                    reqId,
                    sessionId: ctx.sessionId,
                    keyId: ctx.keyId,
                    tool: `prompt:${publicName}`,
                    server: target.server.name,
                    originalTool: target.original,
                    durationMs: Date.now() - t0,
                    status: 'blocked',
                    errorMessage: 'prompt blocked by policy response rules',
                    args,
                });
                throw new PolicyBlockError('prompt blocked by policy');
            }
            const result = checked.result;
            this.deps.audit.log({
                ts: new Date().toISOString(),
                reqId,
                sessionId: ctx.sessionId,
                keyId: ctx.keyId,
                tool: `prompt:${publicName}`,
                server: target.server.name,
                originalTool: target.original,
                durationMs: Date.now() - t0,
                status: 'ok',
                args,
                redactions: checked.redactions || undefined,
            });
            return result;
        }
        catch (e) {
            if (e instanceof PolicyBlockError)
                throw e;
            const message = e instanceof Error ? e.message : String(e);
            this.deps.audit.log({
                ts: new Date().toISOString(),
                reqId,
                sessionId: ctx.sessionId,
                keyId: ctx.keyId,
                tool: `prompt:${publicName}`,
                server: target.server.name,
                originalTool: target.original,
                durationMs: Date.now() - t0,
                status: 'error',
                errorCode: 'downstream_error',
                errorMessage: truncate(message, 1000).text,
                args,
            });
            throw new McpError(-32000, `prompt failed: ${truncate(message, 500).text}`);
        }
    }
}
// Per-session audit context for HTTP sessions. The SDK Server handlers are
// registered once per server instance; tagSession stores the context here.
const sessionContext = new WeakMap();
const VALID_UPSTREAM_SCOPES = ['tools:call', 'tools:list', 'resources:*', 'prompts:*', 'admin'];
/** Map an MCP method to the scope required to call it (null = any authed key). */
export function scopeForMethod(method) {
    if (method === 'tools/call')
        return 'tools:call';
    if (method === 'tools/list')
        return 'tools:list';
    if (method === 'resources/list' || method === 'resources/read' || method === 'resources/subscribe' || method === 'resources/unsubscribe') {
        return 'resources:*';
    }
    if (method === 'prompts/list' || method === 'prompts/get')
        return 'prompts:*';
    return null; // initialize, ping, notifications, completion — any authed key
}
function metaTools() {
    return [
        {
            name: META_SEARCH,
            description: 'Find tools by keyword. Returns matching tool names, descriptions and input schemas. Call this first, then call a match with gateway_call_tool.',
            inputSchema: {
                type: 'object',
                properties: { query: { type: 'string', description: 'keywords, e.g. "create issue"' }, limit: { type: 'number', description: 'max results (default 8, max 25)' } },
                required: ['query'],
            },
        },
        {
            name: META_CALL,
            description: 'Call any tool found with gateway_search_tools. Fleet policy, rate limits and audit apply exactly as for a direct call.',
            inputSchema: {
                type: 'object',
                properties: { name: { type: 'string', description: 'tool name from search results' }, arguments: { type: 'object', description: 'arguments for that tool' } },
                required: ['name'],
            },
        },
    ];
}
/** The tools/list shape for one tool, including what clients use to decide (annotations, outputSchema, title). */
function toolForClient(entry) {
    const t = {
        name: entry.publicName,
        description: entry.description,
        inputSchema: (entry.inputSchema ?? { type: 'object' }),
    };
    if (entry.annotations !== undefined)
        t.annotations = entry.annotations;
    if (entry.outputSchema !== undefined)
        t.outputSchema = entry.outputSchema;
    if (entry.title !== undefined)
        t.title = entry.title;
    return t;
}
function truncateName(name) {
    const clean = stripHostile(name).text;
    return clean.length > 120 ? clean.slice(0, 120) + '…' : clean;
}
/** Sentinel: JSON `null` is a valid body, so failure needs its own marker (a bare null used to leave the request hanging). */
const FAILED = Symbol('body-failed');
function readBody(req, res) {
    return new Promise((resolve) => {
        const chunks = [];
        let size = 0;
        let done = false;
        const fail = (code, error) => {
            if (done)
                return;
            done = true;
            if (!res.headersSent) {
                res.writeHead(code, { 'content-type': 'application/json' });
                res.end(JSON.stringify({ error }));
            }
            resolve(FAILED);
        };
        req.on('data', (chunk) => {
            size += chunk.length;
            if (size > MAX_BODY_BYTES) {
                fail(413, 'request body too large');
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            if (done)
                return;
            let parsed;
            try {
                parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            }
            catch {
                // fail() must run while `done` is still false, or the client is never answered
                // (0.3.0 left a request with an empty or truncated JSON body hanging forever).
                fail(400, 'invalid JSON body');
                return;
            }
            done = true;
            resolve(parsed);
        });
        req.on('error', () => fail(400, 'error reading body'));
    });
}
//# sourceMappingURL=upstream.js.map