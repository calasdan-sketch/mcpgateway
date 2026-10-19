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
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from 'node:http';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
  ErrorCode,
  type CallToolResult,
  type Prompt,
  type Resource,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import type { DownstreamServer } from './downstream.js';
import type { ToolEntry } from './namespace.js';
import type { AuditLogger, AuditStatus } from './audit.js';
import { collectSecretValues, redactSecretValues } from './audit.js';
import type { Metrics } from './metrics.js';
import type { RateLimiter } from './ratelimit.js';
import { checkResponse, checkToolCall, isHidden } from './policy.js';
import { newRequestId, safeJsonStringify, truncate } from './util.js';
import { VERSION } from './version.js';
import type { AuthKey, PolicyConfig, RateLimitRule } from './config.js';

// ---------------------------------------------------------------------------
// Routing table
// ---------------------------------------------------------------------------

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

export const RESOURCE_SCHEME = 'mcpgateway';

export function publicResourceUri(server: string, originalUri: string): string {
  return `${RESOURCE_SCHEME}://${server}/${encodeURIComponent(originalUri)}`;
}

export function parsePublicResourceUri(publicUri: string): { server: string; originalUri: string } | null {
  const prefix = `${RESOURCE_SCHEME}://`;
  if (!publicUri.startsWith(prefix)) return null;
  const rest = publicUri.slice(prefix.length);
  const slash = rest.indexOf('/');
  if (slash === -1) return null;
  try {
    return { server: rest.slice(0, slash), originalUri: decodeURIComponent(rest.slice(slash + 1)) };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Deps
// ---------------------------------------------------------------------------

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
  auditCfg: { redactKeys: string[] };
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

// ---------------------------------------------------------------------------
// Gateway
// ---------------------------------------------------------------------------

const MAX_BODY_BYTES = 10 * 1024 * 1024;

export class GatewayUpstream {
  private inflight = 0;

  constructor(private deps: UpstreamDeps) {}

  // -- MCP server factory (one instance per transport/session) ----------------

  /** Create the agent-facing MCP server. Handlers always read the CURRENT routing table. */
  createMcpServer(): Server {
    const server = new Server({ name: 'mcpgateway', version: VERSION }, { capabilities: { tools: {}, resources: {}, prompts: {} } });

    server.setRequestHandler(ListToolsRequestSchema, async () => {
      const table = this.deps.getTable();
      const tools: Tool[] = [];
      for (const entry of table.toolMeta.values()) {
        if (isHidden(this.deps.policy, entry.publicName)) continue;
        tools.push({
          name: entry.publicName,
          description: entry.description,
          inputSchema: (entry.inputSchema ?? { type: 'object' }) as Tool['inputSchema'],
        });
      }
      return { tools };
    });

    const ctxOf = (): { sessionId: string; keyId?: string } =>
      sessionContext.get(server) ?? { sessionId: 'stdio', keyId: undefined };

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const name = request.params.name;
      const args = request.params.arguments ?? {};
      return this.handleToolCall(name, args, ctxOf());
    });

    server.setRequestHandler(ListResourcesRequestSchema, async () => {
      const table = this.deps.getTable();
      return { resources: [...table.resourceMeta.values()] };
    });

    server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      return this.handleResourceRead(request.params.uri, ctxOf());
    });

    server.setRequestHandler(ListPromptsRequestSchema, async () => {
      const table = this.deps.getTable();
      const prompts: Prompt[] = [];
      for (const meta of table.promptMeta.values()) {
        prompts.push({ name: meta.publicName, description: meta.description, arguments: meta.args });
      }
      return { prompts };
    });

    server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      return this.handlePromptGet(request.params.name, (request.params.arguments ?? {}) as Record<string, string>, ctxOf());
    });

    return server;
  }

  // -- stdio upstream ----------------------------------------------------------

  async connectStdio(): Promise<void> {
    const server = this.createMcpServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
  }

  // -- Streamable HTTP upstream -------------------------------------------------

  listenHttp(host: string, port: number): Promise<HttpServer> {
    const sessions = new Map<string, StreamableHTTPServerTransport>();
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

  private async handleHttp(
    req: IncomingMessage,
    res: ServerResponse,
    sessions: Map<string, StreamableHTTPServerTransport>,
  ): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname !== '/mcp') {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found (MCP endpoint is POST /mcp)' }));
      return;
    }

    // Edge auth for every HTTP request (GET/POST/DELETE alike).
    const authed = this.authenticateHttp(req);
    if (authed === null) {
      res.writeHead(401, { 'content-type': 'application/json', 'www-authenticate': 'Bearer' });
      res.end(JSON.stringify({ error: 'missing or invalid bearer token' }));
      return;
    }

    if (req.method === 'POST') {
      const body = await readBody(req, res);
      if (body === null) return; // error already written
      const methods = Array.isArray(body) ? body.map((m) => (m as { method?: unknown }).method) : [(body as { method?: unknown }).method];
      for (const method of methods) {
        const scope = scopeForMethod(typeof method === 'string' ? method : '');
        if (scope !== null && !authed.scopes.includes(scope)) {
          res.writeHead(403, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: `key "${authed.keyId}" lacks scope "${scope}"` }));
          return;
        }
      }
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      let transport: StreamableHTTPServerTransport | undefined = sessionId !== undefined ? sessions.get(sessionId) : undefined;
      if (transport === undefined) {
        if (sessionId !== undefined) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'unknown mcp-session-id' }));
          return;
        }
        // Bound the session table: clients that never DELETE would otherwise
        // grow it without limit.
        if (sessions.size >= this.deps.httpMaxSessions) {
          res.writeHead(429, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'too many sessions' }));
          return;
        }
        const server = this.createMcpServer();
        const newTransport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => {
            sessions.set(id, newTransport);
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
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      const transport = sessionId !== undefined ? sessions.get(sessionId) : undefined;
      if (transport === undefined) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'unknown mcp-session-id' }));
        return;
      }
      await transport.handleRequest(req, res);
      return;
    }

    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'method not allowed' }));
  }

  // -- authentication ------------------------------------------------------------

  /** Bearer auth for the HTTP upstream. Returns null when rejected. */
  authenticateHttp(req: IncomingMessage): AuthedKey | null {
    if (this.deps.auth.disabled) return { keyId: 'anonymous', scopes: [...VALID_UPSTREAM_SCOPES] };
    const header = req.headers['authorization'];
    if (typeof header !== 'string' || !header.startsWith('Bearer ')) return null;
    const presented = header.slice('Bearer '.length);
    for (const k of this.deps.auth.keys) {
      if (presented.length === k.key.length && timingSafeEqual(Buffer.from(presented), Buffer.from(k.key))) {
        return { keyId: k.id, scopes: k.scopes };
      }
    }
    return null;
  }

  // -- tool call pipeline ----------------------------------------------------------

  private async handleToolCall(publicName: string, args: unknown, ctx: { sessionId: string; keyId?: string }): Promise<CallToolResult> {
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

    const finish = (status: AuditStatus, extra: Partial<Parameters<AuditLogger['log']>[0]> = {}) => {
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

    // 3. Fleet policy.
    const verdict = checkToolCall(this.deps.policy, publicName, args);
    if (verdict.decision === 'deny' && this.deps.policy.mode === 'enforce') {
      metrics.policyDenials.inc({ tool: publicName, reason: verdict.reason });
      finish('denied', { policyReason: verdict.reason, errorMessage: verdict.detail });
      throw new McpError(-32000, `tool call denied by policy: ${verdict.detail}`, { reason: verdict.reason });
    }
    const wouldDeny = verdict.decision === 'deny' ? verdict.reason : undefined;

    // 3. Rate limit.
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
    const scrub = (s: string): string => redactSecretValues(s, secrets);
    // Set before any throw that has already been audited (policy/size/block),
    // so the catch below doesn't audit twice — but downstream McpErrors must
    // still be audited and scrubbed (the SDK wraps them in McpError too).
    let alreadyAudited = false;
    try {
      const result = await target.server.callTool(target.original, args);
      // 5b. Result-size guard: a malicious or buggy server must not OOM the
      // gateway with a giant payload. (Servers are operator-trusted, but
      // bugs happen; fail the call, not the process.)
      const resultSize = safeJsonStringify(result).length;
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
      const checked = checkResponse(this.deps.policy, result);
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
      return checked.result as CallToolResult;
    } catch (e) {
      if (e instanceof McpError && alreadyAudited) throw e;
      const message = e instanceof Error ? e.message : String(e);
      const scrubbed = scrub(message);
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
    } finally {
      this.inflight -= 1;
      metrics.gatewayInflight.dec({});
      metrics.serverInflight.dec({ server: target.server.name });
    }
  }

  private async handleResourceRead(publicUri: string, ctx: { sessionId: string; keyId?: string }) {
    const reqId = newRequestId();
    const t0 = Date.now();
    const parsed = parsePublicResourceUri(publicUri);
    const table = this.deps.getTable();
    const target = parsed !== null ? table.resources.get(publicUri) : undefined;
    if (target === undefined || parsed === null) {
      throw new McpError(ErrorCode.InvalidParams, `unknown resource "${truncateName(publicUri)}"`);
    }
    try {
      const result = await target.server.readResource(parsed.originalUri);
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
      });
      return result;
    } catch (e) {
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

  private async handlePromptGet(publicName: string, args: Record<string, string>, ctx: { sessionId: string; keyId?: string }) {
    const reqId = newRequestId();
    const t0 = Date.now();
    const table = this.deps.getTable();
    const target = table.prompts.get(publicName);
    if (target === undefined) {
      throw new McpError(ErrorCode.InvalidParams, `unknown prompt "${truncateName(publicName)}"`);
    }
    try {
      const result = await target.server.getPrompt(target.original, args);
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
      });
      return result;
    } catch (e) {
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
const sessionContext = new WeakMap<Server, { sessionId: string; keyId: string }>();

const VALID_UPSTREAM_SCOPES = ['tools:call', 'tools:list', 'resources:*', 'prompts:*', 'admin'];

/** Map an MCP method to the scope required to call it (null = any authed key). */
export function scopeForMethod(method: string): string | null {
  if (method === 'tools/call') return 'tools:call';
  if (method === 'tools/list') return 'tools:list';
  if (method === 'resources/list' || method === 'resources/read' || method === 'resources/subscribe' || method === 'resources/unsubscribe') {
    return 'resources:*';
  }
  if (method === 'prompts/list' || method === 'prompts/get') return 'prompts:*';
  return null; // initialize, ping, notifications, completion — any authed key
}

function truncateName(name: string): string {
  return name.length > 120 ? name.slice(0, 120) + '…' : name;
}

function readBody(req: IncomingMessage, res: ServerResponse): Promise<unknown | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    const fail = (code: number, error: string) => {
      if (done) return;
      done = true;
      if (!res.headersSent) {
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error }));
      }
      resolve(null);
    };
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        fail(413, 'request body too large');
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        fail(400, 'invalid JSON body');
        resolve(null);
      }
    });
    req.on('error', () => fail(400, 'error reading body'));
  });
}
