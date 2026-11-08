/**
 * Admin HTTP API (localhost-bound by default; config refuses public binds
 * without an explicit flag).
 *
 *   GET  /healthz       — open (load-balancer convention): gateway status,
 *                         per-server health, audit error count
 *   GET  /metrics       — Prometheus exposition (admin scope)
 *   GET  /v1/registry   — servers, tool counts, health (any authed key)
 *   GET  /v1/namespace  — unified tool table + collision report (any authed key)
 *   POST /v1/reload     — refresh all downstream catalogs (admin scope)
 */
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from 'node:http';
import type { AuditLogger } from './audit.js';
import type { Metrics } from './metrics.js';
import type { DownstreamServer } from './downstream.js';
import type { NamespaceResult } from './namespace.js';
import type { AuthKey } from './config.js';
import { bearerToken, matchKey, newRequestId } from './util.js';
import { checkHostOrigin } from './upstream.js';
import { redactText } from './audit.js';
import { VERSION } from './version.js';

export interface AdminDeps {
  auth: { disabled: boolean; keys: AuthKey[] };
  audit: AuditLogger;
  metrics: Metrics;
  getServers: () => DownstreamServer[];
  getNamespace: () => NamespaceResult | null;
  reloadCatalogs: () => Promise<void>;
  pins?: { violations: () => string[]; accept: (key?: string) => string[] };
  /** bind host and Host-header allowlist (DNS-rebinding defense) */
  bind?: { host: string; allowedHosts: string[] };
}

function authenticate(req: IncomingMessage, auth: AdminDeps['auth']): { keyId: string; scopes: string[] } | null {
  if (auth.disabled) return { keyId: 'anonymous', scopes: ['admin'] };
  const presented = bearerToken(req.headers['authorization']);
  if (presented === null) return null;
  const k = matchKey(auth.keys, presented);
  return k === null ? null : { keyId: k.id, scopes: k.scopes };
}

function json(res: ServerResponse, code: number, body: unknown): void {
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

export function startAdmin(deps: AdminDeps, host: string, port: number): Promise<HttpServer> {
  const server = createHttpServer((req, res) => {
    void handle(req, res, deps).catch(() => {
      if (!res.headersSent) json(res, 500, { error: 'internal error' });
    });
  });
  server.headersTimeout = 15_000;
  server.requestTimeout = 60_000;
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

function auditAdmin(deps: AdminDeps, who: string, action: string, detail: string): void {
  deps.audit.log({
    ts: new Date().toISOString(),
    reqId: newRequestId(),
    keyId: who,
    tool: `admin:${action}`,
    server: 'gateway',
    originalTool: action,
    durationMs: 0,
    status: 'ok',
    errorMessage: detail || undefined,
  });
}

async function handle(req: IncomingMessage, res: ServerResponse, deps: AdminDeps): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const path = url.pathname;

  // A web page in the operator's browser must not be able to drive the admin API
  // (DNS rebinding turns a hostile site into "localhost"): same check as the MCP endpoint.
  const hostProblem = checkHostOrigin(
    { host: deps.bind?.host ?? '127.0.0.1', allowedHosts: deps.bind?.allowedHosts ?? [], allowedOrigins: [] },
    req.headers['host'],
    typeof req.headers['origin'] === 'string' ? req.headers['origin'] : undefined,
  );
  if (hostProblem !== null) {
    deps.metrics.authFailures.inc({ reason: 'bad_host' });
    json(res, 403, { error: hostProblem });
    return;
  }

  if (req.method === 'GET' && path === '/healthz') {
    // Open for load balancers. Error text from downstream servers is untrusted
    // and can echo secrets, so it is only shown to a caller with a valid key.
    const detailed = !deps.auth.disabled && authenticate(req, deps.auth) !== null;
    const servers = deps.getServers().map((s) => ({
      name: s.name,
      up: s.healthy,
      circuit: s.circuitState,
      inflight: s.inFlight,
      ...(detailed ? { lastPingOk: s.lastPingOk, lastError: s.lastError === null ? null : redactText(s.lastError).slice(0, 300) } : {}),
    }));
    const degraded = servers.some((s) => !s.up) || deps.audit.errors > 0;
    json(res, degraded ? 503 : 200, {
      status: degraded ? 'degraded' : 'ok',
      version: VERSION,
      auditErrors: deps.audit.errors,
      servers,
    });
    return;
  }

  const authed = authenticate(req, deps.auth);
  if (authed === null) {
    deps.metrics.authFailures.inc({ reason: 'bad_key' });
    json(res, 401, { error: 'missing or invalid bearer token' });
    return;
  }
  const isAdmin = authed.scopes.includes('admin');

  if (req.method === 'GET' && path === '/metrics') {
    if (!isAdmin) {
      json(res, 403, { error: `key "${authed.keyId}" lacks scope "admin"` });
      return;
    }
    // server_up was set once at startup; refresh it from live health so the
    // gauge actually tracks outages.
    for (const s of deps.getServers()) deps.metrics.serverUp.set({ server: s.name }, s.healthy ? 1 : 0);
    res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4' });
    res.end(deps.metrics.render());
    return;
  }

  if (req.method === 'GET' && path === '/v1/registry') {
    const ns = deps.getNamespace();
    json(res, 200, {
      version: VERSION,
      servers: deps.getServers().map((s) => ({
        name: s.name,
        up: s.healthy,
        circuit: s.circuitState,
        tools: s.getCatalogs().tools.length,
        resources: s.getCatalogs().resources.length,
        prompts: s.getCatalogs().prompts.length,
      })),
      unifiedTools: ns?.tools.length ?? 0,
      collisions: ns?.collisions ?? [],
    });
    return;
  }

  if (req.method === 'GET' && path === '/v1/namespace') {
    const ns = deps.getNamespace();
    if (ns === null) {
      json(res, 503, { error: 'namespace not built yet' });
      return;
    }
    json(res, 200, {
      tools: ns.tools.map((t) => ({ name: t.publicName, server: t.server, original: t.originalName, description: t.description })),
      collisions: ns.collisions,
      warnings: ns.warnings,
    });
    return;
  }

  if (req.method === 'POST' && path === '/v1/reload') {
    if (!isAdmin) {
      json(res, 403, { error: `key "${authed.keyId}" lacks scope "admin"` });
      return;
    }
    await deps.reloadCatalogs();
    auditAdmin(deps, authed.keyId, 'reload', '');
    json(res, 200, { ok: true });
    return;
  }

  if (req.method === 'GET' && path === '/v1/audit/head') {
    if (!isAdmin) {
      json(res, 403, { error: `key "${authed.keyId}" lacks scope "admin"` });
      return;
    }
    // Store this value somewhere the gateway host cannot rewrite; it is the
    // only defense against truncation of the newest records.
    json(res, 200, deps.audit.head());
    return;
  }

  if (req.method === 'GET' && path === '/v1/pins') {
    json(res, 200, { violations: deps.pins?.violations() ?? [] });
    return;
  }

  if (req.method === 'POST' && path === '/v1/pins/accept') {
    if (!isAdmin) {
      json(res, 403, { error: `key "${authed.keyId}" lacks scope "admin"` });
      return;
    }
    const tool = url.searchParams.get('tool') ?? undefined;
    const accepted = deps.pins?.accept(tool) ?? [];
    auditAdmin(deps, authed.keyId, 'pins.accept', `accepted: ${accepted.join(', ') || 'none'}`);
    json(res, 200, { accepted });
    return;
  }

  json(res, 404, { error: 'not found' });
}
