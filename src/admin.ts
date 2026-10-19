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
import { timingSafeEqual } from 'node:crypto';
import type { AuditLogger } from './audit.js';
import type { Metrics } from './metrics.js';
import type { DownstreamServer } from './downstream.js';
import type { NamespaceResult } from './namespace.js';
import type { AuthKey } from './config.js';
import { VERSION } from './version.js';

export interface AdminDeps {
  auth: { disabled: boolean; keys: AuthKey[] };
  audit: AuditLogger;
  metrics: Metrics;
  getServers: () => DownstreamServer[];
  getNamespace: () => NamespaceResult | null;
  reloadCatalogs: () => Promise<void>;
}

function authenticate(req: IncomingMessage, auth: AdminDeps['auth']): { keyId: string; scopes: string[] } | null {
  if (auth.disabled) return { keyId: 'anonymous', scopes: ['admin'] };
  const header = req.headers['authorization'];
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return null;
  const presented = header.slice('Bearer '.length);
  for (const k of auth.keys) {
    if (presented.length === k.key.length && timingSafeEqual(Buffer.from(presented), Buffer.from(k.key))) {
      return { keyId: k.id, scopes: k.scopes };
    }
  }
  return null;
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
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

async function handle(req: IncomingMessage, res: ServerResponse, deps: AdminDeps): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const path = url.pathname;

  if (req.method === 'GET' && path === '/healthz') {
    const servers = deps.getServers().map((s) => ({
      name: s.name,
      up: s.healthy,
      circuit: s.circuitState,
      inflight: s.inFlight,
      lastPingOk: s.lastPingOk,
      lastError: s.lastError,
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
    json(res, 401, { error: 'missing or invalid bearer token' });
    return;
  }
  const isAdmin = authed.scopes.includes('admin');

  if (req.method === 'GET' && path === '/metrics') {
    if (!isAdmin) {
      json(res, 403, { error: `key "${authed.keyId}" lacks scope "admin"` });
      return;
    }
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
    json(res, 200, { ok: true });
    return;
  }

  json(res, 404, { error: 'not found' });
}
