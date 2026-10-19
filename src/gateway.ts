/**
 * Gateway orchestrator: wires config -> downstream servers -> unified
 * namespace -> routing table -> upstream + admin.
 *
 * The routing table is rebuilt (atomically swapped) whenever a downstream
 * server's catalog changes. A rebuild that throws (e.g. a newly appeared
 * collision under `explicit` strategy) keeps the previous table and logs a
 * warning — a misbehaving server must never take the gateway's namespace down.
 */
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import { AuditLogger } from './audit.js';
import { Metrics } from './metrics.js';
import { RateLimiter } from './ratelimit.js';
import { DownstreamServer } from './downstream.js';
import { GatewayUpstream, publicResourceUri, type PromptEntry, type RoutingTable, type UpstreamDeps } from './upstream.js';
import { buildNamespace, resolveNames, type NamespaceResult } from './namespace.js';
import { configWarnings, type GatewayConfig } from './config.js';
import { VERSION } from './version.js';

export interface Gateway {
  config: GatewayConfig;
  servers: DownstreamServer[];
  upstream: GatewayUpstream;
  audit: AuditLogger;
  metrics: Metrics;
  getNamespace(): NamespaceResult | null;
  reloadCatalogs(): Promise<void>;
  close(): Promise<void>;
  /** set when upstream.http.enabled */
  httpServer?: import('node:http').Server;
  /** set when admin.enabled and not opts.noAdmin */
  adminServer?: import('node:http').Server;
}

export interface StartOptions {
  /** Test hook: pre-built transports keyed by server name (skips spawning). */
  transportOverrides?: Map<string, Transport>;
  /** Skip starting the admin HTTP API (tests). */
  noAdmin?: boolean;
  /** Where operational logs go (stderr in stdio mode). Defaults to console. */
  log?: (msg: string) => void;
  /** Started HTTP upstream server, if enabled. */
  httpServer?: import('node:http').Server;
  /** Started admin server, if enabled. */
  adminServer?: import('node:http').Server;
}

export async function startGateway(cfg: GatewayConfig, opts: StartOptions = {}): Promise<Gateway> {
  const log = opts.log ?? ((m: string) => console.error(m));
  const metrics = new Metrics();
  // Blueprint §5: audit write failures are counted in Prometheus, never
  // fatal to the request path.
  const audit = new AuditLogger(cfg.audit, () => metrics.auditErrors.inc({}));
  metrics.buildInfo.set({ version: VERSION }, 1);
  const rateLimiter = new RateLimiter();

  const state: { namespace: NamespaceResult | null; table: RoutingTable | null } = { namespace: null, table: null };

  const rebuildNamespace = (why: string) => {
    try {
      const catalogs = servers.map((s) => ({ server: s.name, tools: s.getCatalogs().tools }));
      const ns = buildNamespace(catalogs, cfg.namespace);
      state.namespace = ns;
      state.table = buildRoutingTable(servers, ns, cfg);
      for (const w of ns.warnings) log(`[mcpgateway] namespace warning: ${w}`);
      if (why !== 'startup') log(`[mcpgateway] namespace rebuilt (${why}): ${ns.tools.length} tools`);
    } catch (e) {
      // Keep serving the previous table; shout about it.
      log(`[mcpgateway] WARNING: namespace rebuild failed (${why}): ${(e as Error).message} — keeping previous table`);
    }
  };

  const servers = cfg.servers.map(
    (sc) =>
      new DownstreamServer(sc, { onCatalogChanged: () => rebuildNamespace(`catalog change`) }, opts.transportOverrides?.get(sc.name)),
  );

  // Connect sequentially: deterministic startup order, clearer errors.
  for (const s of servers) {
    try {
      await s.connect();
      metrics.serverUp.set({ server: s.name }, 1);
      log(`[mcpgateway] connected to server "${s.name}" (${s.getCatalogs().tools.length} tools)`);
    } catch (e) {
      metrics.serverUp.set({ server: s.name }, 0);
      // Fail-closed at startup: a server we cannot reach is a config error.
      // (At runtime the circuit breaker handles flapping.)
      await closeServers(servers);
      throw new Error(`cannot connect to server "${s.name}": ${(e as Error).message}`);
    }
  }

  rebuildNamespace('startup');
  if (state.table === null || state.namespace === null) {
    await closeServers(servers);
    throw new Error('namespace build failed at startup');
  }
  const ns = state.namespace;
  if (ns.collisions.length > 0) {
    log(`[mcpgateway] ${ns.collisions.length} tool name collision(s) resolved with strategy "${cfg.namespace.strategy}":`);
    for (const c of ns.collisions) {
      log(`[mcpgateway]   "${c.originalName}" (${c.servers.join(', ')}) -> ${c.resolvedAs.join(', ')}`);
    }
  }
  for (const w of configWarnings(cfg)) log(`[mcpgateway] ${w}`);

  const deps: UpstreamDeps = {
    getTable: () => {
      const t = state.table;
      if (t === null) throw new Error('namespace not ready');
      return t;
    },
    policy: cfg.policy,
    rateLimiter,
    defaultRateLimit: cfg.defaultRateLimit,
    perToolRateLimits: cfg.perToolRateLimits,
    audit,
    auditCfg: cfg.audit,
    metrics,
    globalMaxInflight: cfg.globalMaxInflight,
    maxResultChars: cfg.maxResultChars,
    httpMaxSessions: cfg.upstream.http.maxSessions,
    auth: cfg.auth,
  };
  const upstream = new GatewayUpstream(deps);

  // Prune idle rate-limit buckets on a slow timer; unref'd so it never
  // keeps the process alive on its own.
  const pruneTimer = setInterval(() => rateLimiter.pruneIdle(), 60_000);
  pruneTimer.unref?.();

  let adminServer: import('node:http').Server | undefined;
  if (cfg.admin.enabled && !opts.noAdmin) {
    const { startAdmin } = await import('./admin.js');
    adminServer = await startAdmin(
      {
        auth: cfg.auth,
        audit,
        metrics,
        getServers: () => servers,
        getNamespace: () => state.namespace,
        reloadCatalogs: async () => rebuildNamespace('admin reload'),
      },
      cfg.admin.host,
      cfg.admin.port,
    );
    log(`[mcpgateway] admin API on http://${cfg.admin.host}:${cfg.admin.port}`);
  }

  let httpServer: import('node:http').Server | undefined;
  if (cfg.upstream.http.enabled) {
    httpServer = await upstream.listenHttp(cfg.upstream.http.host, cfg.upstream.http.port);
    log(`[mcpgateway] MCP Streamable HTTP on http://${cfg.upstream.http.host}:${cfg.upstream.http.port}/mcp`);
  }

  let closed = false;
  const gateway: Gateway = {
    config: cfg,
    servers,
    upstream,
    audit,
    metrics,
    getNamespace: () => state.namespace,
    reloadCatalogs: async () => rebuildNamespace('manual reload'),
    close: async () => {
      if (closed) return;
      closed = true;
      clearInterval(pruneTimer);
      if (httpServer) await new Promise<void>((r) => httpServer?.close(() => r()));
      if (adminServer) await new Promise<void>((r) => adminServer?.close(() => r()));
      await closeServers(servers);
      audit.close();
    },
  };
  if (httpServer) gateway.httpServer = httpServer;
  if (adminServer) gateway.adminServer = adminServer;
  return gateway;
}

async function closeServers(servers: DownstreamServer[]): Promise<void> {
  await Promise.all(servers.map((s) => s.close().catch(() => undefined)));
}

function buildRoutingTable(servers: DownstreamServer[], ns: NamespaceResult, cfg: GatewayConfig): RoutingTable {
  const byServer = new Map(servers.map((s) => [s.name, s]));
  const table: RoutingTable = {
    tools: new Map(),
    toolMeta: new Map(),
    prompts: new Map(),
    promptMeta: new Map(),
    resources: new Map(),
    resourceMeta: new Map(),
  };

  for (const entry of ns.tools) {
    const server = byServer.get(entry.server);
    if (!server) continue;
    table.tools.set(entry.publicName, { server, original: entry.originalName });
    table.toolMeta.set(entry.publicName, entry);
  }

  // Prompts: same collision strategies, strategy-only (aliases are tool-scoped).
  const promptCatalogs = servers.map((s) => ({ server: s.name, names: s.getCatalogs().prompts.map((p) => p.name) }));
  const resolved = resolveNames(promptCatalogs, { ...cfg.namespace, aliases: {} });
  const promptLookup = new Map<string, { description?: string; args?: PromptEntry['args'] }>();
  for (const s of servers) {
    for (const p of s.getCatalogs().prompts) {
      promptLookup.set(`${s.name}\0${p.name}`, { description: p.description ?? undefined, args: p.arguments });
    }
  }
  for (const [key, publicName] of resolved.assigned) {
    const [srv, orig] = key.split('\0') as [string, string];
    const server = byServer.get(srv);
    const meta = promptLookup.get(key);
    if (!server || !meta) continue;
    table.prompts.set(publicName, { server, original: orig });
    table.promptMeta.set(publicName, { publicName, server: srv, originalName: orig, description: meta.description, args: meta.args });
  }

  // Resources: namespaced by URI rewriting (clients treat URIs opaquely).
  for (const s of servers) {
    for (const r of s.getCatalogs().resources) {
      const publicUri = publicResourceUri(s.name, r.uri);
      table.resources.set(publicUri, { server: s, original: r.uri });
      table.resourceMeta.set(publicUri, { ...r, uri: publicUri });
    }
  }

  return table;
}
