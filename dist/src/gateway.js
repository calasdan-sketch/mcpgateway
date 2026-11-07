/**
 * Gateway orchestrator: wires config -> downstream servers -> unified
 * namespace -> routing table -> upstream + admin.
 *
 * The routing table is rebuilt (atomically swapped) whenever a downstream
 * server's catalog changes. A rebuild that throws (e.g. a newly appeared
 * collision under `explicit` strategy) keeps the previous table and logs a
 * warning — a misbehaving server must never take the gateway's namespace down.
 */
import { AuditLogger } from './audit.js';
import { Metrics } from './metrics.js';
import { RateLimiter } from './ratelimit.js';
import { DownstreamServer } from './downstream.js';
import { GatewayUpstream, publicResourceUri } from './upstream.js';
import { buildNamespace, resolveNames } from './namespace.js';
import { configWarnings } from './config.js';
import { VERSION } from './version.js';
import { PinRegistry, suspiciousDescription } from './pins.js';
import { stripHostile } from './util.js';
export async function startGateway(cfg, opts = {}) {
    // Everything logged may contain server-controlled text (tool names, errors): neutralize terminal control and bidi characters.
    const sink = opts.log ?? ((m) => console.error(m));
    const log = (m) => sink(stripHostile(m).text.replace(/[\r\n]+/g, ' ⏎ '));
    const metrics = new Metrics();
    // Blueprint §5: audit write failures are counted in Prometheus, never
    // fatal to the request path.
    const audit = new AuditLogger(cfg.audit, () => metrics.auditErrors.inc({}));
    metrics.buildInfo.set({ version: VERSION }, 1);
    const rateLimiter = new RateLimiter();
    // Throws on a corrupt pin file in block/warn mode: fail closed at startup.
    const pins = new PinRegistry(cfg.policy.pinning ?? { mode: 'off' });
    const state = { namespace: null, table: null };
    const rebuildNamespace = (why) => {
        try {
            const catalogs = servers.map((s) => ({ server: s.name, tools: s.getCatalogs().tools }));
            const ns = hardenNamespace(buildNamespace(catalogs, cfg.namespace), pins, metrics, audit, log);
            state.namespace = ns;
            state.table = buildRoutingTable(servers, ns, cfg);
            for (const w of ns.warnings)
                log(`[mcpgateway] namespace warning: ${w}`);
            if (why !== 'startup')
                log(`[mcpgateway] namespace rebuilt (${why}): ${ns.tools.length} tools`);
        }
        catch (e) {
            // Keep serving the previous table; shout about it.
            log(`[mcpgateway] WARNING: namespace rebuild failed (${why}): ${e.message} — keeping previous table`);
        }
    };
    const servers = cfg.servers.map((sc) => new DownstreamServer(sc, {
        onCatalogChanged: () => rebuildNamespace(`catalog change`),
        onReconnected: (srv) => {
            metrics.serverReconnects.inc({ server: srv.name });
            log(`[mcpgateway] server "${srv.name}" reconnected`);
        },
        ...(opts.onChildStderr ? { onChildStderr: opts.onChildStderr } : {}),
    }, opts.transportOverrides?.get(sc.name)));
    // Connect sequentially: deterministic startup order, clearer errors.
    for (const s of servers) {
        try {
            await s.connect();
            metrics.serverUp.set({ server: s.name }, 1);
            log(`[mcpgateway] connected to server "${s.name}" (${s.getCatalogs().tools.length} tools)`);
        }
        catch (e) {
            metrics.serverUp.set({ server: s.name }, 0);
            // Fail-closed at startup: a server we cannot reach is a config error.
            // (At runtime the circuit breaker handles flapping.)
            await closeServers(servers);
            throw new Error(`cannot connect to server "${s.name}": ${e.message}`);
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
    for (const w of configWarnings(cfg))
        log(`[mcpgateway] ${w}`);
    const deps = {
        getTable: () => {
            const t = state.table;
            if (t === null)
                throw new Error('namespace not ready');
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
        exposure: cfg.exposure,
        http: { host: cfg.upstream.http.host, allowedHosts: cfg.upstream.http.allowedHosts, allowedOrigins: cfg.upstream.http.allowedOrigins },
    };
    const upstream = new GatewayUpstream(deps);
    // Prune idle rate-limit buckets on a slow timer; unref'd so it never
    // keeps the process alive on its own.
    const pruneTimer = setInterval(() => rateLimiter.pruneIdle(), 60_000);
    pruneTimer.unref?.();
    let adminServer;
    if (cfg.admin.enabled && !opts.noAdmin) {
        const { startAdmin } = await import('./admin.js');
        adminServer = await startAdmin({
            auth: cfg.auth,
            audit,
            metrics,
            bind: { host: cfg.admin.host, allowedHosts: cfg.admin.allowedHosts },
            getServers: () => servers,
            getNamespace: () => state.namespace,
            pins: {
                violations: () => pins.violationKeys(),
                accept: (key) => {
                    const accepted = pins.accept(key);
                    if (accepted.length > 0)
                        rebuildNamespace('pin accepted');
                    return accepted;
                },
            },
            reloadCatalogs: async () => {
                await Promise.all(servers.map((s) => s.refresh()));
                rebuildNamespace('admin reload');
            },
        }, cfg.admin.host, cfg.admin.port);
        log(`[mcpgateway] admin API on http://${cfg.admin.host}:${cfg.admin.port}`);
    }
    let httpServer;
    if (cfg.upstream.http.enabled) {
        httpServer = await upstream.listenHttp(cfg.upstream.http.host, cfg.upstream.http.port);
        log(`[mcpgateway] MCP Streamable HTTP on http://${cfg.upstream.http.host}:${cfg.upstream.http.port}/mcp`);
    }
    let closed = false;
    const gateway = {
        config: cfg,
        servers,
        upstream,
        audit,
        metrics,
        getNamespace: () => state.namespace,
        pins,
        reloadCatalogs: async () => {
            await Promise.all(servers.map((s) => s.refresh()));
            rebuildNamespace('manual reload');
        },
        close: async () => {
            if (closed)
                return;
            closed = true;
            clearInterval(pruneTimer);
            if (httpServer)
                await new Promise((r) => httpServer?.close(() => r()));
            if (adminServer)
                await new Promise((r) => adminServer?.close(() => r()));
            await closeServers(servers);
            audit.close();
        },
    };
    if (httpServer)
        gateway.httpServer = httpServer;
    if (adminServer)
        gateway.adminServer = adminServer;
    return gateway;
}
/**
 * Between the raw catalogs and the routing table: pin check (rug-pull
 * defense) and neutralizing of terminal-control / bidi / zero-width characters
 * in anything the model or an operator's terminal will read.
 */
function hardenNamespace(ns, pins, metrics, audit, log) {
    const report = pins.evaluate(ns.tools.map((t) => ({ server: t.server, originalName: t.originalName, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations, outputSchema: t.outputSchema, title: t.title })));
    for (const k of report.changed) {
        metrics.pinViolations.inc({});
        const quarantined = pins.mode === 'block';
        log(`[mcpgateway] WARNING: tool "${k}" changed since it was pinned${quarantined ? ' — QUARANTINED until accepted (POST /v1/pins/accept)' : ''}`);
        audit.log({
            ts: new Date().toISOString(),
            reqId: 'pin',
            tool: k,
            server: k.split(':')[0] ?? '',
            originalTool: k,
            durationMs: 0,
            status: quarantined ? 'blocked' : 'ok',
            policyReason: 'pin_changed',
            errorMessage: 'tool description or schema changed since pinned',
        });
    }
    const warnings = [...ns.warnings];
    const tools = [];
    for (const t of ns.tools) {
        if (pins.quarantined(t.server, t.originalName))
            continue;
        const hits = suspiciousDescription(t.description);
        if (hits.length > 0)
            warnings.push(`tool "${t.publicName}" description looks instruction-like (${hits.join('; ')}) — review it`);
        const d = t.description === undefined ? undefined : stripHostile(t.description);
        if (d?.changed)
            warnings.push(`tool "${t.publicName}" description contained control/bidi/zero-width characters (replaced)`);
        const clean = { ...t, description: d?.text ?? t.description, inputSchema: sanitizeSchema(t.inputSchema) };
        if (t.annotations !== undefined)
            clean.annotations = sanitizeSchema(t.annotations);
        if (t.outputSchema !== undefined)
            clean.outputSchema = sanitizeSchema(t.outputSchema);
        if (t.title !== undefined)
            clean.title = stripHostile(t.title).text;
        tools.push(clean);
    }
    return { ...ns, tools, byPublicName: new Map(tools.map((t) => [t.publicName, t])), warnings };
}
function sanitizeSchema(v, depth = 0) {
    if (depth > 40)
        return v;
    if (typeof v === 'string')
        return stripHostile(v).text;
    if (Array.isArray(v))
        return v.map((x) => sanitizeSchema(x, depth + 1));
    if (v !== null && typeof v === 'object') {
        const out = {};
        for (const [k, val] of Object.entries(v))
            out[k] = sanitizeSchema(val, depth + 1);
        return out;
    }
    return v;
}
async function closeServers(servers) {
    await Promise.all(servers.map((s) => s.close().catch(() => undefined)));
}
function buildRoutingTable(servers, ns, cfg) {
    const byServer = new Map(servers.map((s) => [s.name, s]));
    const table = {
        tools: new Map(),
        toolMeta: new Map(),
        prompts: new Map(),
        promptMeta: new Map(),
        resources: new Map(),
        resourceMeta: new Map(),
    };
    for (const entry of ns.tools) {
        const server = byServer.get(entry.server);
        if (!server)
            continue;
        table.tools.set(entry.publicName, { server, original: entry.originalName });
        table.toolMeta.set(entry.publicName, entry);
    }
    // Prompts: same collision strategies, strategy-only (aliases are tool-scoped).
    const promptCatalogs = servers.map((s) => ({ server: s.name, names: s.getCatalogs().prompts.map((p) => p.name) }));
    const resolved = resolveNames(promptCatalogs, { ...cfg.namespace, aliases: {} });
    const promptLookup = new Map();
    for (const s of servers) {
        for (const p of s.getCatalogs().prompts) {
            promptLookup.set(`${s.name}\0${p.name}`, { description: p.description ?? undefined, args: p.arguments });
        }
    }
    for (const [key, publicName] of resolved.assigned) {
        const [srv, orig] = key.split('\0');
        const server = byServer.get(srv);
        const meta = promptLookup.get(key);
        if (!server || !meta)
            continue;
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
//# sourceMappingURL=gateway.js.map