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
import { type Server as HttpServer } from 'node:http';
import type { AuditLogger } from './audit.js';
import type { Metrics } from './metrics.js';
import type { DownstreamServer } from './downstream.js';
import type { NamespaceResult } from './namespace.js';
import type { AuthKey } from './config.js';
export interface AdminDeps {
    auth: {
        disabled: boolean;
        keys: AuthKey[];
    };
    audit: AuditLogger;
    metrics: Metrics;
    getServers: () => DownstreamServer[];
    getNamespace: () => NamespaceResult | null;
    reloadCatalogs: () => Promise<void>;
}
export declare function startAdmin(deps: AdminDeps, host: string, port: number): Promise<HttpServer>;
//# sourceMappingURL=admin.d.ts.map