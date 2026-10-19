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
import { DownstreamServer } from './downstream.js';
import { GatewayUpstream } from './upstream.js';
import { type NamespaceResult } from './namespace.js';
import { type GatewayConfig } from './config.js';
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
export declare function startGateway(cfg: GatewayConfig, opts?: StartOptions): Promise<Gateway>;
//# sourceMappingURL=gateway.d.ts.map