/**
 * Unified namespace construction with collision resolution.
 *
 * Strategies (per blueprint D1):
 *  - prefix   (default): every tool on a colliding name becomes
 *             `<server><sep><tool>` — deterministic, no silent shadowing.
 *  - priority: the highest-priority server keeps the bare name; losers are
 *             prefixed (still reachable). Every shadowing is reported.
 *  - explicit: namespace.mappings[toolName] names the winning server for each
 *             collision; unmapped collisions are a hard error (fail-closed).
 *
 * Aliases (`aliases: {"<server>:<tool>": "<publicName>"}`) apply after the
 * strategy and let operators pick friendly names.
 *
 * The generic core (resolveNames) works for any named catalog entries
 * (tools, prompts). Resource URIs are namespaced separately (see upstream).
 */
import type { NamespaceConfig } from './config.js';
export interface CatalogTool {
    name: string;
    description?: string;
    inputSchema?: unknown;
}
export interface ServerCatalog {
    server: string;
    tools: CatalogTool[];
}
export interface ToolEntry extends CatalogTool {
    publicName: string;
    server: string;
    originalName: string;
}
export interface CollisionReport {
    originalName: string;
    servers: string[];
    strategy: string;
    /** public names the colliding tools resolved to, in server order */
    resolvedAs: string[];
    /** servers whose tools lost the bare name (priority/explicit) */
    shadowed: string[];
    /** winner server for priority/explicit */
    winner?: string;
}
export interface NamespaceResult {
    tools: ToolEntry[];
    byPublicName: Map<string, ToolEntry>;
    collisions: CollisionReport[];
    warnings: string[];
}
export declare class NamespaceError extends Error {
    constructor(message: string);
}
export interface NameCatalog {
    server: string;
    names: string[];
}
export interface ResolvedNames {
    /** "server\0originalName" -> publicName */
    assigned: Map<string, string>;
    collisions: CollisionReport[];
    warnings: string[];
}
export declare function resolveNames(catalogs: NameCatalog[], cfg: NamespaceConfig): ResolvedNames;
export declare function buildNamespace(catalogs: ServerCatalog[], cfg: NamespaceConfig): NamespaceResult;
//# sourceMappingURL=namespace.d.ts.map