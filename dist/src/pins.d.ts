import type { PinningConfig } from './config.js';
export interface PinInput {
    server: string;
    originalName: string;
    description?: string;
    inputSchema?: unknown;
    /** covered since 0.3.1: a flipped readOnlyHint is as dangerous as a changed description */
    annotations?: unknown;
    outputSchema?: unknown;
    title?: string;
}
export interface PinReport {
    /** keys pinned for the first time this evaluation */
    added: string[];
    /** keys whose definition changed since pinned */
    changed: string[];
    /** pinned keys no longer offered by the server (informational) */
    missing: string[];
}
export declare function pinKey(server: string, originalName: string): string;
/** Hash over description + inputSchema only (the 0.3.0 definition, kept for pin-file upgrades). */
export declare function legacyDefinitionHash(t: PinInput): string;
/**
 * Description + inputSchema + (when present) annotations, outputSchema, title.
 * A tool without extras hashes exactly as in 0.3.0, so existing pin files stay valid.
 */
export declare function definitionHash(t: PinInput): string;
export declare class PinRegistry {
    private cfg;
    private pins;
    /** keys currently in violation (hash differs from the pin) */
    private violations;
    private latest;
    /** pin file written by 0.3.0 (hashes cover description + schema only) */
    private legacyFile;
    constructor(cfg: PinningConfig);
    get mode(): PinningConfig['mode'];
    evaluate(tools: PinInput[]): PinReport;
    /** Should this tool be withheld right now? Only in block mode. */
    quarantined(server: string, originalName: string): boolean;
    violationKeys(): string[];
    /** Accept the current definition of one tool (or all violations). Returns accepted keys. */
    accept(key?: string): string[];
    private save;
}
export declare function suspiciousDescription(description: string | undefined): string[];
//# sourceMappingURL=pins.d.ts.map