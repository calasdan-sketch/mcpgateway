import type { PinningConfig } from './config.js';
export interface PinInput {
    server: string;
    originalName: string;
    description?: string;
    inputSchema?: unknown;
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
export declare function definitionHash(t: PinInput): string;
export declare class PinRegistry {
    private cfg;
    private pins;
    /** keys currently in violation (hash differs from the pin) */
    private violations;
    private latest;
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