interface Args {
    command: string;
    config: string;
    network: boolean;
    http: boolean;
    output: string;
    force: boolean;
    rest: string[];
    keyEnv?: string;
    tool?: string;
    toolArgs?: string;
    keyId?: string;
    generate: boolean;
}
declare function parseArgs(argv: string[]): Args;
export { parseArgs };
export type { Args };
/** Apply serve-time CLI overrides to a loaded config. */
export declare function applyServeFlags(cfg: {
    upstream: {
        http: {
            enabled: boolean;
        };
    };
}, args: Args): void;
export declare function main(argv: string[]): Promise<void>;
//# sourceMappingURL=cli.d.ts.map