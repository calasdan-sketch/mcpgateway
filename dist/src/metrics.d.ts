/**
 * Minimal Prometheus metrics registry — hand-rolled exposition format, zero deps.
 *
 * Metric names are fixed by the gateway (no user input in names). Label VALUES
 * come from tool/server names; they are escaped per the Prometheus exposition
 * format (backslash, double-quote, newline). Cardinality is bounded by the
 * tool catalog, not by request content — args never become labels.
 */
export type LabelSet = Record<string, string>;
declare class Counter {
    private name;
    private help;
    private values;
    private labelMap;
    constructor(name: string, help: string);
    inc(labels?: LabelSet, by?: number): void;
    render(): string;
}
declare class Gauge {
    private name;
    private help;
    private values;
    private labelMap;
    constructor(name: string, help: string);
    set(labels: LabelSet, v: number): void;
    inc(labels?: LabelSet, by?: number): void;
    dec(labels?: LabelSet, by?: number): void;
    render(): string;
}
declare class Histogram {
    private name;
    private help;
    private buckets;
    private counts;
    private sums;
    private labelMap;
    constructor(name: string, help: string, buckets?: number[]);
    observe(labels: LabelSet, v: number): void;
    render(): string;
}
export declare class Metrics {
    readonly toolCalls: Counter;
    readonly policyDenials: Counter;
    readonly rateLimitHits: Counter;
    readonly auditErrors: Counter;
    readonly upstreamErrors: Counter;
    readonly serverUp: Gauge;
    readonly serverInflight: Gauge;
    readonly gatewayInflight: Gauge;
    readonly buildInfo: Gauge;
    readonly toolDuration: Histogram;
    render(): string;
}
export {};
//# sourceMappingURL=metrics.d.ts.map