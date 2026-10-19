function escapeLabelValue(v) {
    return v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}
function labelString(labels) {
    const parts = Object.entries(labels).map(([k, v]) => `${k}="${escapeLabelValue(v)}"`);
    return parts.length > 0 ? `{${parts.join(',')}}` : '';
}
class Counter {
    name;
    help;
    values = new Map();
    labelMap = new Map();
    constructor(name, help) {
        this.name = name;
        this.help = help;
    }
    inc(labels = {}, by = 1) {
        const k = JSON.stringify(labels);
        this.values.set(k, (this.values.get(k) ?? 0) + by);
        this.labelMap.set(k, labels);
    }
    render() {
        let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} counter\n`;
        for (const [k, v] of this.values) {
            out += `${this.name}${labelString(this.labelMap.get(k) ?? {})} ${v}\n`;
        }
        return out;
    }
}
class Gauge {
    name;
    help;
    values = new Map();
    labelMap = new Map();
    constructor(name, help) {
        this.name = name;
        this.help = help;
    }
    set(labels, v) {
        const k = JSON.stringify(labels);
        this.values.set(k, v);
        this.labelMap.set(k, labels);
    }
    inc(labels = {}, by = 1) {
        const k = JSON.stringify(labels);
        this.values.set(k, (this.values.get(k) ?? 0) + by);
        this.labelMap.set(k, labels);
    }
    dec(labels = {}, by = 1) {
        this.inc(labels, -by);
    }
    render() {
        let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} gauge\n`;
        for (const [k, v] of this.values) {
            out += `${this.name}${labelString(this.labelMap.get(k) ?? {})} ${v}\n`;
        }
        return out;
    }
}
const DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
class Histogram {
    name;
    help;
    buckets;
    counts = new Map();
    sums = new Map();
    labelMap = new Map();
    constructor(name, help, buckets = DEFAULT_BUCKETS) {
        this.name = name;
        this.help = help;
        this.buckets = [...buckets].sort((a, b) => a - b);
    }
    observe(labels, v) {
        const k = JSON.stringify(labels);
        let arr = this.counts.get(k);
        if (arr === undefined) {
            arr = new Array(this.buckets.length + 1).fill(0);
            this.counts.set(k, arr);
            this.labelMap.set(k, labels);
            this.sums.set(k, 0);
        }
        for (let i = 0; i < this.buckets.length; i++) {
            if (v <= this.buckets[i])
                arr[i] += 1;
        }
        arr[this.buckets.length] += 1; // +Inf
        this.sums.set(k, (this.sums.get(k) ?? 0) + v);
    }
    render() {
        let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} histogram\n`;
        for (const [k, arr] of this.counts) {
            const labels = this.labelMap.get(k) ?? {};
            const base = labelString(labels);
            const inner = base === '' ? '' : base.slice(1, -1);
            const withLe = (le) => (inner === '' ? `{le="${le}"}` : `{${inner},le="${le}"}`);
            for (let i = 0; i < this.buckets.length; i++) {
                out += `${this.name}_bucket${withLe(String(this.buckets[i]))} ${arr[i]}\n`;
            }
            out += `${this.name}_bucket${withLe('+Inf')} ${arr[this.buckets.length]}\n`;
            out += `${this.name}_sum${base} ${this.sums.get(k) ?? 0}\n`;
            out += `${this.name}_count${base} ${arr[this.buckets.length]}\n`;
        }
        return out;
    }
}
export class Metrics {
    toolCalls = new Counter('mcpgateway_tool_calls_total', 'Tool calls routed by the gateway, by outcome.');
    policyDenials = new Counter('mcpgateway_policy_denials_total', 'Tool calls denied by fleet policy.');
    rateLimitHits = new Counter('mcpgateway_rate_limit_hits_total', 'Tool calls rejected by rate limiting.');
    auditErrors = new Counter('mcpgateway_audit_errors_total', 'Audit log write failures (never fatal to requests).');
    upstreamErrors = new Counter('mcpgateway_upstream_errors_total', 'Upstream transport errors.');
    serverUp = new Gauge('mcpgateway_server_up', '1 when the downstream server is connected and healthy.');
    serverInflight = new Gauge('mcpgateway_server_inflight', 'Tool calls currently executing per downstream server.');
    gatewayInflight = new Gauge('mcpgateway_gateway_inflight', 'Tool calls currently executing across the gateway.');
    buildInfo = new Gauge('mcpgateway_build_info', 'Gateway build info.');
    toolDuration = new Histogram('mcpgateway_tool_call_duration_seconds', 'Tool call duration in seconds.');
    render() {
        return [
            this.buildInfo.render(),
            this.toolCalls.render(),
            this.policyDenials.render(),
            this.rateLimitHits.render(),
            this.auditErrors.render(),
            this.upstreamErrors.render(),
            this.serverUp.render(),
            this.serverInflight.render(),
            this.gatewayInflight.render(),
            this.toolDuration.render(),
        ].join('');
    }
}
//# sourceMappingURL=metrics.js.map