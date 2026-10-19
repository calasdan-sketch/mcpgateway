/**
 * Minimal Prometheus metrics registry — hand-rolled exposition format, zero deps.
 *
 * Metric names are fixed by the gateway (no user input in names). Label VALUES
 * come from tool/server names; they are escaped per the Prometheus exposition
 * format (backslash, double-quote, newline). Cardinality is bounded by the
 * tool catalog, not by request content — args never become labels.
 */
export type LabelSet = Record<string, string>;

function escapeLabelValue(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function labelString(labels: LabelSet): string {
  const parts = Object.entries(labels).map(([k, v]) => `${k}="${escapeLabelValue(v)}"`);
  return parts.length > 0 ? `{${parts.join(',')}}` : '';
}

class Counter {
  private values = new Map<string, number>();
  private labelMap = new Map<string, LabelSet>();
  constructor(private name: string, private help: string) {}
  inc(labels: LabelSet = {}, by = 1): void {
    const k = JSON.stringify(labels);
    this.values.set(k, (this.values.get(k) ?? 0) + by);
    this.labelMap.set(k, labels);
  }
  render(): string {
    let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} counter\n`;
    for (const [k, v] of this.values) {
      out += `${this.name}${labelString(this.labelMap.get(k) ?? {})} ${v}\n`;
    }
    return out;
  }
}

class Gauge {
  private values = new Map<string, number>();
  private labelMap = new Map<string, LabelSet>();
  constructor(private name: string, private help: string) {}
  set(labels: LabelSet, v: number): void {
    const k = JSON.stringify(labels);
    this.values.set(k, v);
    this.labelMap.set(k, labels);
  }
  inc(labels: LabelSet = {}, by = 1): void {
    const k = JSON.stringify(labels);
    this.values.set(k, (this.values.get(k) ?? 0) + by);
    this.labelMap.set(k, labels);
  }
  dec(labels: LabelSet = {}, by = 1): void {
    this.inc(labels, -by);
  }
  render(): string {
    let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} gauge\n`;
    for (const [k, v] of this.values) {
      out += `${this.name}${labelString(this.labelMap.get(k) ?? {})} ${v}\n`;
    }
    return out;
  }
}

const DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

class Histogram {
  private buckets: number[];
  private counts = new Map<string, number[]>();
  private sums = new Map<string, number>();
  private labelMap = new Map<string, LabelSet>();
  constructor(private name: string, private help: string, buckets: number[] = DEFAULT_BUCKETS) {
    this.buckets = [...buckets].sort((a, b) => a - b);
  }
  observe(labels: LabelSet, v: number): void {
    const k = JSON.stringify(labels);
    let arr = this.counts.get(k);
    if (arr === undefined) {
      arr = new Array(this.buckets.length + 1).fill(0);
      this.counts.set(k, arr);
      this.labelMap.set(k, labels);
      this.sums.set(k, 0);
    }
    for (let i = 0; i < this.buckets.length; i++) {
      if (v <= (this.buckets[i] as number)) (arr[i] as number) += 1;
    }
    (arr[this.buckets.length] as number) += 1; // +Inf
    this.sums.set(k, (this.sums.get(k) ?? 0) + v);
  }
  render(): string {
    let out = `# HELP ${this.name} ${this.help}\n# TYPE ${this.name} histogram\n`;
    for (const [k, arr] of this.counts) {
      const labels = this.labelMap.get(k) ?? {};
      const base = labelString(labels);
      const inner = base === '' ? '' : base.slice(1, -1);
      const withLe = (le: string) => (inner === '' ? `{le="${le}"}` : `{${inner},le="${le}"}`);
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
  readonly toolCalls = new Counter('mcpgateway_tool_calls_total', 'Tool calls routed by the gateway, by outcome.');
  readonly policyDenials = new Counter('mcpgateway_policy_denials_total', 'Tool calls denied by fleet policy.');
  readonly rateLimitHits = new Counter('mcpgateway_rate_limit_hits_total', 'Tool calls rejected by rate limiting.');
  readonly auditErrors = new Counter('mcpgateway_audit_errors_total', 'Audit log write failures (never fatal to requests).');
  readonly upstreamErrors = new Counter('mcpgateway_upstream_errors_total', 'Upstream transport errors.');
  readonly serverUp = new Gauge('mcpgateway_server_up', '1 when the downstream server is connected and healthy.');
  readonly serverInflight = new Gauge('mcpgateway_server_inflight', 'Tool calls currently executing per downstream server.');
  readonly gatewayInflight = new Gauge('mcpgateway_gateway_inflight', 'Tool calls currently executing across the gateway.');
  readonly buildInfo = new Gauge('mcpgateway_build_info', 'Gateway build info.');
  readonly toolDuration = new Histogram('mcpgateway_tool_call_duration_seconds', 'Tool call duration in seconds.');

  render(): string {
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
