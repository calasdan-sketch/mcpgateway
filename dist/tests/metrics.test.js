import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Metrics } from '../src/metrics.js';
test('counter renders Prometheus exposition format', () => {
    const m = new Metrics();
    m.toolCalls.inc({ server: 'a', tool: 'a__ping', status: 'ok' });
    m.toolCalls.inc({ server: 'a', tool: 'a__ping', status: 'ok' });
    const out = m.render();
    assert.ok(out.includes('# HELP mcpgateway_tool_calls_total'));
    assert.ok(out.includes('# TYPE mcpgateway_tool_calls_total counter'));
    assert.ok(out.includes('mcpgateway_tool_calls_total{server="a",tool="a__ping",status="ok"} 2'));
});
test('label values are escaped (quote, backslash, newline)', () => {
    const m = new Metrics();
    m.toolCalls.inc({ server: 'a"b\\c\nd', tool: 't', status: 'ok' });
    const out = m.render();
    assert.ok(out.includes('server="a\\"b\\\\c\\nd"'));
});
test('histogram buckets are cumulative with +Inf, sum, count', () => {
    const m = new Metrics();
    m.toolDuration.observe({ server: 'a', tool: 't' }, 0.05);
    m.toolDuration.observe({ server: 'a', tool: 't' }, 5);
    const out = m.render();
    assert.ok(out.includes('mcpgateway_tool_call_duration_seconds_bucket{server="a",tool="t",le="0.05"} 1'));
    assert.ok(out.includes('mcpgateway_tool_call_duration_seconds_bucket{server="a",tool="t",le="1"} 1'));
    assert.ok(out.includes('mcpgateway_tool_call_duration_seconds_bucket{server="a",tool="t",le="+Inf"} 2'));
    assert.ok(out.includes('mcpgateway_tool_call_duration_seconds_count{server="a",tool="t"} 2'));
    assert.ok(out.includes('mcpgateway_tool_call_duration_seconds_sum{server="a",tool="t"} 5.05'));
});
test('gauge set/inc/dec', () => {
    const m = new Metrics();
    m.serverUp.set({ server: 'a' }, 1);
    m.gatewayInflight.inc({});
    m.gatewayInflight.inc({});
    m.gatewayInflight.dec({});
    const out = m.render();
    assert.ok(out.includes('mcpgateway_server_up{server="a"} 1'));
    assert.ok(out.includes('mcpgateway_gateway_inflight 1'));
});
//# sourceMappingURL=metrics.test.js.map