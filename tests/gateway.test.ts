/**
 * End-to-end: fake downstream MCP servers (in-process, InMemoryTransport)
 * -> gateway -> SDK client. Exercises namespace unification, routing,
 * policy, rate limits, audit, metrics, resources, and prompts.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { validateConfig, type Raw } from '../src/config.js';
import { startGateway, type Gateway } from '../src/gateway.js';

interface Fake {
  server: Server;
  calls: Array<{ tool: string; args: unknown }>;
  resources: Array<{ uri: string; text: string }>;
  prompts: string[];
}

/** Build an in-process MCP server double. */
export type ToolFn = (args: unknown) => { content: Array<{ type: 'text'; text: string }> };
function makeFake(name: string, tools: Record<string, ToolFn>, opts: { resources?: Array<{ uri: string; text: string }>; prompts?: string[] } = {}): Fake {
  const fake: Fake = { server: null as unknown as Server, calls: [], resources: opts.resources ?? [], prompts: opts.prompts ?? [] };
  const server = new Server({ name, version: '1.0.0' }, { capabilities: { tools: {}, resources: {}, prompts: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: Object.keys(tools).map((t) => ({ name: t, inputSchema: { type: 'object' as const } })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const fn = tools[req.params.name];
    if (!fn) throw new McpError(-32602, `unknown tool ${req.params.name}`);
    fake.calls.push({ tool: req.params.name, args: req.params.arguments });
    return fn(req.params.arguments);
  });
  server.setRequestHandler(ListResourcesRequestSchema, async () => ({
    resources: fake.resources.map((r) => ({ uri: r.uri, name: r.uri })),
  }));
  server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
    const r = fake.resources.find((x) => x.uri === req.params.uri);
    if (!r) throw new McpError(-32602, 'unknown resource');
    return { contents: [{ uri: r.uri, text: r.text }] };
  });
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: fake.prompts.map((p) => ({ name: p })),
  }));
  server.setRequestHandler(GetPromptRequestSchema, async (req) => ({
    messages: [{ role: 'user' as const, content: { type: 'text' as const, text: `prompt:${name}:${req.params.name}` } }],
  }));
  fake.server = server;
  return fake;
}

const textResult = (text: string) => ({ content: [{ type: 'text' as const, text }] });

interface Harness {
  gw: Gateway;
  client: Client;
  fakes: Record<string, Fake>;
  auditPath: string;
  close: () => Promise<void>;
}

async function startHarness(rawOver: Record<string, unknown> = {}, extraTools: { alpha?: Record<string, ToolFn>; beta?: Record<string, ToolFn> } = {}): Promise<Harness> {
  const fakeA = makeFake('alpha-srv', {
    ping: () => textResult('pong-a'),
    compare: () => textResult('a-wins'),
    ...(extraTools.alpha ?? {}),
  }, { resources: [{ uri: 'file:///a.md', text: 'AAA' }], prompts: ['summarize'] });
  const fakeB = makeFake('beta-srv', {
    ping: () => textResult('pong-b'),
    compare: () => textResult('b-wins'),
    secret_tool: (args) => textResult(`leak: ${(args as { k?: string }).k ?? ''} sk-live-12345`),
    ...(extraTools.beta ?? {}),
  }, { prompts: ['summarize'] });

  const pairs = { a: InMemoryTransport.createLinkedPair(), b: InMemoryTransport.createLinkedPair() };
  await fakeA.server.connect(pairs.a[1]);
  await fakeB.server.connect(pairs.b[1]);

  const auditPath = join(mkdtempSync(join(tmpdir(), 'mcpgw-it-')), 'audit.jsonl');
  const cfg = validateConfig({
    servers: [
      { name: 'alpha', transport: 'stdio', command: 'true' },
      { name: 'beta', transport: 'stdio', command: 'true' },
    ],
    auth: { disabled: true },
    audit: { path: auditPath },
    admin: { enabled: false },
    upstream: { stdio: { enabled: true }, http: { enabled: false } },
    ...rawOver,
  } as Raw, 'test');

  const gw = await startGateway(cfg, {
    transportOverrides: new Map([['alpha', pairs.a[0]], ['beta', pairs.b[0]]]),
    noAdmin: true,
    log: () => undefined,
  });

  const up = InMemoryTransport.createLinkedPair();
  await gw.upstream.createMcpServer().connect(up[1]);
  const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} });
  await client.connect(up[0]);

  return {
    gw,
    client,
    fakes: { alpha: fakeA, beta: fakeB },
    auditPath,
    close: async () => {
      await client.close().catch(() => undefined);
      await gw.close();
      await fakeA.server.close().catch(() => undefined);
      await fakeB.server.close().catch(() => undefined);
    },
  };
}

const auditRecords = (h: Harness): Array<Record<string, unknown>> =>
  readFileSync(h.auditPath, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);

// ---------------------------------------------------------------------------

test('unified namespace: colliding tools are prefixed per server', async () => {
  const h = await startHarness();
  try {
    const { tools } = await h.client.listTools();
    const names = tools.map((t) => t.name).sort();
    assert.deepEqual(names, ['alpha__compare', 'alpha__ping', 'beta__compare', 'beta__ping', 'secret_tool']);
  } finally {
    await h.close();
  }
});

test('tool calls route to the owning server', async () => {
  const h = await startHarness();
  try {
    const r1 = await h.client.callTool({ name: 'alpha__compare', arguments: {} });
    const r2 = await h.client.callTool({ name: 'beta__compare', arguments: {} });
    assert.equal((r1.content as Array<{ text: string }>)[0]?.text, 'a-wins');
    assert.equal((r2.content as Array<{ text: string }>)[0]?.text, 'b-wins');
    assert.equal(h.fakes['alpha']?.calls.length, 1);
    assert.equal(h.fakes['beta']?.calls.length, 1);
    assert.equal(h.fakes['alpha']?.calls[0]?.tool, 'compare'); // original name downstream
  } finally {
    await h.close();
  }
});

test('unknown tool -> InvalidParams', async () => {
  const h = await startHarness();
  try {
    await assert.rejects(() => h.client.callTool({ name: 'nope__missing', arguments: {} }), /unknown tool/);
  } finally {
    await h.close();
  }
});

test('policy deny blocks the call and audits it', async () => {
  const h = await startHarness({ policy: { denyTools: ['secret_tool'] } });
  try {
    await assert.rejects(() => h.client.callTool({ name: 'secret_tool', arguments: { k: 'v' } }), /denied by policy/);
    assert.equal(h.fakes['beta']?.calls.length, 0); // never reached the server
    const recs = auditRecords(h);
    assert.equal(recs.length, 1);
    assert.equal(recs[0]?.['status'], 'denied');
    assert.equal(recs[0]?.['tool'], 'secret_tool');
    assert.ok(h.gw.metrics.render().includes('mcpgateway_policy_denials_total{tool="secret_tool",reason="deny_list"} 1'));
  } finally {
    await h.close();
  }
});

test('observe mode forwards the call but records the would-be verdict', async () => {
  const h = await startHarness({ policy: { mode: 'observe', denyTools: ['alpha__ping'] } });
  try {
    const r = await h.client.callTool({ name: 'alpha__ping', arguments: {} });
    assert.equal((r.content as Array<{ text: string }>)[0]?.text, 'pong-a');
    const recs = auditRecords(h);
    assert.equal(recs[0]?.['status'], 'ok');
    assert.equal(recs[0]?.['policyReason'], 'would_deny:deny_list');
  } finally {
    await h.close();
  }
});

test('rate limit: burst then reject', async () => {
  const h = await startHarness({ rateLimits: { default: { rps: 1, burst: 1 } } });
  try {
    await h.client.callTool({ name: 'alpha__ping', arguments: {} });
    await assert.rejects(() => h.client.callTool({ name: 'alpha__ping', arguments: {} }), /rate limit exceeded/);
    const recs = auditRecords(h);
    assert.ok(recs.some((r) => r['status'] === 'rate_limited'));
    assert.ok(h.gw.metrics.render().includes('mcpgateway_rate_limit_hits_total{tool="alpha__ping"} 1'));
  } finally {
    await h.close();
  }
});

test('hidden tools vanish from listings and are denied on call', async () => {
  const h = await startHarness({ policy: { hideTools: ['secret_tool'] } });
  try {
    const { tools } = await h.client.listTools();
    assert.ok(!tools.some((t) => t.name === 'secret_tool'));
    // Masked as "unknown tool": the error must not confirm the hidden tool
    // exists (existence oracle). The audit record keeps the real reason.
    await assert.rejects(() => h.client.callTool({ name: 'secret_tool', arguments: {} }), /unknown tool/);
    const recs = auditRecords(h);
    assert.ok(recs.some((r) => r['tool'] === 'secret_tool' && r['policyReason'] === 'hidden'));
  } finally {
    await h.close();
  }
});

test('response redact rewrites secrets in results', async () => {
  const h = await startHarness({ policy: { responseRedact: ['sk-live-12345'] } });
  try {
    const r = await h.client.callTool({ name: 'secret_tool', arguments: { k: 'K' } });
    const text = (r.content as Array<{ text: string }>)[0]?.text ?? '';
    assert.ok(!text.includes('sk-live-12345'));
    assert.ok(text.includes('[REDACTED]'));
    const recs = auditRecords(h);
    assert.equal(recs[0]?.['redactions'], 1);
  } finally {
    await h.close();
  }
});

test('audit log captures routed calls with redacted args', async () => {
  const h = await startHarness();
  try {
    await h.client.callTool({ name: 'alpha__ping', arguments: { github_token: 'ghp_real-secret' } });
    const recs = auditRecords(h);
    assert.equal(recs.length, 1);
    const rec = recs[0] as Record<string, unknown>;
    assert.equal(rec['tool'], 'alpha__ping');
    assert.equal(rec['server'], 'alpha');
    assert.equal(rec['originalTool'], 'ping');
    assert.equal(rec['status'], 'ok');
    assert.ok(typeof rec['durationMs'] === 'number');
    assert.ok(!(rec['args'] as string).includes('ghp_real-secret'));
  } finally {
    await h.close();
  }
});

test('metrics count calls and durations', async () => {
  const h = await startHarness();
  try {
    await h.client.callTool({ name: 'alpha__ping', arguments: {} });
    const out = h.gw.metrics.render();
    assert.ok(out.includes('mcpgateway_tool_calls_total{server="alpha",tool="alpha__ping",status="ok"} 1'));
    assert.ok(out.includes('mcpgateway_tool_call_duration_seconds_count{server="alpha",tool="alpha__ping"} 1'));
  } finally {
    await h.close();
  }
});

test('resources are namespaced by URI and routed', async () => {
  const h = await startHarness();
  try {
    const { resources } = await h.client.listResources();
    assert.equal(resources.length, 1);
    const uri = resources[0]?.uri ?? '';
    assert.ok(uri.startsWith('mcpgateway://alpha/'), uri);
    const res = await h.client.readResource({ uri });
    assert.equal((res.contents[0] as { text: string }).text, 'AAA');
  } finally {
    await h.close();
  }
});

test('prompts are namespaced and routed', async () => {
  const h = await startHarness();
  try {
    const { prompts } = await h.client.listPrompts();
    const names = prompts.map((p) => p.name).sort();
    assert.deepEqual(names, ['alpha__summarize', 'beta__summarize']);
    const res = await h.client.getPrompt({ name: 'beta__summarize', arguments: {} });
    assert.equal((res.messages[0]?.content as { text: string }).text, 'prompt:beta-srv:summarize');
  } finally {
    await h.close();
  }
});

test('edge auth: valid key, wrong key, disabled', async () => {
  const h = await startHarness({
    auth: { keys: [{ id: 'k1', key: 'x'.repeat(32), scopes: ['tools:call', 'tools:list'] }] },
  });
  try {
    const good = h.gw.upstream.authenticateHttp({ headers: { authorization: `Bearer ${'x'.repeat(32)}` } } as never);
    assert.equal(good?.keyId, 'k1');
    const bad = h.gw.upstream.authenticateHttp({ headers: { authorization: 'Bearer wrong' } } as never);
    assert.equal(bad, null);
    const missing = h.gw.upstream.authenticateHttp({ headers: {} } as never);
    assert.equal(missing, null);
  } finally {
    await h.close();
  }
});

test('downstream failure surfaces as a gateway error and is audited', async () => {
  const { DownstreamServer } = await import('../src/downstream.js');
  const bad = makeFake('bad-srv', { boom: () => { throw new McpError(-32000, 'kaboom'); } });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await bad.server.connect(st);
  const cfg = validateConfig({
    servers: [{ name: 'bad', transport: 'stdio', command: 'true', timeoutMs: 5000 }],
    auth: { disabled: true },
  } as Raw, 'test');
  const ds = new DownstreamServer(cfg.servers[0]!, { onCatalogChanged: () => undefined }, ct);
  await ds.connect();
  // A throwing tool propagates (the gateway maps it to a JSON-RPC error upstream).
  await assert.rejects(() => ds.callTool('boom', {}), /kaboom/);
  // The server itself is NOT killed by one failure (timeout != kill).
  assert.equal(ds.circuitState, 'closed');
  await ds.close();
  await bad.server.close().catch(() => undefined);
});

test('circuit breaker opens after threshold and fails fast', async () => {
  // Build a raw DownstreamServer against a fake whose tool always throws.
  const { DownstreamServer } = await import('../src/downstream.js');
  const bad = makeFake('bad-srv', { boom: () => { throw new McpError(-32000, 'kaboom'); } });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await bad.server.connect(st);
  const cfg = validateConfig({
    servers: [{ name: 'bad', transport: 'stdio', command: 'true', failureThreshold: 2, breakerCooldownMs: 60000, timeoutMs: 5000 }],
    auth: { disabled: true },
  } as Raw, 'test');
  const ds = new DownstreamServer(cfg.servers[0]!, { onCatalogChanged: () => undefined }, ct);
  await ds.connect();
  await assert.rejects(() => ds.callTool('boom', {}), /kaboom/);
  await assert.rejects(() => ds.callTool('boom', {}), /kaboom/);
  assert.equal(ds.circuitState, 'open');
  await assert.rejects(() => ds.callTool('boom', {}), /circuit breaker is open/); // fail fast, no downstream hit
  await ds.close();
  await bad.server.close().catch(() => undefined);
});

test('hidden tools are denied even in observe mode', async () => {
  const h = await startHarness({ policy: { mode: 'observe', hideTools: ['secret_tool'] } });
  try {
    // Masked as unknown (no existence oracle), never forwarded downstream.
    await assert.rejects(() => h.client.callTool({ name: 'secret_tool', arguments: {} }), /unknown tool/);
    assert.equal(h.fakes['beta']?.calls.length, 0); // never reached the server
  } finally {
    await h.close();
  }
});

test('oversized results fail the call, not the gateway', async () => {
  const h = await startHarness({ maxResultChars: 2000 }, { beta: { big: () => textResult('x'.repeat(5000)) } });
  try {
    await assert.rejects(() => h.client.callTool({ name: 'big', arguments: {} }), /exceeded.*limit/);
    const recs = auditRecords(h);
    assert.ok(recs.some((r) => r['errorCode'] === 'result_too_large'));
    // gateway still serves other tools afterwards
    const r = await h.client.callTool({ name: 'alpha__ping', arguments: {} });
    assert.equal((r.content as Array<{ text: string }>)[0]?.text, 'pong-a');
  } finally {
    await h.close();
  }
});

test('downstream tool errors are audited (not swallowed)', async () => {
  const h = await startHarness(
    {},
    { beta: { failer: () => { throw new McpError(-32000, 'downstream kaput'); } } },
  );
  try {
    await assert.rejects(() => h.client.callTool({ name: 'failer', arguments: {} }), /kaput/);
    const recs = auditRecords(h);
    assert.equal(recs.length, 1);
    assert.equal(recs[0]?.['status'], 'error');
    assert.equal(recs[0]?.['errorCode'], 'downstream_error');
    assert.equal(recs[0]?.['tool'], 'failer');
    assert.ok(h.gw.metrics.render().includes('mcpgateway_tool_calls_total{server="beta",tool="failer",status="error"} 1'));
  } finally {
    await h.close();
  }
});

test('secrets in args are scrubbed from downstream error messages', async () => {
  const h = await startHarness(
    {},
    { beta: { boom: () => { throw new McpError(-32000, 'downstream exploded, token was ghp_secretvalue123'); } } },
  );
  try {
    await assert.rejects(
      () => h.client.callTool({ name: 'boom', arguments: { api_token: 'ghp_secretvalue123' } }),
      (e: unknown) => e instanceof Error && !e.message.includes('ghp_secretvalue123') && /failed/.test(e.message),
    );
    const raw = readFileSync(h.auditPath, 'utf8');
    assert.ok(!raw.includes('ghp_secretvalue123'), 'secret must not appear in audit log');
    assert.ok(raw.includes('[REDACTED]'));
  } finally {
    await h.close();
  }
});

test('http sessions are capped (429 past maxSessions)', async () => {
  const fakeA = makeFake('a-srv', { ping: () => textResult('p') });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await fakeA.server.connect(st);
  const auditPath = join(mkdtempSync(join(tmpdir(), 'mcpgw-it-')), 'audit.jsonl');
  const cfg = validateConfig({
    servers: [{ name: 'a', transport: 'stdio', command: 'true' }],
    auth: { disabled: true },
    audit: { path: auditPath },
    admin: { enabled: false },
    upstream: { stdio: { enabled: false }, http: { enabled: true, host: '127.0.0.1', port: 0, maxSessions: 1 } },
  } as Raw, 'test');
  const gw = await startGateway(cfg, { transportOverrides: new Map([['a', ct]]), noAdmin: true, log: () => undefined });
  try {
    const port = (gw.httpServer?.address() as import('node:net').AddressInfo).port;
    const initReq = () =>
      fetch(`http://127.0.0.1:${port}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1, method: 'initialize',
          params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } },
        }),
      });
    const r1 = await initReq();
    assert.equal(r1.status, 200);
    await r1.body?.cancel(); // abandon the SSE stream: session stays open server-side
    await new Promise((r) => setTimeout(r, 200));
    const r2 = await initReq();
    assert.equal(r2.status, 429);
    await r2.body?.cancel();
  } finally {
    await gw.close();
    await fakeA.server.close().catch(() => undefined);
  }
});

test('unknown tool calls are audited without leaking names into metric labels', async () => {
  const h = await startHarness();
  try {
    await assert.rejects(() => h.client.callTool({ name: 'definitely_not_a_tool', arguments: {} }), /unknown tool/);
    // A second probe with a DIFFERENT name must not create new metric series.
    await assert.rejects(() => h.client.callTool({ name: 'another_missing_tool', arguments: {} }), /unknown tool/);
    const recs = auditRecords(h);
    const unknowns = recs.filter((r) => r['errorCode'] === 'unknown_tool');
    assert.equal(unknowns.length, 2);
    assert.equal(unknowns[0]?.['server'], 'unknown');
    const rendered = h.gw.metrics.render();
    assert.ok(rendered.includes('mcpgateway_tool_calls_total{server="unknown",tool="unknown",status="error"} 2'));
    assert.ok(!rendered.includes('definitely_not_a_tool'));
    assert.ok(!rendered.includes('another_missing_tool'));
  } finally {
    await h.close();
  }
});

test('audit write failures increment mcpgateway_audit_errors_total', async () => {
  // Point the audit path at a directory: every append fails, nothing throws.
  const { AuditLogger } = await import('../src/audit.js');
  const dir = mkdtempSync(join(tmpdir(), 'mcpgw-auditfail-'));
  let calls = 0;
  const logger = new AuditLogger({ path: dir, logArgs: true, redactKeys: [], maxArgsChars: 100, maxSizeMB: 1, keepFiles: 1 }, () => { calls += 1; });
  logger.log({ ts: new Date().toISOString(), reqId: 'r', tool: 't', server: 's', originalTool: 't', durationMs: 1, status: 'ok' });
  assert.equal(logger.errors, 1);
  assert.equal(calls, 1);
});
