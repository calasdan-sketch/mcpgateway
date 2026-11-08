/**
 * Round-5 tests: author line, version consistency, argument-depth guard (breaker
 * cannot be opened by one key), case-insensitive Bearer, 404 for unknown sessions,
 * CLI usage errors, slow-client timeouts. Includes a differential/property test
 * for the depth checker against a plain recursive reference.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { validateConfig, type Raw } from '../src/config.js';
import { startGateway } from '../src/gateway.js';
import { MAX_ARG_DEPTH, bearerToken, exceedsDepth } from '../src/util.js';
import { VERSION } from '../src/version.js';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = join(here, '..', '..');
const CLI = join(here, '..', 'src', 'index.js');
const tmp = () => mkdtempSync(join(tmpdir(), 'mcpgw-r5-'));
const KEY = ['round5', 'key', 'z'.repeat(20)].join('-');
const AUTHOR = 'Calas Automations Inc.';

// ---- author line + version ---------------------------------------------------------

test('author is exactly "Calas Automations Inc." in package.json, LICENSE and the CLI text', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as Record<string, unknown>;
  assert.equal(pkg['author'], AUTHOR);
  assert.match(readFileSync(join(ROOT, 'LICENSE'), 'utf8'), /^MIT License\s+Copyright \(c\) 2026 Calas Automations Inc\.$/m);
  const r = spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf8' });
  assert.match(r.stdout, /Maintained by Calas Automations Inc\./);
  for (const old of ['DC Enterprises', 'Dan Calas']) {
    assert.ok(!readFileSync(join(ROOT, 'README.md'), 'utf8').includes(old), `README mentions ${old}`);
    assert.ok(!r.stdout.includes(old));
  }
});

test('package.json is publish-shaped: no tests or maps in the file list, no repository claim', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { files?: string[]; repository?: unknown; homepage?: unknown; bugs?: unknown };
  assert.ok(Array.isArray(pkg.files) && pkg.files.length > 0);
  assert.ok(!pkg.files.some((f) => /tests|\.map/.test(f)));
  assert.equal(pkg.repository, undefined); // the repo is private; no URL is claimed
  assert.equal(pkg.homepage, undefined);
  assert.equal(pkg.bugs, undefined);
});

test('version is the same in package.json, --version and the CHANGELOG heading', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as { version: string };
  assert.equal(VERSION, pkg.version);
  assert.equal(spawnSync(process.execPath, [CLI, '--version'], { encoding: 'utf8' }).stdout.trim(), pkg.version);
  assert.match(readFileSync(join(ROOT, 'CHANGELOG.md'), 'utf8'), new RegExp(`^## ${pkg.version.replace(/\./g, '\\.')}`, 'm'));
});

// ---- depth checker: unit + differential/property ---------------------------------------

function refDepth(v: unknown): number {
  if (v === null || typeof v !== 'object') return 0;
  let d = 0;
  for (const c of Object.values(v)) d = Math.max(d, refDepth(c));
  return d + 1;
}

test('exceedsDepth: boundary and 100k-deep input without a stack overflow', () => {
  const nest = (n: number) => { let v: unknown = 'x'; for (let i = 0; i < n; i++) v = [v]; return v; };
  assert.equal(exceedsDepth(nest(MAX_ARG_DEPTH)), false);
  assert.equal(exceedsDepth(nest(MAX_ARG_DEPTH + 1)), true);
  assert.equal(exceedsDepth('s'), false);
  assert.equal(exceedsDepth(null), false);
  assert.equal(exceedsDepth(nest(100_000)), true);
});

test('exceedsDepth agrees with a recursive reference on 300 seeded random structures', () => {
  let seed = 12345;
  const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
  const gen = (d: number): unknown => {
    const r = rnd();
    if (d <= 0 || r < 0.25) return r < 0.1 ? null : r < 0.2 ? 'leaf' : 7;
    if (r < 0.6) return Array.from({ length: Math.floor(rnd() * 3) }, () => gen(d - 1 - Math.floor(rnd() * 2)));
    const o: Record<string, unknown> = {};
    for (let i = 0; i < Math.floor(rnd() * 3); i++) o[`k${i}`] = gen(d - 1 - Math.floor(rnd() * 2));
    return o;
  };
  for (let i = 0; i < 300; i++) {
    const v = gen(1 + Math.floor(rnd() * 14));
    const max = 1 + Math.floor(rnd() * 10);
    assert.equal(exceedsDepth(v, max), refDepth(v) > max, JSON.stringify(v));
  }
});

test('bearerToken: scheme is case-insensitive, other schemes and junk give null', () => {
  assert.equal(bearerToken('Bearer abc'), 'abc');
  assert.equal(bearerToken('bearer abc'), 'abc');
  assert.equal(bearerToken('BEARER   abc'), 'abc');
  assert.equal(bearerToken('Basic abc'), null);
  assert.equal(bearerToken('Bearerabc'), null);
  assert.equal(bearerToken(undefined), null);
  assert.equal(bearerToken(['Bearer a']), null);
});

// ---- live HTTP gateway ---------------------------------------------------------------

const rawReq = (port: number, method: string, headers: Record<string, string>, body?: string) =>
  new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }>((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path: '/mcp', method, headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers } }, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: b }));
    });
    req.on('error', reject);
    req.end(body);
  });
const rpc = (id: number, method: string, params?: unknown) => JSON.stringify({ jsonrpc: '2.0', id, method, params });
const initBody = rpc(1, 'initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } });

async function boot() {
  const server = new Server({ name: 'f', version: '1' }, { capabilities: { tools: {} } });
  let calls = 0;
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: 'echo', description: 'd', inputSchema: { type: 'object' as const } }] }));
  server.setRequestHandler(CallToolRequestSchema, async () => { calls += 1; return { content: [{ type: 'text' as const, text: 'ok' }] }; });
  const pair = InMemoryTransport.createLinkedPair();
  await server.connect(pair[1]);
  const audit = join(tmp(), 'audit.jsonl');
  const cfg = validateConfig(
    {
      servers: [{ name: 'srv', transport: 'stdio', command: 'true' }],
      auth: { keys: [{ id: 'k', key: KEY }] },
      audit: { path: audit },
      admin: { enabled: false },
      rateLimits: { default: { rps: 1000, burst: 1000 } },
      upstream: { stdio: { enabled: false }, http: { enabled: true, port: 0 } },
    } as Raw,
    'test',
  );
  const gw = await startGateway(cfg, { transportOverrides: new Map([['srv', pair[0]]]), noAdmin: true, log: () => undefined });
  const port = (gw.httpServer!.address() as { port: number }).port;
  const auth = { authorization: `Bearer ${KEY}` };
  const r = await rawReq(port, 'POST', auth, initBody);
  assert.equal(r.status, 200, r.body);
  const hdr = { ...auth, 'mcp-session-id': r.headers['mcp-session-id'] as string };
  await rawReq(port, 'POST', hdr, JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));
  return { gw, port, audit, auth, hdr, calls: () => calls, close: async () => { await gw.close(); await server.close().catch(() => undefined); } };
}

test('deeply nested arguments are refused (-32602), audited, never forwarded, and cannot open the breaker', async () => {
  const h = await boot();
  try {
    const deep = '['.repeat(60_000) + ']'.repeat(60_000);
    for (let i = 0; i < 12; i++) {
      const r = await rawReq(h.port, 'POST', h.hdr, `{"jsonrpc":"2.0","id":${10 + i},"method":"tools/call","params":{"name":"echo","arguments":{"t":${deep}}}}`);
      assert.match(r.body, /"code":-32602/);
      assert.match(r.body, /nest deeper than/);
    }
    assert.equal(h.calls(), 0, 'nothing reached the downstream server');
    const ok = await rawReq(h.port, 'POST', h.hdr, rpc(99, 'tools/call', { name: 'echo', arguments: { t: 'fine' } }));
    assert.match(ok.body, /"text":"ok"/, ok.body);
    assert.equal(h.calls(), 1);
    const lines = readFileSync(h.audit, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { status: string; policyReason?: string });
    assert.ok(lines.some((l) => l.status === 'denied' && l.policyReason === 'args_too_deep'));
  } finally {
    await h.close();
  }
});

test('lowercase "bearer" authenticates; a wrong scheme does not', async () => {
  const h = await boot();
  try {
    assert.equal((await rawReq(h.port, 'POST', { authorization: `bearer ${KEY}` }, initBody)).status, 200);
    assert.equal((await rawReq(h.port, 'POST', { authorization: `Basic ${KEY}` }, initBody)).status, 401);
  } finally {
    await h.close();
  }
});

test('unknown or closed session id answers 404 so clients re-initialize (MCP session rules)', async () => {
  const h = await boot();
  try {
    const bogus = { ...h.auth, 'mcp-session-id': 'no-such-session' };
    assert.equal((await rawReq(h.port, 'POST', bogus, rpc(2, 'tools/list'))).status, 404);
    assert.equal((await rawReq(h.port, 'GET', bogus)).status, 404);
    assert.equal((await rawReq(h.port, 'DELETE', bogus)).status, 404);
    assert.equal((await rawReq(h.port, 'DELETE', h.hdr)).status, 200);
    assert.equal((await rawReq(h.port, 'POST', h.hdr, rpc(3, 'tools/list'))).status, 404);
    // a fresh initialize still works afterwards
    assert.equal((await rawReq(h.port, 'POST', h.auth, initBody)).status, 200);
  } finally {
    await h.close();
  }
});

test('the HTTP server has slow-client deadlines', async () => {
  const h = await boot();
  try {
    assert.equal(h.gw.httpServer!.headersTimeout, 15_000);
    assert.equal(h.gw.httpServer!.requestTimeout, 60_000);
  } finally {
    await h.close();
  }
});

// ---- CLI usage errors ----------------------------------------------------------------------

test('a flag with no value is a plain usage error (exit 2), not "path undefined"', () => {
  for (const argv of [['serve', '-c'], ['validate', '-c', '--http'], ['policy-test', '--tool'], ['init', '-o']]) {
    const r = spawnSync(process.execPath, [CLI, ...argv], { encoding: 'utf8' });
    assert.equal(r.status, 2, argv.join(' '));
    assert.match(r.stderr, /needs a value/);
    assert.ok(!/undefined/.test(r.stderr));
  }
});

// ---- stdio mode: client goes away -------------------------------------------------------------

async function startStdioGateway(httpToo: boolean) {
  const { spawn } = await import('node:child_process');
  const dir = tmp();
  const cfgPath = join(dir, 'gw.yaml');
  writeFileSync(
    cfgPath,
    [
      'servers:',
      '  - name: fx',
      '    transport: stdio',
      `    command: ${JSON.stringify(process.execPath)}`,
      `    args: [${JSON.stringify(join(here, 'fixtures', 'stdio-server.js'))}]`,
      'auth:',
      httpToo ? `  keys: [{ id: k, key: ${JSON.stringify(KEY)} }]` : '  disabled: true',
      'audit:',
      `  path: ${JSON.stringify(join(dir, 'audit.jsonl'))}`,
      'admin:',
      '  enabled: false',
      'upstream:',
      '  stdio: { enabled: true }',
      httpToo ? '  http: { enabled: true, port: 0 }' : '  http: { enabled: false }',
      '',
    ].join('\n'),
  );
  const p = spawn(process.execPath, [CLI, 'serve', '-c', cfgPath], { stdio: ['pipe', 'pipe', 'pipe'] });
  let err = '';
  p.stderr.on('data', (d) => (err += d));
  for (let i = 0; i < 100 && !err.includes('serving'); i++) await new Promise((r) => setTimeout(r, 100));
  assert.match(err, /serving 4 unified tools/, err);
  const exited = new Promise<number | null>((resolve) => p.on('exit', (c) => resolve(c)));
  return { p, exited };
}

test('stdio-only mode: closing stdin shuts the gateway and its child server down (no orphans)', async () => {
  const { p, exited } = await startStdioGateway(false);
  p.stdin.end();
  const code = await Promise.race([exited, new Promise<string>((r) => setTimeout(() => r('hung'), 8000))]);
  if (code === 'hung') p.kill('SIGKILL');
  assert.equal(code, 0, 'gateway must exit by itself when stdin closes');
});

test('stdio + HTTP mode: no stdin (a supervisor) does NOT stop the gateway', async () => {
  const { p, exited } = await startStdioGateway(true);
  p.stdin.end();
  const state = await Promise.race([exited.then(() => 'exited'), new Promise<string>((r) => setTimeout(() => r('running'), 2000))]);
  p.kill('SIGTERM');
  assert.equal(state, 'running');
  assert.equal(await exited, 0);
});

// ---- Windows (static: these are pure functions; nothing here ran on Windows) ------------------------------

test('hasPathSeparator: backslash counts as a path only on win32', async () => {
  const { hasPathSeparator, commandCandidates } = await import('../src/config.js');
  assert.equal(hasPathSeparator('C:\\tools\\srv.exe', 'win32'), true);
  assert.equal(hasPathSeparator('.\\srv', 'win32'), true);
  assert.equal(hasPathSeparator('tools/srv', 'win32'), true);
  assert.equal(hasPathSeparator('npx', 'win32'), false);
  assert.equal(hasPathSeparator('a\\b', 'linux'), false); // a backslash is a legal file-name character on POSIX
  assert.equal(hasPathSeparator('/usr/bin/x', 'linux'), true);
  assert.ok(commandCandidates('C:\\tools\\srv', 'win32', '.EXE;.CMD').includes('C:\\tools\\srv.exe'));
});

test('policy-test: a broken config exits 2 (1 means DENY), DENY exits 1, ALLOW exits 0', () => {
  const dir = tmp();
  const good = join(dir, 'good.yaml');
  writeFileSync(good, ['servers:', '  - name: fx', '    transport: stdio', '    command: node', 'auth:', '  disabled: true', 'policy:', '  denyTools: ["rm_*"]', ''].join('\n'));
  const run = (...a: string[]) => spawnSync(process.execPath, [CLI, 'policy-test', ...a], { encoding: 'utf8' });
  assert.equal(run('-c', good, '--tool', 'echo').status, 0);
  assert.equal(run('-c', good, '--tool', 'rm_all').status, 1);
  const bad = join(dir, 'bad.yaml');
  writeFileSync(bad, 'servers: nope\n');
  const r = run('-c', bad, '--tool', 'echo');
  assert.equal(r.status, 2);
  assert.match(r.stderr + r.stdout, /invalid config/);
});
