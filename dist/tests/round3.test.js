/**
 * Round-3 tests: catalog pagination, annotations + pinning, read-only keys,
 * cancellation, argument-matching hardening, key hashes/expiry, audit
 * redaction of credential shapes, edge-failure auditing, admin hardening,
 * child stderr sanitizing, SIGKILL escalation, CLI helpers.
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
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListResourcesRequestSchema, ListToolsRequestSchema, ReadResourceRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { validateConfig, ConfigError } from '../src/config.js';
import { startGateway } from '../src/gateway.js';
import { redactText, redactDeep } from '../src/audit.js';
import { checkToolCall } from '../src/policy.js';
import { collectPages } from '../src/downstream.js';
import { legacyDefinitionHash, definitionHash } from '../src/pins.js';
import { hashKey, matchKey } from '../src/util.js';
const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(here, 'fixtures', 'stdio-server.js');
const CLI = join(here, '..', 'src', 'index.js');
const tmp = () => mkdtempSync(join(tmpdir(), 'mcpgw-r3-'));
function makeFake(tools, pageSize = 1000) {
    const fake = { server: null, tools, pageSize, failListAfterFirst: false, seenAbort: false, listCalls: 0 };
    const server = new Server({ name: 'f', version: '1' }, { capabilities: { tools: { listChanged: true }, resources: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async (req) => {
        fake.listCalls += 1;
        if (fake.failListAfterFirst && fake.listCalls > 1)
            throw new Error('listing exploded');
        const start = req.params?.cursor ? Number(req.params.cursor) : 0;
        const page = fake.tools.slice(start, start + fake.pageSize);
        const next = start + fake.pageSize < fake.tools.length ? String(start + fake.pageSize) : undefined;
        return {
            tools: page.map((t) => ({ name: t.name, description: t.description ?? 'd', inputSchema: { type: 'object' }, ...(t.annotations ? { annotations: t.annotations } : {}), ...(t.title ? { title: t.title } : {}) })),
            ...(next ? { nextCursor: next } : {}),
        };
    });
    server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
        if (req.params.name === 'slow') {
            await new Promise((resolve) => {
                const t = setTimeout(resolve, 3000);
                extra.signal.addEventListener('abort', () => {
                    fake.seenAbort = true;
                    clearTimeout(t);
                    resolve();
                });
            });
        }
        return { content: [{ type: 'text', text: `ran:${req.params.name}` }] };
    });
    server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: [{ uri: 'file:///r', name: 'r' }] }));
    server.setRequestHandler(ReadResourceRequestSchema, async () => ({ contents: [{ uri: 'file:///r', text: 'res' }] }));
    fake.server = server;
    return fake;
}
async function boot(fakes, extra = {}) {
    const overrides = new Map();
    for (const [name, f] of Object.entries(fakes)) {
        const pair = InMemoryTransport.createLinkedPair();
        await f.server.connect(pair[1]);
        overrides.set(name, pair[0]);
    }
    const audit = join(tmp(), 'audit.jsonl');
    const cfg = validateConfig({
        servers: Object.keys(fakes).map((name) => ({ name, transport: 'stdio', command: 'true' })),
        auth: { disabled: true },
        audit: { path: audit },
        admin: { enabled: false },
        rateLimits: { default: { rps: 1000, burst: 1000 } },
        ...extra,
    }, 'test');
    const gw = await startGateway(cfg, { transportOverrides: overrides, noAdmin: true, log: () => undefined });
    const up = InMemoryTransport.createLinkedPair();
    await gw.upstream.createMcpServer().connect(up[1]);
    const client = new Client({ name: 'c', version: '1' }, { capabilities: {} });
    await client.connect(up[0]);
    return {
        gw,
        client,
        audit,
        close: async () => {
            await client.close().catch(() => undefined);
            await gw.close();
            for (const f of Object.values(fakes))
                await f.server.close().catch(() => undefined);
        },
    };
}
const textOf = (r) => r.content[0].text;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// ---- catalog pagination ------------------------------------------------------
test('tools/list is followed across every page (0.3.0 saw only the first page)', async () => {
    const tools = Array.from({ length: 23 }, (_, i) => ({ name: `t${i}` }));
    const h = await boot({ srv: makeFake(tools, 5) });
    try {
        assert.equal((await h.client.listTools()).tools.length, 23);
    }
    finally {
        await h.close();
    }
});
test('collectPages: a server that loops its cursor cannot trap the gateway', async () => {
    let n = 0;
    const items = await collectPages(async () => ({ items: [n++], nextCursor: 'same' }));
    assert.equal(items.length, 2); // first page, then the repeated cursor ends the walk
    let pages = 0;
    const many = await collectPages(async () => ({ items: [1], nextCursor: String(pages++) }));
    assert.ok(many.length <= 200, 'bounded page count');
});
test('a failed catalog refresh keeps the previous tools instead of emptying the server', async () => {
    const fake = makeFake([{ name: 'a' }, { name: 'b' }]);
    const h = await boot({ srv: fake });
    try {
        assert.equal((await h.client.listTools()).tools.length, 2);
        fake.failListAfterFirst = true;
        await h.gw.reloadCatalogs();
        assert.equal((await h.client.listTools()).tools.length, 2, 'tools survived a failed refresh');
        assert.match(h.gw.servers[0]?.lastError ?? '', /kept previous/);
    }
    finally {
        await h.close();
    }
});
// ---- annotations, titles and pinning -----------------------------------------
test('annotations and title are forwarded (clients use readOnlyHint to decide what to auto-approve)', async () => {
    const h = await boot({ srv: makeFake([{ name: 'ro', annotations: { readOnlyHint: true }, title: 'Read only' }, { name: 'plain' }]) });
    try {
        const tools = (await h.client.listTools()).tools;
        const ro = tools.find((t) => t.name === 'ro');
        assert.deepEqual(ro?.annotations, { readOnlyHint: true });
        assert.equal(ro?.title, 'Read only');
        assert.equal(tools.find((t) => t.name === 'plain')?.annotations, undefined);
    }
    finally {
        await h.close();
    }
});
test('pinning covers annotations: flipping readOnlyHint is a rug pull', async () => {
    const fake = makeFake([{ name: 'ro', annotations: { readOnlyHint: true } }]);
    const pinFile = join(tmp(), 'pins.json');
    const h = await boot({ srv: fake }, { policy: { pinning: { mode: 'block', file: pinFile } } });
    try {
        assert.equal((await h.client.listTools()).tools.length, 1);
        fake.tools = [{ name: 'ro', annotations: { readOnlyHint: false } }];
        await h.gw.reloadCatalogs();
        assert.equal((await h.client.listTools()).tools.length, 0, 'quarantined');
        assert.deepEqual(h.gw.pins.violationKeys(), ['srv:ro']);
    }
    finally {
        await h.close();
    }
});
test('a 0.3.0 pin file upgrades once, silently, then is strict (version 2)', async () => {
    const dir = tmp();
    const pinFile = join(dir, 'pins.json');
    const tool = { server: 'srv', originalName: 'ro', description: 'd', inputSchema: { type: 'object' } };
    writeFileSync(pinFile, JSON.stringify({ version: 1, pins: { 'srv:ro': legacyDefinitionHash(tool) } }));
    const fake = makeFake([{ name: 'ro', annotations: { readOnlyHint: true } }]);
    const h = await boot({ srv: fake }, { policy: { pinning: { mode: 'block', file: pinFile } } });
    try {
        assert.equal((await h.client.listTools()).tools.length, 1, 'legacy pin still valid');
        assert.equal(JSON.parse(readFileSync(pinFile, 'utf8')).version, 2);
        assert.equal(JSON.parse(readFileSync(pinFile, 'utf8')).pins['srv:ro'], definitionHash({ ...tool, annotations: { readOnlyHint: true } }));
        fake.tools = [{ name: 'ro', annotations: { readOnlyHint: true, destructiveHint: true } }];
        await h.gw.reloadCatalogs();
        assert.equal((await h.client.listTools()).tools.length, 0, 'strict after the upgrade');
    }
    finally {
        await h.close();
    }
});
test('a tool without annotations hashes exactly as in 0.3.0 (existing pins stay valid)', () => {
    const t = { server: 's', originalName: 'x', description: 'd', inputSchema: { type: 'object' } };
    assert.equal(definitionHash(t), legacyDefinitionHash(t));
});
// ---- HTTP: read-only keys, allowServers, auth failures ----------------------------
const rawReq = (port, method, path, headers, body) => new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method, headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers } }, (res) => {
        let b = '';
        res.on('data', (c) => (b += c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: b }));
    });
    req.on('error', reject);
    req.end(body);
});
const post = (port, headers, body) => rawReq(port, 'POST', '/mcp', headers, body);
const init = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
// built at runtime: no contiguous key-looking literals in the repo
const K1 = ['reader', 'key', 'x'.repeat(16)].join('-');
const K2 = ['writer', 'key', 'y'.repeat(16)].join('-');
async function bootHttp(keys, fakes, extra = {}) {
    const overrides = new Map();
    for (const [name, f] of Object.entries(fakes)) {
        const pair = InMemoryTransport.createLinkedPair();
        await f.server.connect(pair[1]);
        overrides.set(name, pair[0]);
    }
    const audit = join(tmp(), 'audit.jsonl');
    const cfg = validateConfig({
        servers: Object.keys(fakes).map((name) => ({ name, transport: 'stdio', command: 'true' })),
        auth: { keys },
        audit: { path: audit },
        admin: { enabled: false },
        rateLimits: { default: { rps: 1000, burst: 1000 } },
        upstream: { stdio: { enabled: false }, http: { enabled: true, port: 0 } },
        ...extra,
    }, 'test');
    const gw = await startGateway(cfg, { transportOverrides: overrides, noAdmin: true, log: () => undefined });
    const port = gw.httpServer.address().port;
    return { gw, port, audit, close: async () => { await gw.close(); for (const f of Object.values(fakes))
            await f.server.close().catch(() => undefined); } };
}
async function session(port, key) {
    const r = await post(port, { authorization: `Bearer ${key}` }, init);
    assert.equal(r.status, 200, r.body);
    return { authorization: `Bearer ${key}`, 'mcp-session-id': r.headers['mcp-session-id'] };
}
const rpc = (id, method, params) => JSON.stringify({ jsonrpc: '2.0', id, method, params });
test('readOnly key sees only tools whose server declared readOnlyHint:true (no hint = not read-only)', async () => {
    const f = makeFake([{ name: 'get_x', annotations: { readOnlyHint: true } }, { name: 'set_x', annotations: { readOnlyHint: false } }, { name: 'mystery' }]);
    const h = await bootHttp([{ id: 'ro', key: K1, readOnly: true }, { id: 'rw', key: K2 }], { srv: f });
    try {
        const ro = await session(h.port, K1);
        const list = await post(h.port, ro, rpc(2, 'tools/list'));
        assert.ok(list.body.includes('get_x') && !list.body.includes('set_x') && !list.body.includes('mystery'), list.body);
        assert.ok((await post(h.port, ro, rpc(3, 'tools/call', { name: 'set_x', arguments: {} }))).body.includes('unknown tool'));
        assert.ok((await post(h.port, ro, rpc(4, 'tools/call', { name: 'get_x', arguments: {} }))).body.includes('ran:get_x'));
        const rw = await session(h.port, K2);
        assert.ok((await post(h.port, rw, rpc(5, 'tools/call', { name: 'set_x', arguments: {} }))).body.includes('ran:set_x'));
    }
    finally {
        await h.close();
    }
});
test('allowServers limits tools, resources and prompts to named servers', async () => {
    const a = makeFake([{ name: 'a_tool' }]);
    const b = makeFake([{ name: 'b_tool' }]);
    const h = await bootHttp([{ id: 'onlyA', key: K1, scopes: ['tools:call', 'tools:list', 'resources:*'], allowServers: ['a'] }], { a, b });
    try {
        const s = await session(h.port, K1);
        const list = await post(h.port, s, rpc(2, 'tools/list'));
        assert.ok(list.body.includes('a_tool') && !list.body.includes('b_tool'));
        const res = await post(h.port, s, rpc(3, 'resources/list'));
        assert.ok(res.body.includes('mcpgateway://a/') && !res.body.includes('mcpgateway://b/'), res.body);
        const uriB = 'mcpgateway://b/' + encodeURIComponent('file:///r');
        assert.ok((await post(h.port, s, rpc(4, 'resources/read', { uri: uriB }))).body.includes('unknown resource'));
        assert.ok((await post(h.port, s, rpc(5, 'tools/call', { name: 'b_tool', arguments: {} }))).body.includes('unknown tool'));
    }
    finally {
        await h.close();
    }
});
test('edge failures are audited, counted, and the audit writes are bounded', async () => {
    const h = await bootHttp([{ id: 'k', key: K1 }], { srv: makeFake([{ name: 't' }]) });
    try {
        for (let i = 0; i < 40; i++)
            assert.equal((await post(h.port, { authorization: 'Bearer wrong-wrong-wrong-wrong' }, init)).status, 401);
        const lines = readFileSync(h.audit, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
        const failed = lines.filter((r) => r.status === 'auth_failed');
        assert.equal(failed.length, 30, 'capped at 30 per minute');
        assert.ok(failed.every((r) => r.errorCode === 'bad_key'));
        assert.ok(!readFileSync(h.audit, 'utf8').includes('wrong-wrong'), 'the presented token is never logged');
        assert.match(h.gw.metrics.render(), /mcpgateway_auth_failures_total\{reason="bad_key"\} 40/);
    }
    finally {
        await h.close();
    }
});
test('per-key call metric exists and is bounded by configured key ids', async () => {
    const h = await bootHttp([{ id: 'k1', key: K1 }], { srv: makeFake([{ name: 't' }]) });
    try {
        const s = await session(h.port, K1);
        await post(h.port, s, rpc(2, 'tools/call', { name: 't', arguments: {} }));
        assert.match(h.gw.metrics.render(), /mcpgateway_key_calls_total\{key="k1",status="ok"\} 1/);
    }
    finally {
        await h.close();
    }
});
// ---- cancellation ------------------------------------------------------------------
test('a client that cancels a call cancels it downstream, without tripping the breaker', async () => {
    const fake = makeFake([{ name: 'slow' }, { name: 'quick' }]);
    const h = await boot({ srv: fake });
    try {
        const ac = new AbortController();
        const p = h.client.callTool({ name: 'slow', arguments: {} }, undefined, { signal: ac.signal }).catch((e) => e);
        await sleep(150);
        ac.abort();
        await p;
        await sleep(200);
        assert.equal(fake.seenAbort, true, 'downstream server saw the cancellation');
        assert.equal(h.gw.servers[0]?.circuitState, 'closed');
        assert.match(h.gw.metrics.render(), /mcpgateway_tool_calls_cancelled_total 1/);
        assert.equal(textOf(await h.client.callTool({ name: 'quick', arguments: {} })), 'ran:quick');
    }
    finally {
        await h.close();
    }
});
// ---- argument rule hardening -----------------------------------------------------------
const pol = (argMatch, rule) => validateConfig({ servers: [{ name: 's', transport: 'stdio', command: 'true' }], auth: { disabled: true }, policy: { argRules: { t: rule }, argMatch } }, 'test').policy;
test('Windows paths: a deny pattern with a backslash matches (JSON escaping used to hide it)', () => {
    const p = pol({}, { deny: ['C:\\Windows\\System32'] });
    assert.equal(checkToolCall(p, 't', { path: 'C:\\Windows\\System32\\cmd.exe' }).decision, 'deny');
    assert.equal(checkToolCall(p, 't', { path: 'D:\\ok' }).decision, 'allow');
});
test('keys and nested values are matched, and the 0.3.0 JSON-substring behaviour still works', () => {
    const p = pol({}, { deny: ['"drop"', 'rm -rf'] });
    assert.equal(checkToolCall(p, 't', { a: [{ cmd: 'rm -rf /' }] }).decision, 'deny');
    assert.equal(checkToolCall(p, 't', { drop: 1 }).decision, 'deny', 'JSON form (quotes included) still matches');
});
test('ignoreCase and normalizePaths close the cheap bypasses', () => {
    const strict = pol({}, { deny: ['/etc/passwd'] });
    assert.equal(checkToolCall(strict, 't', { p: '/etc//passwd' }).decision, 'allow', 'the documented default stays exact');
    const hard = pol({ ignoreCase: true, normalizePaths: true }, { deny: ['/etc/passwd'] });
    for (const evil of ['/ETC/Passwd', '/etc//passwd', '/etc/./passwd', '/tmp/../etc/passwd', '\\etc\\passwd', '/etc/%70asswd', '%2fetc%2fpasswd']) {
        assert.equal(checkToolCall(hard, 't', { p: evil }).decision, 'deny', evil);
    }
    assert.equal(checkToolCall(hard, 't', { p: '/etc/hosts' }).decision, 'allow');
});
test('normalizePaths does not break URL patterns', () => {
    const p = pol({ normalizePaths: true }, { deny: ['http://169.254.169.254'] });
    assert.equal(checkToolCall(p, 't', { url: 'http://169.254.169.254/latest' }).decision, 'deny');
    assert.equal(checkToolCall(p, 't', { url: 'https://example.com' }).decision, 'allow');
});
test('allow rules also see raw values', () => {
    const p = pol({}, { allow: ['C:\\work\\'] });
    assert.equal(checkToolCall(p, 't', { path: 'C:\\work\\a.txt' }).decision, 'allow');
    assert.equal(checkToolCall(p, 't', { path: 'C:\\other' }).decision, 'deny');
});
test('hostile arguments cannot stall rule evaluation', () => {
    const p = pol({ ignoreCase: true, normalizePaths: true }, { deny: ['zzz'] });
    const big = { a: 'x/'.repeat(500_000), many: Array.from({ length: 50_000 }, (_, i) => `v${i}`), deep: JSON.parse('['.repeat(30) + ']'.repeat(30)) };
    const t0 = Date.now();
    assert.equal(checkToolCall(p, 't', big).decision, 'allow');
    assert.ok(Date.now() - t0 < 1500, `took ${Date.now() - t0}ms`);
});
test('argMatch config: unknown key and wrong type are errors', () => {
    const mk = (argMatch) => () => validateConfig({ servers: [{ name: 's', transport: 'stdio', command: 'true' }], auth: { disabled: true }, policy: { argMatch } }, 'test');
    assert.throws(mk({ ignorecase: true }), ConfigError);
    assert.throws(mk({ ignoreCase: 'yes' }), ConfigError);
});
// ---- keys: hash, expiry ----------------------------------------------------------------------
test('keyHash: the config never needs the secret; matching and expiry', () => {
    const keys = [{ key: '', keyHash: hashKey(K1), id: 'a' }, { key: K2, id: 'b', expiresAt: 1000 }];
    assert.equal(matchKey(keys, K1)?.id, 'a');
    assert.equal(matchKey(keys, K2, 999)?.id, 'b');
    assert.equal(matchKey(keys, K2, 1000), null, 'expired');
    assert.equal(matchKey(keys, K1 + 'x'), null);
});
test('config validation for keyHash / expiresAt / readOnly', () => {
    const mk = (key) => () => validateConfig({ servers: [{ name: 's', transport: 'stdio', command: 'true' }], auth: { keys: [key] } }, 'test');
    assert.doesNotThrow(mk({ id: 'a', keyHash: hashKey(K1), expiresAt: '2099-01-01T00:00:00Z', readOnly: true, allowServers: ['s'] }));
    assert.throws(mk({ id: 'a', key: K1, keyHash: hashKey(K1) }), /either "key" or "keyHash"/);
    assert.throws(mk({ id: 'a', keyHash: 'sha256:xyz' }), /keyHash/);
    assert.throws(mk({ id: 'a', key: K1, expiresAt: 'tomorrow-ish' }), /expiresAt/);
    assert.throws(mk({ id: 'a', key: K1, readOnly: 'yes' }), /readOnly/);
});
test('an expired key is refused at the edge', async () => {
    const h = await bootHttp([{ id: 'old', key: K1, expiresAt: '2001-01-01T00:00:00Z' }], { srv: makeFake([{ name: 't' }]) });
    try {
        assert.equal((await post(h.port, { authorization: `Bearer ${K1}` }, init)).status, 401);
    }
    finally {
        await h.close();
    }
});
// ---- audit redaction of credential shapes ------------------------------------------------------------
// Shapes are assembled at runtime so no contiguous secret-looking literal is committed.
const fakeSecrets = () => ({
    bearer: 'Bearer ' + 'a1B2c3D4'.repeat(4),
    jwt: ['eyJ' + 'h'.repeat(10), 'p'.repeat(12), 's'.repeat(12)].join('.'),
    sk: 'sk' + '-' + 'Z9'.repeat(12),
    aws: 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP',
    gh: 'gh' + 'p_' + 'q'.repeat(36),
    slack: 'xo' + 'xb-' + '1234567890-abc',
    url: 'postgres://admin:hunter2pw@db.internal/x',
    pem: '-----BEGIN ' + 'RSA PRIVATE KEY-----',
});
test('credential shapes are redacted wherever they sit, not only under secret-looking keys', () => {
    const s = fakeSecrets();
    const out = JSON.stringify(redactDeep({ query: `use ${s.bearer} now`, notes: [s.jwt, s.sk, s.aws], deep: { x: `${s.gh} ${s.slack} ${s.url} ${s.pem}` }, ok: 'plain words stay' }, [], true));
    const secretPieces = [s.bearer.slice(7), s.jwt, s.sk, s.aws, s.gh, s.slack, 'hunter2pw', s.pem];
    for (const piece of secretPieces)
        assert.ok(!out.includes(piece), `leaked: ${piece.slice(0, 6)}...`);
    assert.ok(out.includes('plain words stay'));
    assert.ok(out.includes('postgres://[REDACTED]@db.internal/x'));
    // without the flag, the shape redaction is off (0.3.0 behaviour for direct callers)
    assert.ok(JSON.stringify(redactDeep({ q: s.sk }, [])).includes(s.sk));
});
test('redactText leaves ordinary text and is fast on pathological input', () => {
    assert.equal(redactText('the sky is blue, sk is short, Bearer too'), 'the sky is blue, sk is short, Bearer too');
    const t0 = Date.now();
    redactText('Bearer ' + 'a'.repeat(200_000) + ' ' + 'eyJ'.repeat(100_000) + ':'.repeat(100_000) + '@'.repeat(50_000));
    assert.ok(Date.now() - t0 < 1500, `took ${Date.now() - t0}ms`);
});
test('audit records are value-redacted end to end; audit.redactValues:false opts out', async () => {
    const s = fakeSecrets();
    for (const optOut of [false, true]) {
        const path = join(tmp(), 'a.jsonl');
        const h = await boot({ srv: makeFake([{ name: 't' }]) }, { audit: optOut ? { path, redactValues: false } : { path } });
        try {
            await h.client.callTool({ name: 't', arguments: { note: s.sk } });
            assert.equal(readFileSync(path, 'utf8').includes(s.sk), optOut);
        }
        finally {
            await h.close();
        }
    }
});
// ---- admin hardening ---------------------------------------------------------------------------------------
async function bootAdmin(auth) {
    const fake = makeFake([{ name: 't' }]);
    const pair = InMemoryTransport.createLinkedPair();
    await fake.server.connect(pair[1]);
    const audit = join(tmp(), 'audit.jsonl');
    const cfg = validateConfig({ servers: [{ name: 'srv', transport: 'stdio', command: 'true' }], auth, audit: { path: audit }, admin: { enabled: true, port: 0 }, policy: { pinning: { mode: 'warn' } } }, 'test');
    const gw = await startGateway(cfg, { transportOverrides: new Map([['srv', pair[0]]]), log: () => undefined });
    const port = gw.adminServer.address().port;
    return { gw, port, audit, close: async () => { await gw.close(); await fake.server.close().catch(() => undefined); } };
}
test('admin API refuses a rebound Host header (DNS rebinding) and a foreign Origin', async () => {
    const h = await bootAdmin({ disabled: true });
    try {
        assert.equal((await rawReq(h.port, 'GET', '/v1/registry', {})).status, 200);
        assert.equal((await rawReq(h.port, 'GET', '/v1/registry', { host: 'evil.example:80' })).status, 403);
        assert.equal((await rawReq(h.port, 'POST', '/v1/pins/accept', { origin: 'http://evil.example' })).status, 403);
    }
    finally {
        await h.close();
    }
});
test('anonymous /healthz hides downstream error text; a valid key sees it; admin actions are audited', async () => {
    const h = await bootAdmin({ keys: [{ id: 'ops', key: K1, scopes: ['admin', 'tools:list'] }] });
    try {
        h.gw.servers[0].lastError = 'boom token=' + 'p'.repeat(5);
        const anon = JSON.parse((await rawReq(h.port, 'GET', '/healthz', {})).body);
        assert.equal(anon.servers[0].lastError, undefined);
        assert.equal(anon.servers[0].name, 'srv');
        const authed = JSON.parse((await rawReq(h.port, 'GET', '/healthz', { authorization: `Bearer ${K1}` })).body);
        assert.match(authed.servers[0].lastError, /boom/);
        assert.equal((await rawReq(h.port, 'POST', '/v1/reload', { authorization: `Bearer ${K1}` })).status, 200);
        assert.equal((await rawReq(h.port, 'POST', '/v1/pins/accept', { authorization: `Bearer ${K1}` })).status, 200);
        const recs = readFileSync(h.audit, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
        assert.deepEqual(recs.filter((r) => String(r.tool).startsWith('admin:')).map((r) => `${r.tool}/${r.keyId}`), ['admin:reload/ops', 'admin:pins.accept/ops']);
    }
    finally {
        await h.close();
    }
});
// ---- child processes -----------------------------------------------------------------------------------------------
async function bootFixture(env, lines) {
    const cfg = validateConfig({
        servers: [{ name: 'fx', transport: 'stdio', command: process.execPath, args: [FIXTURE], env, timeoutMs: 2000 }],
        auth: { disabled: true },
        audit: { path: join(tmp(), 'audit.jsonl') },
        admin: { enabled: false },
    }, 'test');
    return startGateway(cfg, { noAdmin: true, log: () => undefined, onChildStderr: (_s, l) => lines.push(l) });
}
test('a server\'s stderr is sanitized: escape sequences and bidi overrides never reach the terminal', async () => {
    const lines = [];
    const gw = await bootFixture({ FIXTURE_STDERR_ESC: '1' }, lines);
    try {
        await sleep(200);
        const joined = lines.join('\n');
        assert.ok(joined.includes('red'), joined);
        // eslint-disable-next-line no-control-regex
        assert.ok(!/[\u001b\u0007\u202e\r]/.test(joined), JSON.stringify(joined));
    }
    finally {
        await gw.close();
    }
});
test('a child that ignores SIGTERM is SIGKILLed on shutdown (no orphan)', { skip: process.platform === 'win32' }, async () => {
    const lines = [];
    const gw = await bootFixture({ FIXTURE_IGNORE_SIGTERM: '1', FIXTURE_PRINT_PID: '1' }, lines);
    await sleep(200);
    const pid = Number(lines.find((l) => l.startsWith('PID:'))?.slice(4));
    assert.ok(pid > 0, lines.join('|'));
    process.kill(pid, 0); // alive
    await gw.close();
    await sleep(100);
    assert.throws(() => process.kill(pid, 0), /ESRCH/);
});
// ---- CLI -----------------------------------------------------------------------------------------------------------------
const cli = (args, input) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', input });
test('cli hash-key: stdin, env and --generate; refuses short keys', () => {
    const k = 'k'.repeat(20);
    assert.equal(cli(['hash-key'], k + '\n').stdout.trim(), `keyHash: ${hashKey(k)}`);
    const env = spawnSync(process.execPath, [CLI, 'hash-key', '--key-env', 'MY_K'], { encoding: 'utf8', env: { ...process.env, MY_K: k } });
    assert.equal(env.stdout.trim(), `keyHash: ${hashKey(k)}`);
    const gen = cli(['hash-key', '--generate']);
    assert.match(gen.stdout, /key \(give this to the client.*: [0-9a-f]{64}\nkeyHash: sha256:[0-9a-f]{64}/);
    assert.equal(cli(['hash-key'], 'short').status, 2);
});
test('cli policy-test: allow, deny with reason, hidden, key ACL, bad JSON', () => {
    const dir = tmp();
    const cfg = join(dir, 'c.yaml');
    writeFileSync(cfg, [
        'servers:',
        '  - name: s',
        '    transport: stdio',
        '    command: "true"',
        'auth:',
        '  keys:',
        '    - id: bot',
        `      key: ${K1}`,
        '      allowTools: ["read_*"]',
        'policy:',
        '  hideTools: ["secret_*"]',
        '  denyTools: ["drop_*"]',
        '  argMatch: { ignoreCase: true, normalizePaths: true }',
        '  argRules:',
        '    read_file: { deny: ["/etc/passwd"] }',
        '',
    ].join('\n'));
    const t = (args) => cli(['policy-test', '-c', cfg, ...args]);
    assert.equal(t(['--tool', 'read_file', '--args', '{"p":"/home/a"}']).status, 0);
    const denied = t(['--tool', 'read_file', '--args', '{"p":"/etc/../ETC/passwd"}']);
    assert.equal(denied.status, 1);
    assert.match(denied.stdout, /DENY\s+arg_deny/);
    assert.match(t(['--tool', 'secret_a']).stdout, /hidden/);
    assert.match(t(['--tool', 'drop_table']).stdout, /deny_list/);
    assert.match(t(['--tool', 'write_file', '--key', 'bot']).stdout, /key "bot" may not use/);
    assert.equal(t(['--tool', 'x', '--args', '{nope']).status, 2);
    assert.equal(t(['--tool', 'x', '--key', 'ghost']).status, 2);
});
test('example config still validates', () => {
    const r = spawnSync(process.execPath, [CLI, 'validate', '-c', join(here, '..', '..', 'mcpgateway.example.yaml')], { encoding: 'utf8', env: { ...process.env, GATEWAY_KEY: 'g'.repeat(24) } });
    assert.notEqual(r.status, 2, r.stdout + r.stderr);
});
// ---- untrusted text in logs and audit ------------------------------------------------------------------------------------
test('hostile tool names: operator log lines and audit files carry no raw control/bidi characters, and the chain still verifies', async () => {
    const lines = [];
    const evil = 'bad\u001b[2J‮name';
    const fake = makeFake([{ name: 'ok' }, { name: evil }]);
    const pair = InMemoryTransport.createLinkedPair();
    await fake.server.connect(pair[1]);
    const audit = join(tmp(), 'audit.jsonl');
    const cfg = validateConfig({ servers: [{ name: 'srv', transport: 'stdio', command: 'true' }], auth: { disabled: true }, audit: { path: audit, chain: true }, admin: { enabled: false } }, 'test');
    const gw = await startGateway(cfg, { transportOverrides: new Map([['srv', pair[0]]]), noAdmin: true, log: (m) => lines.push(m) });
    const up = InMemoryTransport.createLinkedPair();
    await gw.upstream.createMcpServer().connect(up[1]);
    const client = new Client({ name: 'c', version: '1' }, { capabilities: {} });
    await client.connect(up[0]);
    try {
        const err = await client.callTool({ name: evil, arguments: { note: '‮​hidden' } }).catch((e) => e.message);
        // eslint-disable-next-line no-control-regex
        const raw = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿]/;
        assert.ok(!raw.test(String(err)), 'error text sent back');
        assert.ok(lines.length > 0 && lines.every((l) => !raw.test(l)), 'operator log');
        const file = readFileSync(audit, 'utf8');
        assert.ok(!raw.test(file.replace(/\n/g, '')), 'audit file');
        assert.match(file, /\\u202e/);
        const { verifyChain } = await import('../src/audit.js');
        assert.equal(verifyChain([audit]).ok, true);
    }
    finally {
        await client.close().catch(() => undefined);
        await gw.close();
        await fake.server.close().catch(() => undefined);
    }
});
test('Windows: bare commands are looked up through PATHEXT (npx -> npx.cmd)', async () => {
    const { commandCandidates } = await import('../src/config.js');
    assert.deepEqual(commandCandidates('node', 'linux'), ['node']);
    const w = commandCandidates('npx', 'win32', '.COM;.EXE;.CMD');
    assert.ok(w.includes('npx.cmd') && w.includes('npx.CMD') && w[0] === 'npx');
    assert.deepEqual(commandCandidates('tool.exe', 'win32', '.COM;.EXE'), ['tool.exe']);
});
// ---- HTTP robustness ---------------------------------------------------------------------------------------------------------------
test('empty, truncated and NUL bodies get 400 (they used to hang the request forever); oversized batches get 413', async () => {
    const h = await bootHttp([{ id: 'k', key: K1 }], { srv: makeFake([{ name: 't' }]) });
    try {
        const s = await session(h.port, K1);
        const timed = (body) => Promise.race([post(h.port, s, body), new Promise((r) => setTimeout(() => r({ status: -1 }), 3000))]);
        for (const b of ['', '{', '\u0000', '[{"jsonrpc":"2.0"'])
            assert.equal((await timed(b)).status, 400, JSON.stringify(b));
        const big = '[' + Array.from({ length: 101 }, (_, i) => `{"jsonrpc":"2.0","id":${i},"method":"ping"}`).join(',') + ']';
        assert.equal((await timed(big)).status, 413);
        const ok = '[' + Array.from({ length: 100 }, (_, i) => `{"jsonrpc":"2.0","id":${i + 5},"method":"ping"}`).join(',') + ']';
        assert.equal((await timed(ok)).status, 200);
    }
    finally {
        await h.close();
    }
});
test('hardened matching also defeats invisible characters, full-width forms and double encoding', () => {
    const hard = pol({ ignoreCase: true, normalizePaths: true }, { deny: ['/etc/passwd'] });
    for (const evil of ['/etc/pa​sswd', '/e⁠tc/passwd', '／etc／passwd', '/etc/%2570asswd', '%252fetc%252fpasswd', '/etc/pass­wd']) {
        assert.equal(checkToolCall(hard, 't', { p: evil }).decision, 'deny', JSON.stringify(evil));
    }
});
test('log lines cannot be forged with newlines in server-controlled text', async () => {
    const lines = [];
    const fake = makeFake([{ name: 'ok' }, { name: 'x\n[mcpgateway] FAKE LINE\rmore' }]);
    const pair = InMemoryTransport.createLinkedPair();
    await fake.server.connect(pair[1]);
    const cfg = validateConfig({ servers: [{ name: 'srv', transport: 'stdio', command: 'true' }], auth: { disabled: true }, audit: { path: join(tmp(), 'a.jsonl') }, admin: { enabled: false } }, 'test');
    const gw = await startGateway(cfg, { transportOverrides: new Map([['srv', pair[0]]]), noAdmin: true, log: (m) => lines.push(m) });
    try {
        assert.ok(lines.length > 0 && lines.every((l) => !/[\r\n]/.test(l)), JSON.stringify(lines));
    }
    finally {
        await gw.close();
        await fake.server.close().catch(() => undefined);
    }
});
//# sourceMappingURL=round3.test.js.map