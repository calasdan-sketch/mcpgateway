// Reproducible benchmark: `npm run build && node bench/run.mjs`
// Needs only this repo (spawns its own stdio fixture). Numbers vary by machine;
// the RATIOS are the point. Token counts are chars/4 estimates, not a tokenizer.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { validateConfig } from '../dist/src/config.js';
import { startGateway } from '../dist/src/gateway.js';
import { AuditLogger, redactText } from '../dist/src/audit.js';
import { checkToolCall } from '../dist/src/policy.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE = join(root, 'dist', 'tests', 'fixtures', 'stdio-server.js');
const dir = mkdtempSync(join(tmpdir(), 'mcpgw-bench-'));

async function gateway(extra, tools) {
  const cfg = validateConfig({
    servers: [{ name: 'fx', transport: 'stdio', command: process.execPath, args: [FIXTURE], env: { FIXTURE_TOOLS: String(tools) } }],
    auth: { disabled: true }, audit: { path: join(dir, `a-${Math.random()}.jsonl`) }, admin: { enabled: false },
    rateLimits: { default: { rps: 1e6, burst: 1e6 } }, ...extra,
  }, 'bench');
  const gw = await startGateway(cfg, { noAdmin: true, log: () => {} });
  const up = InMemoryTransport.createLinkedPair();
  await gw.upstream.createMcpServer().connect(up[1]);
  const client = new Client({ name: 'b', version: '1' }, { capabilities: {} });
  await client.connect(up[0]);
  return { gw, client, close: async () => { await client.close(); await gw.close(); } };
}

const pct = (a, p) => a[Math.min(a.length - 1, Math.floor(a.length * p))];
async function time(n, fn) {
  for (let i = 0; i < 200; i++) await fn();
  const t = [];
  for (let i = 0; i < n; i++) { const s = process.hrtime.bigint(); await fn(); t.push(Number(process.hrtime.bigint() - s) / 1e3); }
  t.sort((a, b) => a - b);
  return { p50: pct(t, 0.5), p95: pct(t, 0.95), p99: pct(t, 0.99) };
}
const us = (x) => `${x.toFixed(0)}us`;

console.log('## 1. tools/list size an agent must read (what it costs in context every session)');
console.log('| tools behind gateway | full: bytes | full: ~tokens | search mode: bytes | search mode: ~tokens | reduction |');
console.log('|---|---|---|---|---|---|');
for (const n of [20, 100, 500]) {
  const full = await gateway({}, n);
  const search = await gateway({ exposure: { mode: 'search' } }, n);
  const fb = JSON.stringify((await full.client.listTools()).tools).length;
  const sb = JSON.stringify((await search.client.listTools()).tools).length;
  console.log(`| ${n + 3} | ${fb} | ${Math.round(fb / 4)} | ${sb} | ${Math.round(sb / 4)} | ${(fb / sb).toFixed(1)}x |`);
  await full.close(); await search.close();
}

console.log('\n## 2. per-call latency: direct stdio server vs through the gateway (sequential echo, 2000 calls)');
const direct = new Client({ name: 'd', version: '1' }, { capabilities: {} });
await direct.connect(new StdioClientTransport({ command: process.execPath, args: [FIXTURE], stderr: 'inherit' }));
const d = await time(2000, () => direct.callTool({ name: 'echo', arguments: { text: 'x' } }));
await direct.close();
const g = await gateway({}, 0);
const gr = await time(2000, () => g.client.callTool({ name: 'echo', arguments: { text: 'x' } }));
await g.close();
const gc = await gateway({ audit: { path: join(dir, 'chain.jsonl'), chain: true } }, 0);
const gcr = await time(2000, () => gc.client.callTool({ name: 'echo', arguments: { text: 'x' } }));
await gc.close();
console.log('| path | p50 | p95 | p99 |\n|---|---|---|---|');
console.log(`| direct (client -> server) | ${us(d.p50)} | ${us(d.p95)} | ${us(d.p99)} |`);
console.log(`| gateway (policy+rate limit+audit+metrics) | ${us(gr.p50)} | ${us(gr.p95)} | ${us(gr.p99)} |`);
console.log(`| gateway + audit hash chain | ${us(gcr.p50)} | ${us(gcr.p95)} | ${us(gcr.p99)} |`);
console.log(`gateway overhead at p50: ${us(gr.p50 - d.p50)} (upstream is in-memory here, so this isolates the gateway pipeline + one extra hop)`);

console.log('\n## 2b. large results: 1,000,000-char tool result through the gateway (300 calls)');
const bigCall = (c) => () => c.callTool({ name: 'big', arguments: { n: 1000000 } });
const dbig = new Client({ name: 'd', version: '1' }, { capabilities: {} });
await dbig.connect(new StdioClientTransport({ command: process.execPath, args: [FIXTURE], stderr: 'inherit' }));
const bd = await time(300, bigCall(dbig)); await dbig.close();
const gb0 = await gateway({}, 0);
const b0 = await time(300, bigCall(gb0.client)); await gb0.close();
const gb1 = await gateway({ policy: { responseRedact: ['AKIA'], responseWarn: ['password'] } }, 0);
const b1 = await time(300, bigCall(gb1.client)); await gb1.close();
console.log('| config | p50 | p95 |\n|---|---|---|');
console.log(`| direct (no gateway) | ${us(bd.p50)} | ${us(bd.p95)} |`);
console.log(`| no response rules | ${us(b0.p50)} | ${us(b0.p95)} |`);
console.log(`| responseRedact + responseWarn set | ${us(b1.p50)} | ${us(b1.p95)} |`);

console.log('\n## 3. audit writer throughput (20000 records, sync append)');
for (const chain of [false, true]) {
  const log = new AuditLogger({ path: join(dir, `w-${chain}.jsonl`), logArgs: true, redactKeys: ['token'], maxArgsChars: 8192, maxSizeMB: 500, keepFiles: 2, chain });
  const s = process.hrtime.bigint();
  for (let i = 0; i < 20000; i++) log.log({ ts: new Date().toISOString(), reqId: String(i), tool: 't', server: 's', originalTool: 't', durationMs: 1, status: 'ok', args: { q: 'x' } });
  const ms = Number(process.hrtime.bigint() - s) / 1e6;
  console.log(`chain=${chain}: ${(20000 / (ms / 1000)).toFixed(0)} records/s`);
}

console.log('\n## 4. argument-rule evaluation (checkToolCall, microseconds per call, 50000 calls)');
const mkPolicy = (argMatch) => validateConfig({ servers: [{ name: 's', transport: 'stdio', command: 'true' }], auth: { disabled: true }, policy: { argMatch, argRules: { t: { deny: ['/etc/passwd', 'rm -rf', '169.254.169.254'] } } } }, 'bench').policy;
const argsSmall = { path: '/home/user/project/readme.md', mode: 'r' };
const argsLarge = { files: Array.from({ length: 200 }, (_, i) => ({ path: `/srv/data/${i}/file-${i}.txt`, note: 'x'.repeat(400) })) };
console.log('| mode | ~100 B args | ~100 KB args |\n|---|---|---|');
for (const [label, m] of [['exact (default)', {}], ['ignoreCase', { ignoreCase: true }], ['ignoreCase + normalizePaths', { ignoreCase: true, normalizePaths: true }]]) {
  const pol = mkPolicy(m);
  const run = (a, n) => { const st = process.hrtime.bigint(); for (let i = 0; i < n; i++) checkToolCall(pol, 't', a); return Number(process.hrtime.bigint() - st) / 1e3 / n; };
  console.log(`| ${label} | ${run(argsSmall, 50000).toFixed(1)} us | ${run(argsLarge, 500).toFixed(0)} us |`);
}

console.log('\n## 5. audit writer with credential-shape redaction (20000 records, 600-char string args)');
const note = 'customer asked about invoice 4471 and the refund policy for orders shipped last month; '.repeat(7);
for (const redactValues of [false, true]) {
  const log = new AuditLogger({ path: join(dir, `v-${redactValues}.jsonl`), logArgs: true, redactKeys: ['token'], maxArgsChars: 8192, maxSizeMB: 500, keepFiles: 2, chain: false, redactValues });
  const st = process.hrtime.bigint();
  for (let i = 0; i < 20000; i++) log.log({ ts: new Date().toISOString(), reqId: String(i), tool: 't', server: 's', originalTool: 't', durationMs: 1, status: 'ok', args: { note } });
  console.log(`redactValues=${redactValues}: ${(20000 / (Number(process.hrtime.bigint() - st) / 1e9)).toFixed(0)} records/s`);
}

rmSync(dir, { recursive: true, force: true });
process.exit(0);
