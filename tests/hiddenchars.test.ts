/** Invisible-character check on tool metadata. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ListToolsRequestSchema, type Tool } from '@modelcontextprotocol/sdk/types.js';
import { validateConfig, type Raw } from '../src/config.js';
import { startGateway } from '../src/gateway.js';
import { findHiddenChars, scanTool } from '../src/hiddenchars.js';

test('tag-block character in a description is reported with its code point', () => {
  const hits = scanTool({ name: 't', description: 'read file\u{E0041}\u{E0042}', inputSchema: { type: 'object' } } as Tool);
  assert.deepEqual(hits, [{ path: 'description', codePoints: ['U+E0041', 'U+E0042'] }]);
});

test('zero-width space inside a schema property description is found at its JSON path', () => {
  const hits = scanTool({ name: 't', inputSchema: { type: 'object', properties: { q: { type: 'string', description: 'query\u200B' } } } } as Tool);
  assert.deepEqual(hits, [{ path: 'inputSchema.properties.q.description', codePoints: ['U+200B'] }]);
});

test('plain and accented text is not flagged', () => {
  assert.deepEqual(findHiddenChars('plain ASCII text'), []);
  assert.deepEqual(findHiddenChars('Café crème, über straße'), []);
  for (const c of ['\u202E', '\u2066', '\u2060', '\uFEFF', '\u200F']) assert.equal(findHiddenChars(`a${c}b`).length, 1);
});

async function run(policy: Record<string, unknown>) {
  const tools: Tool[] = [
    { name: 'clean', description: 'ok', inputSchema: { type: 'object' } },
    { name: 'sneaky', description: 'ok\u{E0049}', inputSchema: { type: 'object' } },
  ];
  const fake = new Server({ name: 'f', version: '1' }, { capabilities: { tools: {} } });
  fake.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await fake.connect(st);
  const auditPath = join(mkdtempSync(join(tmpdir(), 'mcpgw-hid-')), 'audit.jsonl');
  const cfg = validateConfig({
    servers: [{ name: 'srv', transport: 'stdio', command: 'node' }],
    auth: { disabled: true }, audit: { path: auditPath }, admin: { enabled: false }, policy,
  } as Raw, 'test');
  const gw = await startGateway(cfg, { transportOverrides: new Map([['srv', ct]]), noAdmin: true, log: () => undefined });
  const up = InMemoryTransport.createLinkedPair();
  await gw.upstream.createMcpServer().connect(up[1]);
  const client = new Client({ name: 'c', version: '1' }, { capabilities: {} });
  await client.connect(up[0]);
  const names = (await client.listTools()).tools.map((t) => t.name).sort();
  const recs = readFileSync(auditPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
  const metrics = gw.metrics.render();
  await client.close().catch(() => undefined);
  await gw.close();
  await fake.close().catch(() => undefined);
  return { names, recs, metrics };
}

test('flagged tools are audited and still listed by default', async () => {
  const r = await run({});
  assert.deepEqual(r.names, ['clean', 'sneaky']);
  const ev = r.recs.filter((x) => x['status'] === 'hidden_chars');
  assert.equal(ev.length, 1);
  assert.equal(ev[0]?.['tool'], 'sneaky');
  assert.ok(r.metrics.includes('mcpgateway_hidden_chars_tools 1'));
});

test('policy.hideSuspicious removes flagged tools', async () => {
  const r = await run({ hideSuspicious: true });
  assert.deepEqual(r.names, ['clean']);
});
