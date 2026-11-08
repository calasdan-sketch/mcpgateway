/** CLI arg parsing: --http flag and serve overrides. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyServeFlags, parseArgs } from '../src/cli.js';

test('--http sets the http flag', () => {
  const a = parseArgs(['serve', '--http', '-c', 'gw.yaml']);
  assert.equal(a.command, 'serve');
  assert.equal(a.http, true);
  assert.equal(a.config, 'gw.yaml');
});

test('--http defaults to false', () => {
  const a = parseArgs(['serve']);
  assert.equal(a.http, false);
});

test('applyServeFlags enables the HTTP upstream', () => {
  const cfg = { upstream: { http: { enabled: false } } };
  applyServeFlags(cfg, parseArgs(['serve', '--http']));
  assert.equal(cfg.upstream.http.enabled, true);
});

test('applyServeFlags leaves config alone without --http', () => {
  const cfg = { upstream: { http: { enabled: false } } };
  applyServeFlags(cfg, parseArgs(['serve']));
  assert.equal(cfg.upstream.http.enabled, false);
});

test('unknown flags are rejected', () => {
  assert.throws(() => parseArgs(['serve', '--bogus']), /unknown flag/);
});

test('init prints a fresh 64-hex key and does not write it to the file', async () => {
  const { execFileSync } = await import('node:child_process');
  const { mkdtempSync, readFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const { fileURLToPath } = await import('node:url');
  const out = join(mkdtempSync(join(tmpdir(), 'mcpgw-init-')), 'gw.yaml');
  const entry = fileURLToPath(new URL('../src/index.js', import.meta.url));
  const stdout = execFileSync(process.execPath, [entry, 'init', '-o', out], { encoding: 'utf8' });
  const m = /export GATEWAY_KEY=([0-9a-f]{64})\b/.exec(stdout);
  assert.ok(m, stdout);
  assert.ok(!readFileSync(out, 'utf8').includes(m[1] as string));
});

test('import: .mcp.json becomes a valid servers block with secrets swapped for ${VARS}', async () => {
  const { mcpJsonToServers } = await import('../src/cli.js');
  const { validateConfig } = await import('../src/config.js');
  const { parse, stringify } = await import('yaml');
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const { servers, notes } = mcpJsonToServers({
    mcpServers: {
      'My Server': { command: 'npx', args: ['-y', 'pkg'], env: { GITHUB_TOKEN: 'ghp_abc', LOG_LEVEL: 'debug' } },
      'my_server!': { command: 'node' },
      docs: { url: 'http://localhost:8080/mcp', headers: { Authorization: 'Bearer s3cret' } },
    },
  });
  const text = stringify({ servers });
  assert.ok(!text.includes('ghp_abc') && !text.includes('s3cret'), text);
  assert.ok(text.includes('GITHUB_TOKEN: ${GITHUB_TOKEN}'), text);
  assert.ok(text.includes('LOG_LEVEL: debug'), text);
  assert.deepEqual(servers.map((s) => s['name']), ['my-server', 'my_server-', 'docs']);
  assert.ok(notes.some((n) => n.includes('GITHUB_TOKEN')));
  const example = parse(readFileSync(fileURLToPath(new URL('../../mcpgateway.example.yaml', import.meta.url)), 'utf8')) as Record<string, unknown>;
  const cfg = validateConfig({ ...example, ...parse(text), auth: { disabled: true } }, 'test', { noNetwork: true });
  assert.deepEqual(cfg.servers.map((s) => s.transport), ['stdio', 'stdio', 'http']);
});

test('import: name collisions get a numeric suffix', async () => {
  const { mcpJsonToServers } = await import('../src/cli.js');
  const { servers } = mcpJsonToServers({ 'A b': { command: 'x' }, 'a-b': { command: 'y' } });
  assert.deepEqual(servers.map((s) => s['name']), ['a-b', 'a-b-2']);
});

test('import: invalid JSON exits 2', async () => {
  const { spawnSync } = await import('node:child_process');
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const { fileURLToPath } = await import('node:url');
  const bad = join(mkdtempSync(join(tmpdir(), 'mcpgw-imp-')), 'bad.json');
  writeFileSync(bad, '{not json');
  const r = spawnSync(process.execPath, [fileURLToPath(new URL('../src/index.js', import.meta.url)), 'import', bad], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /not valid JSON/);
});
