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
