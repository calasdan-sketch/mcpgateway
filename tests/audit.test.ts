import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AuditLogger, collectSecretValues, redactDeep, redactSecretValues } from '../src/audit.js';
import type { AuditConfig } from '../src/config.js';

const baseAudit = (over: Partial<AuditConfig> = {}): AuditConfig => ({
  path: join(mkdtempSync(join(tmpdir(), 'mcpgw-audit-')), 'audit.jsonl'),
  logArgs: true,
  redactKeys: ['token', 'secret', 'password'],
  maxArgsChars: 8192,
  maxSizeMB: 100,
  keepFiles: 5,
  ...over,
});

const baseRecord = () => ({
  ts: new Date().toISOString(),
  reqId: 'r1',
  tool: 'a__ping',
  server: 'a',
  originalTool: 'ping',
  durationMs: 3,
  status: 'ok' as const,
});

function readLines(path: string): unknown[] {
  return readFileSync(path, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
}

test('writes one JSON object per line', () => {
  const cfg = baseAudit();
  const log = new AuditLogger(cfg);
  log.log({ ...baseRecord(), args: { x: 1 } });
  const lines = readLines(cfg.path);
  assert.equal(lines.length, 1);
  assert.equal((lines[0] as { tool: string }).tool, 'a__ping');
});

test('newlines inside args cannot break JSONL framing (log injection)', () => {
  const cfg = baseAudit();
  const log = new AuditLogger(cfg);
  log.log({ ...baseRecord(), args: { evil: 'line1\nline2\r\nline3' } });
  log.log({ ...baseRecord(), reqId: 'r2' });
  const raw = readFileSync(cfg.path, 'utf8').trim().split('\n');
  assert.equal(raw.length, 2); // still exactly 2 records
  assert.equal((JSON.parse(raw[1] as string) as { reqId: string }).reqId, 'r2');
});

test('redacts secret-looking keys recursively, case-insensitive', () => {
  const out = redactDeep(
    { apiToken: 'abc', nested: { PASSWORD: 'x', list: [{ Secret: 'y' }] }, safe: 'keep' },
    ['token', 'secret', 'password'],
  ) as Record<string, unknown>;
  assert.equal(out['apiToken'], '[REDACTED]');
  assert.equal((out['nested'] as Record<string, unknown>)['PASSWORD'], '[REDACTED]');
  assert.equal((out['safe']), 'keep');
  const list = (out['nested'] as Record<string, unknown>)['list'] as Array<Record<string, unknown>>;
  assert.equal(list[0]?.['Secret'], '[REDACTED]');
});

test('redaction is applied to logged args', () => {
  const cfg = baseAudit();
  const log = new AuditLogger(cfg);
  log.log({ ...baseRecord(), args: { github_token: 'ghp_real', q: 'x' } });
  const raw = readFileSync(cfg.path, 'utf8');
  assert.ok(!raw.includes('ghp_real'));
  assert.ok(raw.includes('[REDACTED]'));
});

test('long args are truncated with a visible marker', () => {
  const cfg = baseAudit({ maxArgsChars: 50 });
  const log = new AuditLogger(cfg);
  log.log({ ...baseRecord(), args: { blob: 'x'.repeat(500) } });
  const [rec] = readLines(cfg.path) as Array<{ args: string; argsTruncated?: boolean }>;
  assert.ok(rec);
  assert.equal(rec.argsTruncated, true);
  assert.ok(rec.args.includes('[truncated]'));
});

test('logArgs=false stores only an args hash', () => {
  const cfg = baseAudit({ logArgs: false });
  const log = new AuditLogger(cfg);
  log.log({ ...baseRecord(), args: { secret: 'shh' } });
  const [rec] = readLines(cfg.path) as Array<{ args?: unknown; argsHash?: string }>;
  assert.ok(rec);
  assert.equal(rec.args, undefined);
  assert.ok(rec.argsHash?.startsWith('sha256:'));
  assert.ok(!readFileSync(cfg.path, 'utf8').includes('shh'));
});

test('rotation bounds disk usage', () => {
  const cfg = baseAudit({ maxSizeMB: 0.0002, keepFiles: 2 }); // ~200 bytes
  const log = new AuditLogger(cfg);
  for (let i = 0; i < 30; i++) log.log({ ...baseRecord(), reqId: `r${i}`, args: { pad: 'x'.repeat(100) } });
  assert.ok(existsSync(`${cfg.path}.1`));
  assert.ok(!existsSync(`${cfg.path}.3`), 'must not keep more than keepFiles');
});

test('unwritable path never throws; errors are counted', () => {
  const log = new AuditLogger(baseAudit({ path: '/nonexistent-dir-xyz/audit.jsonl' }));
  assert.doesNotThrow(() => log.log(baseRecord()));
  assert.ok(log.errors > 0);
});

test('collectSecretValues picks values of secret-named keys (>= 8 chars)', () => {
  const vals = collectSecretValues({ api_token: 'ghp_abcdef123', q: 'short', nested: { password: 's3cr3t!!' } }, ['token', 'password']);
  assert.deepEqual(vals.sort(), ['ghp_abcdef123', 's3cr3t!!']);
  assert.deepEqual(collectSecretValues({ token: 'abc' }, ['token']), []); // too short: never redact common words
});

test('redactSecretValues replaces every occurrence', () => {
  assert.equal(redactSecretValues('a ghp_1 b ghp_1', ['ghp_1']), 'a [REDACTED] b [REDACTED]');
});
