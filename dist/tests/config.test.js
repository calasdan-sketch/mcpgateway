import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { validateConfig, configWarnings, loadConfigFile, interpolateEnv, ConfigError } from '../src/config.js';
const base = (over = {}) => ({
    servers: [{ name: 'a', transport: 'stdio', command: 'true' }],
    auth: { disabled: true },
    ...over,
});
test('minimal config loads with sane defaults', () => {
    const cfg = validateConfig(base(), 'test');
    assert.equal(cfg.namespace.strategy, 'prefix');
    assert.equal(cfg.namespace.separator, '__');
    assert.deepEqual(cfg.defaultRateLimit, { rps: 10, burst: 20 });
    assert.equal(cfg.policy.mode, 'enforce');
    assert.equal(cfg.admin.host, '127.0.0.1');
    assert.equal(cfg.upstream.stdio.enabled, true);
    assert.equal(cfg.globalMaxInflight, 256);
    assert.equal(cfg.servers[0]?.concurrency, 1); // stdio default
    assert.equal(cfg.servers[0]?.timeoutMs, 60000);
});
test('http server defaults to higher concurrency', () => {
    const cfg = validateConfig(base({ servers: [{ name: 'h', transport: 'http', url: 'http://localhost:8080/mcp' }] }), 'test');
    assert.equal(cfg.servers[0]?.concurrency, 8);
});
test('${VAR} interpolation and ${VAR:-default}', () => {
    process.env['MCPGW_TEST_VAR'] = 'hello';
    delete process.env['MCPGW_UNSET_VAR'];
    assert.equal(interpolateEnv('${MCPGW_TEST_VAR}', 'test'), 'hello');
    assert.equal(interpolateEnv('pre-${MCPGW_TEST_VAR}-post', 'test'), 'pre-hello-post');
    assert.equal(interpolateEnv('${MCPGW_UNSET_VAR:-fallback}', 'test'), 'fallback');
    delete process.env['MCPGW_TEST_VAR'];
});
test('loadConfigFile interpolates env before validating', () => {
    process.env['MCPGW_TEST_TOKEN'] = 'tok-123';
    const dir = mkdtempSync(join(tmpdir(), 'mcpgw-cfg-'));
    const path = join(dir, 'gw.yaml');
    writeFileSync(path, 'servers:\n  - name: a\n    transport: stdio\n    command: "true"\n    env:\n      T: "${MCPGW_TEST_TOKEN}"\nauth:\n  disabled: true\n', 'utf8');
    const cfg = loadConfigFile(path);
    assert.equal(cfg.servers[0]?.env?.['T'], 'tok-123');
    delete process.env['MCPGW_TEST_TOKEN'];
});
test('unset variable without default names the variable', () => {
    delete process.env['MCPGW_DEFINITELY_UNSET'];
    assert.throws(() => validateConfig(base({ servers: [{ name: 'a', transport: 'stdio', command: '${MCPGW_DEFINITELY_UNSET}' }] }), 'test'), (e) => e instanceof ConfigError && /MCPGW_DEFINITELY_UNSET/.test(e.message));
});
test('duplicate server names rejected', () => {
    assert.throws(() => validateConfig(base({ servers: [{ name: 'a', transport: 'stdio', command: 'true' }, { name: 'a', transport: 'stdio', command: 'true' }] }), 'test'), (e) => e instanceof ConfigError && /duplicate server name/.test(e.message));
});
test('server names must be lowercase slug', () => {
    assert.throws(() => validateConfig(base({ servers: [{ name: 'Bad Name', transport: 'stdio', command: 'true' }] }), 'test'), ConfigError);
});
test('bad namespace strategy rejected', () => {
    assert.throws(() => validateConfig(base({ namespace: { strategy: 'magic' } }), 'test'), ConfigError);
});
test('explicit mapping to unknown server rejected', () => {
    assert.throws(() => validateConfig(base({ namespace: { strategy: 'explicit', mappings: { x: 'nope' } } }), 'test'), (e) => e instanceof ConfigError && /unknown server/.test(e.message));
});
test('admin public bind without flag is refused', () => {
    assert.throws(() => validateConfig(base({ admin: { host: '0.0.0.0' } }), 'test'), (e) => e instanceof ConfigError && /allowPublicAdmin/.test(e.message));
    const ok = validateConfig(base({ admin: { host: '0.0.0.0', allowPublicAdmin: true } }), 'test');
    assert.equal(ok.admin.allowPublicAdmin, true);
});
test('auth: empty keys without disabled is an error; short keys rejected', () => {
    assert.throws(() => validateConfig(base({ auth: {} }), 'test'), ConfigError);
    assert.throws(() => validateConfig(base({ auth: { keys: [{ id: 'k', key: 'short', scopes: ['tools:call'] }] } }), 'test'), (e) => e instanceof ConfigError && /shorter than 16/.test(e.message));
});
test('auth: unknown scope rejected', () => {
    assert.throws(() => validateConfig(base({ auth: { keys: [{ id: 'k', key: 'a'.repeat(32), scopes: ['nope'] }] } }), 'test'), (e) => e instanceof ConfigError && /unknown scope/.test(e.message));
});
test('no upstream enabled is an error', () => {
    assert.throws(() => validateConfig(base({ upstream: { stdio: { enabled: false }, http: { enabled: false } } }), 'test'), (e) => e instanceof ConfigError && /at least one upstream/.test(e.message));
});
test('cleartext http to non-localhost warns (does not fail)', () => {
    const cfg = validateConfig(base({ servers: [{ name: 'h', transport: 'http', url: 'http://example.com/mcp' }] }), 'test');
    assert.ok(configWarnings(cfg).some((w) => w.includes('cleartext')));
});
test('unknown top-level keys warn (do not fail)', () => {
    const cfg = validateConfig(base({ frobnicate: true }), 'test');
    assert.ok(configWarnings(cfg).some((w) => w.includes('frobnicate')));
});
test('invalid rate limit rejected', () => {
    assert.throws(() => validateConfig(base({ rateLimits: { default: { rps: -1, burst: 0 } } }), 'test'), ConfigError);
});
test('bad transport rejected', () => {
    assert.throws(() => validateConfig(base({ servers: [{ name: 'a', transport: 'grpc' }] }), 'test'), (e) => e instanceof ConfigError && /stdio.*http/.test(e.message));
});
test('global limits have safe defaults', () => {
    const cfg = validateConfig(base(), 'test');
    assert.equal(cfg.globalMaxInflight, 256);
    assert.equal(cfg.maxResultChars, 10_000_000);
    assert.equal(cfg.upstream.http.maxSessions, 128);
});
//# sourceMappingURL=config.test.js.map