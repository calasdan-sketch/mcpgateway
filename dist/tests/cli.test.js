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
//# sourceMappingURL=cli.test.js.map