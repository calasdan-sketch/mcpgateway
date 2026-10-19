import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildNamespace, resolveNames, NamespaceError } from '../src/namespace.js';
const baseNs = (over = {}) => ({
    strategy: 'prefix',
    separator: '__',
    priority: [],
    mappings: {},
    aliases: {},
    ...over,
});
const cat = (server, ...tools) => ({
    server,
    tools: tools.map((name) => ({ name })),
});
test('no collision: tools keep bare names', () => {
    const ns = buildNamespace([cat('a', 'ping'), cat('b', 'pong')], baseNs());
    assert.deepEqual([...ns.byPublicName.keys()].sort(), ['ping', 'pong']);
    assert.equal(ns.collisions.length, 0);
});
test('prefix strategy: colliding tools get server prefixes', () => {
    const ns = buildNamespace([cat('a', 'compare', 'solo'), cat('b', 'compare')], baseNs());
    assert.deepEqual([...ns.byPublicName.keys()].sort(), ['a__compare', 'b__compare', 'solo']);
    assert.equal(ns.collisions.length, 1);
    assert.equal(ns.collisions[0]?.originalName, 'compare');
    assert.deepEqual(ns.collisions[0]?.resolvedAs, ['a__compare', 'b__compare']);
    assert.equal(ns.byPublicName.get('a__compare')?.originalName, 'compare');
    assert.equal(ns.byPublicName.get('a__compare')?.server, 'a');
    assert.equal(ns.byPublicName.get('solo')?.server, 'a');
});
test('priority strategy: winner keeps bare name, losers prefixed + warned', () => {
    const ns = buildNamespace([cat('a', 'compare'), cat('b', 'compare')], baseNs({ strategy: 'priority', priority: ['b', 'a'] }));
    assert.ok(ns.byPublicName.has('compare'));
    assert.ok(ns.byPublicName.has('a__compare'));
    assert.equal(ns.byPublicName.get('compare')?.server, 'b');
    assert.deepEqual(ns.collisions[0]?.shadowed, ['a']);
    assert.equal(ns.collisions[0]?.winner, 'b');
    assert.ok(ns.warnings.some((w) => w.includes('shadowed')));
});
test('priority strategy: unlisted servers lose to listed ones, config order otherwise', () => {
    const ns = buildNamespace([cat('b', 'x'), cat('a', 'x'), cat('c', 'x')], baseNs({ strategy: 'priority', priority: ['c'] }));
    assert.equal(ns.byPublicName.get('x')?.server, 'c');
});
test('explicit strategy: mapping picks the winner', () => {
    const ns = buildNamespace([cat('a', 'compare'), cat('b', 'compare')], baseNs({ strategy: 'explicit', mappings: { compare: 'b' } }));
    assert.equal(ns.byPublicName.get('compare')?.server, 'b');
    assert.ok(ns.byPublicName.has('a__compare'));
});
test('explicit strategy without mapping: hard error (fail-closed)', () => {
    assert.throws(() => buildNamespace([cat('a', 'compare'), cat('b', 'compare')], baseNs({ strategy: 'explicit' })), (e) => e instanceof NamespaceError && /no namespace\.mappings entry/.test(e.message));
});
test('explicit strategy with mapping to non-colliding server: hard error', () => {
    assert.throws(() => buildNamespace([cat('a', 'compare'), cat('b', 'compare')], baseNs({ strategy: 'explicit', mappings: { compare: 'zzz' } })), NamespaceError);
});
test('aliases override the strategy assignment', () => {
    const ns = buildNamespace([cat('a', 'compare'), cat('b', 'compare')], baseNs({ aliases: { 'a:compare': 'duel' } }));
    assert.ok(ns.byPublicName.has('duel'));
    assert.ok(ns.byPublicName.has('b__compare'));
    assert.ok(!ns.byPublicName.has('a__compare'));
    assert.equal(ns.byPublicName.get('duel')?.originalName, 'compare');
});
test('alias to unknown tool: hard error', () => {
    assert.throws(() => buildNamespace([cat('a', 'ping')], baseNs({ aliases: { 'a:nope': 'x' } })), NamespaceError);
});
test('public name over 64 chars: hard error with alias hint', () => {
    const long = 't'.repeat(60);
    assert.throws(() => buildNamespace([cat('averylongservername', long), cat('b', long)], baseNs()), (e) => e instanceof NamespaceError && /alias/.test(e.message));
});
test('natural-name collision with a prefixed name: hard error', () => {
    // "x" collides on a+b -> prefixed "a__x","b__x"; server c has a tool
    // literally named "a__x" -> public-name collision, hard error.
    assert.throws(() => buildNamespace([cat('a', 'x'), cat('b', 'x'), cat('c', 'a__x')], baseNs()), NamespaceError);
});
test('illegal tool names are skipped with a warning', () => {
    const ns = buildNamespace([{ server: 'a', tools: [{ name: 'ok' }, { name: 'not a name!' }] }], baseNs());
    assert.ok(ns.byPublicName.has('ok'));
    assert.ok(!ns.byPublicName.has('not a name!'));
    assert.ok(ns.warnings.some((w) => w.includes('illegal')));
});
test('custom separator is honored', () => {
    const ns = buildNamespace([cat('a', 'x'), cat('b', 'x')], baseNs({ separator: '_' }));
    assert.ok(ns.byPublicName.has('a_x'));
    assert.ok(ns.byPublicName.has('b_x'));
});
test('resolveNames works generically (prompts)', () => {
    const r = resolveNames([
        { server: 'a', names: ['summarize'] },
        { server: 'b', names: ['summarize', 'plan'] },
    ], baseNs());
    assert.equal(r.assigned.get('a\0summarize'), 'a__summarize');
    assert.equal(r.assigned.get('b\0summarize'), 'b__summarize');
    assert.equal(r.assigned.get('b\0plan'), 'plan');
});
test('three-way collision prefixes all three', () => {
    const ns = buildNamespace([cat('a', 'x'), cat('b', 'x'), cat('c', 'x')], baseNs());
    assert.deepEqual([...ns.byPublicName.keys()].sort(), ['a__x', 'b__x', 'c__x']);
});
//# sourceMappingURL=namespace.test.js.map