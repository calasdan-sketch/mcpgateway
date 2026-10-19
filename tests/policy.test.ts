import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkToolCall, checkResponse, isHidden } from '../src/policy.js';
import type { PolicyConfig } from '../src/config.js';

const basePolicy = (over: Partial<PolicyConfig> = {}): PolicyConfig => ({
  mode: 'enforce',
  allowTools: ['*'],
  denyTools: [],
  hideTools: [],
  argRules: {},
  responseRedact: [],
  responseBlock: [],
  responseWarn: [],
  scanWindowChars: 65536,
  ...over,
});

test('default policy allows everything', () => {
  const v = checkToolCall(basePolicy(), 'a__ping', {});
  assert.equal(v.decision, 'allow');
});

test('deny wins over allow', () => {
  const v = checkToolCall(basePolicy({ allowTools: ['*'], denyTools: ['a__*'] }), 'a__ping', {});
  assert.equal(v.decision, 'deny');
  assert.equal(v.reason, 'deny_list');
});

test('not on allow list is denied', () => {
  const v = checkToolCall(basePolicy({ allowTools: ['b__*'] }), 'a__ping', {});
  assert.equal(v.decision, 'deny');
  assert.equal(v.reason, 'not_allow_listed');
});

test('hidden tools are denied and reported hidden', () => {
  const p = basePolicy({ hideTools: ['secret__*'] });
  assert.equal(isHidden(p, 'secret__key'), true);
  assert.equal(isHidden(p, 'a__ping'), false);
  const v = checkToolCall(p, 'secret__key', {});
  assert.equal(v.decision, 'deny');
});

test('glob patterns: exact and prefix', () => {
  assert.equal(checkToolCall(basePolicy({ denyTools: ['exact'] }), 'exact', {}).decision, 'deny');
  assert.equal(checkToolCall(basePolicy({ denyTools: ['exact'] }), 'exactx', {}).decision, 'allow');
  assert.equal(checkToolCall(basePolicy({ denyTools: ['pre*'] }), 'prefix-tool', {}).decision, 'deny');
});

test('argRules deny on substring of JSON-encoded args', () => {
  const p = basePolicy({ argRules: { 'a__*': { deny: ['rm -rf'] } } });
  assert.equal(checkToolCall(p, 'a__run', { cmd: 'echo hi' }).decision, 'allow');
  const v = checkToolCall(p, 'a__run', { cmd: 'rm -rf /' });
  assert.equal(v.decision, 'deny');
  assert.equal(v.reason, 'arg_deny');
});

test('argRules allow list: miss is denied', () => {
  const p = basePolicy({ argRules: { 'a__run': { allow: ['ls'] } } });
  assert.equal(checkToolCall(p, 'a__run', { cmd: 'ls -la' }).decision, 'allow');
  assert.equal(checkToolCall(p, 'a__run', { cmd: 'cat /etc/passwd' }).reason, 'arg_allow_miss');
});

test('argRules: exact tool name beats glob', () => {
  const p = basePolicy({ argRules: { 'a__*': { deny: ['x'] }, 'a__run': { deny: ['y'] } } });
  assert.equal(checkToolCall(p, 'a__run', { c: 'x' }).decision, 'allow');
  assert.equal(checkToolCall(p, 'a__run', { c: 'y' }).decision, 'deny');
});

test('response redact rewrites secrets in string values (structured, JSON-safe)', () => {
  const r = checkResponse(basePolicy({ responseRedact: ['sk-secret'] }), { content: [{ type: 'text', text: 'key=sk-secret ok' }] });
  assert.equal(r.action, 'pass');
  assert.equal(r.redactions, 1);
  assert.deepEqual(r.result, { content: [{ type: 'text', text: 'key=[REDACTED] ok' }] });
});

test('response redact also scrubs secret-looking keys', () => {
  const r = checkResponse(basePolicy({ responseRedact: ['sk-secret'] }), { 'sk-secret': 'v' });
  assert.equal(r.redactions, 1);
  assert.deepEqual(r.result, { '[REDACTED]': 'v' });
});

test('response redact is JSON-safe even for patterns inside escape sequences', () => {
  // Old string-level approach: serialized '{"text":"a\\nb"}' + pattern 'n'
  // would replace the n inside the \n escape -> invalid JSON on re-parse.
  // Structured walk redacts the value, so serialization always round-trips.
  const r = checkResponse(basePolicy({ responseRedact: ['n'] }), { text: 'anb' });
  assert.equal(r.action, 'pass');
  assert.deepEqual(r.result, { text: 'a[REDACTED]b' });
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(r.result)));
});

test('response block wins over redact', () => {
  const r = checkResponse(basePolicy({ responseRedact: ['a'], responseBlock: ['blockme'] }), 'x blockme y');
  assert.equal(r.action, 'block');
  assert.equal(r.blockedBy, 'response_block');
});

test('response warn collects without blocking', () => {
  const r = checkResponse(basePolicy({ responseWarn: ['suspicious'] }), 'a suspicious result');
  assert.equal(r.action, 'pass');
  assert.equal(r.warnings.length, 1);
});

test('response scan is bounded by scanWindowChars', () => {
  const p = basePolicy({ responseBlock: ['needle'], scanWindowChars: 10 });
  const r = checkResponse(p, '0123456789 needle');
  assert.equal(r.action, 'pass'); // needle is outside the window
});
