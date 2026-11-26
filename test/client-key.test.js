// Run with: node --test test/*.test.js
const test = require('node:test');
const assert = require('node:assert');
const { clientKey } = require('../lib/client-key');

const req = (addr, headers = {}) => ({ socket: { remoteAddress: addr }, headers });

test('Serve request is keyed on the Tailscale login', () => {
  assert.strictEqual(
    clientKey(req('127.0.0.1', { 'tailscale-user-login': 'Alice@example.com', 'x-forwarded-for': '100.64.0.5' })),
    'ts:alice@example.com');
});

test('two tailnet users behind Serve get different keys', () => {
  assert.notStrictEqual(
    clientKey(req('127.0.0.1', { 'tailscale-user-login': 'a@x.com' })),
    clientKey(req('127.0.0.1', { 'tailscale-user-login': 'b@x.com' })));
});

test('loopback proxy without a login falls back to the first X-Forwarded-For hop', () => {
  assert.strictEqual(clientKey(req('::1', { 'x-forwarded-for': '100.64.0.7, 10.0.0.1' })), 'ip:100.64.0.7');
});

test('direct local request with no proxy headers uses the socket address', () => {
  assert.strictEqual(clientKey(req('127.0.0.1')), 'ip:127.0.0.1');
});

test('headers from a non-loopback peer are ignored', () => {
  assert.strictEqual(
    clientKey(req('203.0.113.9', { 'tailscale-user-login': 'victim@x.com', 'x-forwarded-for': '1.2.3.4' })),
    'ip:203.0.113.9');
});
