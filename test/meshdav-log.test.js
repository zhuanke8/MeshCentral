'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeHeaders, sanitizeUrl } = require('../meshdav-route.js');

// --- sanitizeHeaders ---

test('sanitizeHeaders: 白名单头保留原值', () => {
  const h = {
    'host': 'a.com', 'content-type': 'text/plain', 'content-length': '3',
    'user-agent': 'ua', 'upgrade': 'h2', 'connection': 'keep-alive',
    'depth': '1', 'range': 'bytes=0-1', 'accept': '*/*', 'accept-encoding': 'gzip'
  };
  const s = sanitizeHeaders(h);
  assert.strictEqual(s['host'], 'a.com');
  assert.strictEqual(s['content-type'], 'text/plain');
  assert.strictEqual(s['content-length'], '3');
  assert.strictEqual(s['user-agent'], 'ua');
  assert.strictEqual(s['upgrade'], 'h2');
  assert.strictEqual(s['connection'], 'keep-alive');
  assert.strictEqual(s['depth'], '1');
  assert.strictEqual(s['range'], 'bytes=0-1');
  assert.strictEqual(s['accept'], '*/*');
  assert.strictEqual(s['accept-encoding'], 'gzip');
});

test('sanitizeHeaders: authorization/cookie/proxy-authorization 不输出', () => {
  const h = {
    'authorization': 'Basic dXNlcjpwYXNz',
    'cookie': 'session=abc',
    'proxy-authorization': 'Basic xyz',
    'host': 'a.com'
  };
  const s = sanitizeHeaders(h);
  assert.strictEqual(s['authorization'], undefined);
  assert.strictEqual(s['cookie'], undefined);
  assert.strictEqual(s['proxy-authorization'], undefined);
  assert.strictEqual(s['host'], 'a.com');
});

test('sanitizeHeaders: 未知秘密头与 referer 不输出', () => {
  const h = {
    'x-secret-token': 'topsecret',
    'x-custom-auth': 'bearer abc',
    'x-api-key': 'key123',
    'x-access-token': 'tok',
    'referer': 'https://evil.com/leak'
  };
  const s = sanitizeHeaders(h);
  assert.strictEqual(s['x-secret-token'], undefined);
  assert.strictEqual(s['x-custom-auth'], undefined);
  assert.strictEqual(s['x-api-key'], undefined);
  assert.strictEqual(s['x-access-token'], undefined);
  assert.strictEqual(s['referer'], undefined);
});

test('sanitizeHeaders: 不修改传入原对象', () => {
  const h = { 'authorization': 'Basic dXNlcjpwYXNz', 'host': 'a.com', 'x-secret': 's' };
  const orig = JSON.stringify(h);
  sanitizeHeaders(h);
  assert.strictEqual(JSON.stringify(h), orig);
});

test('sanitizeHeaders: 大小写不敏感白名单匹配', () => {
  const h = { 'Host': 'a.com', 'Content-Type': 'text/plain', 'DEPTH': '1' };
  const s = sanitizeHeaders(h);
  assert.strictEqual(s['Host'], 'a.com');
  assert.strictEqual(s['Content-Type'], 'text/plain');
  assert.strictEqual(s['DEPTH'], '1');
});

test('sanitizeHeaders: 非对象原样返回', () => {
  assert.strictEqual(sanitizeHeaders(null), null);
  assert.strictEqual(sanitizeHeaders(undefined), undefined);
  assert.strictEqual(sanitizeHeaders('str'), 'str');
  assert.strictEqual(sanitizeHeaders(42), 42);
});

// --- sanitizeUrl ---

test('sanitizeUrl: DAV 路径去 query', () => {
  assert.strictEqual(sanitizeUrl('/dav/node1/file.txt?token=secret'), '/dav/node1/file.txt');
});

test('sanitizeUrl: DAV 路径去 fragment', () => {
  assert.strictEqual(sanitizeUrl('/dav/node1/file.txt#section'), '/dav/node1/file.txt');
});

test('sanitizeUrl: 非 DAV 路径也去 query 和 fragment', () => {
  assert.strictEqual(sanitizeUrl('/any/path?foo=bar'), '/any/path');
  assert.strictEqual(sanitizeUrl('/any/path#frag'), '/any/path');
  assert.strictEqual(sanitizeUrl('/any/path?a=1#frag'), '/any/path');
});

test('sanitizeUrl: query 和 fragment 同时存在取较早者截断', () => {
  assert.strictEqual(sanitizeUrl('/p?a=1#frag'), '/p');
  assert.strictEqual(sanitizeUrl('/p#frag?query'), '/p');
});

test('sanitizeUrl: 无 query/fragment 原样返回', () => {
  assert.strictEqual(sanitizeUrl('/dav/node1/file.txt'), '/dav/node1/file.txt');
  assert.strictEqual(sanitizeUrl('https://host/dav/x'), 'https://host/dav/x');
});

test('sanitizeUrl: 非字符串原样返回', () => {
  assert.strictEqual(sanitizeUrl(123), 123);
  assert.strictEqual(sanitizeUrl(null), null);
  assert.strictEqual(sanitizeUrl(undefined), undefined);
});
