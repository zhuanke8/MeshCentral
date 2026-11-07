'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const expressWs = require('express-ws');
const WebSocket = require('ws');
const { createDavDispatcher, createDavDomainResolver } = require('../meshdav-route.js');

// --- 测试夹具 ---

const DEFAULT_HOST = 'server.example.test';
const DNS_HOST = 'dav.example.test';

const domains = {
  '': { id: '', url: '/', dns: null },
  'site2': { id: 'site2', url: '/site2/', dns: null },
  'dnsdom': { id: 'dnsdom', url: '/', dns: DNS_HOST }
};

const dnsDomains = {};
dnsDomains[DNS_HOST] = domains['dnsdom'];

function isLoopback(addr) {
  if (typeof addr != 'string') return false;
  if (addr.indexOf('::ffff:') == 0) addr = addr.substring(7);
  return addr == '127.0.0.1' || addr == '::1' || addr == 'localhost' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(addr);
}

function mockInstance(id) {
  return {
    handleRequest: function (req, res) { res.status(200).send(id); },
    handleAgentTunnel: function (ws) { try { ws.send(JSON.stringify({ domain: id })); } catch (e) { } try { ws.close(); } catch (e) { } }
  };
}

const instances = {
  '': { instance: mockInstance(''), url: '/' },
  'site2': { instance: mockInstance('site2'), url: '/site2/' },
  'dnsdom': { instance: mockInstance('dnsdom'), url: '/' }
};

const resolveDomain = createDavDomainResolver({
  domains: domains,
  dnsDomains: dnsDomains,
  defaultHost: DEFAULT_HOST,
  isLoopback: isLoopback
});

const dispatcher = createDavDispatcher({
  resolveDomain: resolveDomain,
  lookup: function (id) { return instances[id] || null; }
});

function createApp(extraMiddleware) {
  const app = express();
  app.use(function (req, res, next) { req.clientIp = req.socket.remoteAddress; next(); });
  if (extraMiddleware) app.use(extraMiddleware);
  const mounted = {};
  for (const id in instances) {
    const u = instances[id].url;
    if (mounted[u]) continue;
    mounted[u] = true;
    app.use(u + 'dav/', dispatcher.handleRequest);
  }
  return app;
}

function listen(app) {
  return new Promise(function (resolve) {
    const server = app.listen(0, '127.0.0.1', function () { resolve(server); });
  });
}

function request(server, path, headers) {
  return new Promise(function (resolve, reject) {
    const addr = server.address();
    const req = http.request({
      host: addr.address, port: addr.port, path: path, method: 'GET',
      headers: headers || {}
    }, function (res) {
      let body = '';
      res.on('data', function (d) { body += d; });
      res.on('end', function () { resolve({ status: res.statusCode, body: body }); });
    });
    req.on('error', reject);
    req.end();
  });
}

// --- 真实 Express 回环测试 ---

test('默认域: /dav/ + 默认Host -> 200 默认域', async () => {
  const server = await listen(createApp());
  try {
    const r = await request(server, '/dav/file.txt', { host: DEFAULT_HOST });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, '');
  } finally { server.close(); }
});

test('路径域: /site2/dav/ + 默认Host -> 200 site2', async () => {
  const server = await listen(createApp());
  try {
    const r = await request(server, '/site2/dav/file.txt', { host: DEFAULT_HOST });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, 'site2');
  } finally { server.close(); }
});

test('DNS域(无证书): /dav/ + DNS Host -> 200 dnsdom', async () => {
  const server = await listen(createApp());
  try {
    const r = await request(server, '/dav/file.txt', { host: DNS_HOST });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, 'dnsdom');
  } finally { server.close(); }
});

test('未知Host: /dav/ + 未知Host -> 404', async () => {
  const server = await listen(createApp());
  try {
    const r = await request(server, '/dav/file.txt', { host: 'evil.example.test' });
    assert.strictEqual(r.status, 404);
  } finally { server.close(); }
});

test('跨域前缀: /site2/dav/ + DNS Host -> 404 (DNS不走路径前缀)', async () => {
  const server = await listen(createApp());
  try {
    const r = await request(server, '/site2/dav/file.txt', { host: DNS_HOST });
    assert.strictEqual(r.status, 404);
  } finally { server.close(); }
});

test('无效localhost domainid: 未知domainid -> 404', async () => {
  const server = await listen(createApp());
  try {
    const r = await request(server, '/dav/file.txt?domainid=nope', { host: 'localhost' });
    assert.strictEqual(r.status, 404);
  } finally { server.close(); }
});

test('有效localhost 无domainid: /dav/ -> 200 默认域', async () => {
  const server = await listen(createApp());
  try {
    const r = await request(server, '/dav/file.txt', { host: 'localhost' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, '');
  } finally { server.close(); }
});

test('有效localhost 路径域: /site2/dav/ -> 200 site2', async () => {
  const server = await listen(createApp());
  try {
    const r = await request(server, '/site2/dav/file.txt', { host: 'localhost' });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, 'site2');
  } finally { server.close(); }
});

test('远程domainid不覆盖: 默认Host + ?domainid=site2 仍走路径解析', async () => {
  const server = await listen(createApp());
  try {
    const r = await request(server, '/dav/file.txt?domainid=site2', { host: DEFAULT_HOST });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, '');
  } finally { server.close(); }
});

test('xdomain校验: 错误xdomain不导致跨域', async () => {
  const server = await listen(createApp(function (req, res, next) { req.xdomain = domains['site2']; next(); }));
  try {
    const r = await request(server, '/dav/file.txt', { host: DEFAULT_HOST });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, '');
  } finally { server.close(); }
});

// --- 直接测试 resolver 边界 ---

test('resolver: 非字符串domainid直接拒绝', () => {
  assert.strictEqual(resolveDomain({
    hostname: 'localhost', clientIp: '127.0.0.1',
    connection: { remoteAddress: '127.0.0.1' },
    query: { domainid: 12345 }, originalUrl: '/dav/file.txt'
  }), null);
});

test('resolver: 远程非回环localhost请求拒绝', () => {
  assert.strictEqual(resolveDomain({
    hostname: 'localhost', clientIp: '10.0.0.5',
    connection: { remoteAddress: '10.0.0.5' },
    query: { domainid: 'site2' }, originalUrl: '/dav/file.txt'
  }), null);
});

test('resolver: 未知Host返回null', () => {
  assert.strictEqual(resolveDomain({ hostname: 'unknown.test', originalUrl: '/dav/file.txt' }), null);
});

// --- helper 审查补充测试 ---

test('生产cached xdomain + localhost未知domainid -> 404 (不绕过)', async () => {
  // 模拟生产：getDomain 已将 req.xdomain 填成默认域
  const server = await listen(createApp(function (req, res, next) { req.xdomain = domains['']; next(); }));
  try {
    const r = await request(server, '/dav/file.txt?domainid=nope', { host: 'localhost' });
    assert.strictEqual(r.status, 404);
  } finally { server.close(); }
});

test('生产cached xdomain + localhost非字符串domainid -> 404', async () => {
  const server = await listen(createApp(function (req, res, next) { req.xdomain = domains['']; next(); }));
  try {
    // Express 查询解析会将 domainid=123 解析为字符串 "123"，用 resolver 直测非字符串
    assert.strictEqual(resolveDomain({
      hostname: 'localhost', clientIp: '127.0.0.1',
      connection: { remoteAddress: '127.0.0.1' },
      xdomain: domains[''],
      query: { domainid: 12345 }, originalUrl: '/dav/file.txt'
    }), null);
  } finally { server.close(); }
});

test('valid team内部根WS: localhost + domainid=site2 + /davtunnel.ashx -> site2', () => {
  const d = resolveDomain({
    hostname: 'localhost', clientIp: '127.0.0.1',
    connection: { remoteAddress: '127.0.0.1' },
    query: { domainid: 'site2' }, originalUrl: '/davtunnel.ashx'
  });
  assert.strictEqual(d, domains['site2']);
});

test('valid team内部根WS via dispatcher.handleAgentTunnel', () => {
  let handled = null;
  const ws = { send: function () { }, close: function () { } };
  const inst2 = { instance: { handleAgentTunnel: function (ws, req) { handled = 'site2'; } }, url: '/site2/' };
  const disp = createDavDispatcher({
    resolveDomain: resolveDomain,
    lookup: function (id) { return (id === 'site2') ? inst2 : null; }
  });
  disp.handleAgentTunnel(ws, {
    hostname: 'localhost', clientIp: '127.0.0.1',
    connection: { remoteAddress: '127.0.0.1' },
    query: { domainid: 'site2' }, originalUrl: '/davtunnel.ashx'
  });
  assert.strictEqual(handled, 'site2');
});

test('DNS旧xdomain错误但按config DNS选中 -> 200 dnsdom', async () => {
  // 模拟生产：getDomain 无 DNS 映射，将 xdomain 填成默认域
  const server = await listen(createApp(function (req, res, next) { req.xdomain = domains['']; next(); }));
  try {
    const r = await request(server, '/dav/file.txt', { host: DNS_HOST });
    assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body, 'dnsdom');
  } finally { server.close(); }
});

test('DNS /site2/dav 拒绝 (DNS不走路径前缀)', async () => {
  const server = await listen(createApp());
  try {
    const r = await request(server, '/site2/dav/file.txt', { host: DNS_HOST });
    assert.strictEqual(r.status, 404);
  } finally { server.close(); }
});

test('精确路径匹配: /dave/ 不匹配为DAV', () => {
  assert.strictEqual(resolveDomain({
    hostname: DEFAULT_HOST, originalUrl: '/dave/file.txt'
  }), null);
});

test('IPv6 [::1]:8080 解析正确不空串', () => {
  // ::1 不是 localhost/默认Host/DNS -> null，但 reqHost 不应返回空串误配
  assert.strictEqual(resolveDomain({
    headers: { host: '[::1]:8080' }, originalUrl: '/dav/file.txt'
  }), null);
  // 确认不误配为默认域（空串 !== defaultHost）
  assert.strictEqual(resolveDomain({
    headers: { host: '[::1]' }, originalUrl: '/dav/file.txt'
  }), null);
});

// --- 真实 express-ws upgrade 测试 ---

function createWsApp(extraMiddleware) {
  const app = express();
  expressWs(app);
  app.use(function (req, res, next) {
    if (req.originalUrl == null) { req.originalUrl = req.url; }
    if (req.query == null) { req.query = require('url').parse(req.url, true).query || {}; }
    req.clientIp = req.socket.remoteAddress;
    next();
  });
  if (extraMiddleware) app.use(extraMiddleware);
  const mounted = {};
  for (const id in instances) {
    const u = instances[id].url;
    if (mounted[u]) continue;
    mounted[u] = true;
    app.ws(u + 'davtunnel.ashx', dispatcher.handleAgentTunnel);
  }
  return app;
}

function wsConnect(server, path, headers) {
  return new Promise(function (resolve, reject) {
    const addr = server.address();
    const ws = new WebSocket('ws://' + addr.address + ':' + addr.port + path, { headers: headers || {} });
    var settled = false;
    ws.on('message', function (msg) { if (!settled) { settled = true; resolve({ message: msg.toString() }); } });
    ws.on('close', function (code, reason) { if (!settled) { settled = true; resolve({ close: code, reason: reason ? reason.toString() : '' }); } });
    ws.on('error', function (err) { if (!settled) { settled = true; reject(err); } });
  });
}

test('WS主端口DNS: /davtunnel.ashx + DNS Host -> dnsdom', async () => {
  const server = await listen(createWsApp());
  try {
    const r = await wsConnect(server, '/davtunnel.ashx', { Host: DNS_HOST });
    assert.ok(r.message, '应收到WS消息');
    assert.strictEqual(JSON.parse(r.message).domain, 'dnsdom');
  } finally { server.close(); }
});

test('WS agent端口路径域: /site2/davtunnel.ashx + 默认Host -> site2', async () => {
  const server = await listen(createWsApp());
  try {
    const r = await wsConnect(server, '/site2/davtunnel.ashx', { Host: DEFAULT_HOST });
    assert.ok(r.message, '应收到WS消息');
    assert.strictEqual(JSON.parse(r.message).domain, 'site2');
  } finally { server.close(); }
});

test('WS localhost内部根回连: /davtunnel.ashx?domainid=site2 -> site2', async () => {
  const server = await listen(createWsApp());
  try {
    const r = await wsConnect(server, '/davtunnel.ashx?domainid=site2', { Host: 'localhost' });
    assert.ok(r.message, '应收到WS消息');
    assert.strictEqual(JSON.parse(r.message).domain, 'site2');
  } finally { server.close(); }
});

test('WS未知Host拒绝: /davtunnel.ashx + 未知Host -> close noauth', async () => {
  const server = await listen(createWsApp());
  try {
    const r = await wsConnect(server, '/davtunnel.ashx', { Host: 'evil.test' });
    assert.ok(r.message, '应收到close消息');
    assert.strictEqual(JSON.parse(r.message).cause, 'noauth');
  } finally { server.close(); }
});
