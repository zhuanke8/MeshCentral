'use strict';
// MeshCentral 只读 WebDAV 网关测试 — 纯函数部分
const { test } = require('node:test');
const assert = require('node:assert/strict');
const meshdav = require('../meshdav.js');

// ---- parseDavPath: 路径解析与穿越防护 ----
test('parseDavPath 正常多段路径', () => {
  const r = meshdav.parseDavPath('/a/b', '/root');
  assert.deepEqual(r.segments, ['a', 'b']);
  assert.equal(r.remotePath, '/root/a/b');
});
test('parseDavPath 空路径返回 root', () => {
  const r = meshdav.parseDavPath('', '/root');
  assert.deepEqual(r.segments, []);
  assert.equal(r.remotePath, '/root');
});
test('parseDavPath 拒绝 .. 穿越', () => {
  assert.throws(() => meshdav.parseDavPath('/a/../b', '/root'), /traversal/);
});
test('parseDavPath 拒绝 . 当前目录', () => {
  assert.throws(() => meshdav.parseDavPath('/./a', '/root'), /traversal/);
});
test('parseDavPath 拒绝编码穿越 %2e%2e', () => {
  assert.throws(() => meshdav.parseDavPath('/a/%2e%2e/b', '/root'), /traversal/);
});
test('parseDavPath 拒绝反斜杠/冒号/NUL/控制字符', () => {
  assert.throws(() => meshdav.parseDavPath('/a\\b', '/root'), /backslash/);
  assert.throws(() => meshdav.parseDavPath('/a:b', '/root'), /colon/);
  assert.throws(() => meshdav.parseDavPath('/a\0b', '/root'), /nul/);
  assert.throws(() => meshdav.parseDavPath('/a\x01b', '/root'), /control/);
});
test('parseDavPath 拒绝坏编码', () => {
  assert.throws(() => meshdav.parseDavPath('/%zz', '/root'), /encoding/);
});
test('parseDavPath URL 解码段', () => {
  const r = meshdav.parseDavPath('/%E4%B8%AD', '/root');
  assert.deepEqual(r.segments, ['中']);
});

// ---- parseBasicAuth / hashPassword / verifyPassword ----
test('parseBasicAuth 正常', () => {
  const r = meshdav.parseBasicAuth('Basic ' + Buffer.from('user:pass').toString('base64'));
  assert.deepEqual(r, { username: 'user', password: 'pass' });
});
test('parseBasicAuth 无效返回 null', () => {
  assert.equal(meshdav.parseBasicAuth('Bearer x'), null);
  assert.equal(meshdav.parseBasicAuth(null), null);
  assert.equal(meshdav.parseBasicAuth('Basic !!!'), null);
});
test('hashPassword/verifyPassword 往返', () => {
  const h = meshdav.hashPassword('secret');
  assert.ok(h.startsWith('scrypt:'));
  assert.equal(meshdav.verifyPassword('secret', h), true);
  assert.equal(meshdav.verifyPassword('wrong', h), false);
});
test('verifyPassword 拒绝坏 hash', () => {
  assert.equal(meshdav.verifyPassword('x', 'bad'), false);
  assert.equal(meshdav.verifyPassword('x', 'scrypt:xx:yy'), false);
});
test('verifyPasswordAsync 回调 (err, boolean)', (t, done) => {
  const h = meshdav.hashPassword('pw');
  meshdav.verifyPasswordAsync('pw', h, (err, ok) => {
    assert.equal(err, null);
    assert.equal(ok, true);
    meshdav.verifyPasswordAsync('no', h, (err2, ok2) => {
      assert.equal(err2, null);
      assert.equal(ok2, false);
      done();
    });
  });
});

// ---- evaluateRange ----
test('evaluateRange 无 Range → 200', () => {
  assert.deepEqual(meshdav.evaluateRange(null, 100), { status: 200 });
  assert.deepEqual(meshdav.evaluateRange('', 100), { status: 200 });
});
test('evaluateRange bytes=0- → 200', () => {
  assert.deepEqual(meshdav.evaluateRange('bytes=0-', 100), { status: 200 });
});
test('evaluateRange bytes=10- → 416', () => {
  const r = meshdav.evaluateRange('bytes=10-', 100);
  assert.equal(r.status, 416);
  assert.equal(r.contentRange, 'bytes */100');
  assert.equal(r.acceptRanges, 'none');
});
test('evaluateRange 其他格式 → 416', () => {
  assert.equal(meshdav.evaluateRange('bytes=0-99', 100).status, 416);
  assert.equal(meshdav.evaluateRange('bytes=abc-', 100).status, 416);
});

// ---- buildPropfindXml ----
test('buildPropfindXml 目录结构', () => {
  const xml = meshdav.buildPropfindXml([{ href: '/dav/x/', displayname: 'x', isCollection: true, name: 'x' }]);
  assert.ok(xml.indexOf('<D:multistatus') >= 0);
  assert.ok(xml.indexOf('<D:collection/>') >= 0);
  assert.ok(xml.indexOf('</D:multistatus>') >= 0);
  assert.ok(xml.indexOf('HTTP/1.1 200 OK') >= 0);
});
test('buildPropfindXml 文件含 size/etag/contenttype', () => {
  const xml = meshdav.buildPropfindXml([{ href: '/f.txt', displayname: 'f.txt', isCollection: false, name: 'f.txt', size: 5, mtime: 1700000000000 }]);
  assert.ok(xml.indexOf('<D:getcontentlength>5</D:getcontentlength>') >= 0);
  assert.ok(xml.indexOf('<D:getetag>') >= 0);
  assert.ok(xml.indexOf('text/plain') >= 0);
});
test('buildPropfindXml 转义特殊字符', () => {
  const xml = meshdav.buildPropfindXml([{ href: '/a&b<c>', displayname: 'x', isCollection: true, name: 'x' }]);
  assert.ok(xml.indexOf('&amp;') >= 0);
  assert.ok(xml.indexOf('&lt;') >= 0);
  assert.ok(xml.indexOf('&gt;') >= 0);
});

// ===========================================================================
// 集成测试: HTTP 框架 + 401/OPTIONS/405
// ===========================================================================
const http = require('node:http');

function makeMockWebserver() {
  return {
    users: { 'user/dom1/alice': { _id: 'user/dom1/alice', name: 'alice' } },
    GetNodeWithRights(domain, user, nodeId, cb) { cb({ meshid: 'mesh//dom1/m1' }, 0xFFFFFFFF, true); },
    wsagents: { 'node/dom1/node1': { send() {} } },
    meshes: { 'mesh//dom1/m1': {} },
  };
}
function makeDomain(pass) {
  return { id: 'dom1', url: '/', readonlydav: { shares: { share1: {
    username: 'davuser', passwordhash: meshdav.hashPassword(pass),
    runasuser: 'user/dom1/alice', nodeid: 'node/dom1/node1', root: '/remote/root', maxdownloads: 4,
  } } } };
}
function makeDav(pass, openTunnelOverride, extraOpts) {
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain(pass);
  const inst = meshdav.CreateMeshDav(ws, parent, Object.assign({ domain, openTunnel: openTunnelOverride, lsIdleMs: 100, tunnelTimeoutMs: 5000, downloadTimeoutMs: 5000 }, extraOpts || {}));
  return { ws, parent, domain, inst };
}
function startServer(inst) {
  const server = http.createServer((req, res) => {
    req.path = req.url.split('?')[0];
    inst.handleRequest(req, res, () => { res.writeHead(404); res.end(); });
  });
  server.setTimeout(10000);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}
function httpReq(server, method, path, headers, body) {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    const h = Object.assign({}, headers || {});
    if (body) h['Content-Length'] = Buffer.byteLength(body);
    const r = http.request({ host: addr.address, port: addr.port, method, path, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    r.on('error', reject);
    r.setTimeout(10000, () => { r.destroy(new Error('httpReq 10s timeout')); });
    if (body) r.write(body);
    r.end();
  });
}
function basicAuth(u, p) { return { Authorization: 'Basic ' + Buffer.from(u + ':' + p).toString('base64') }; }

test('401 无认证', async () => {
  const { inst } = makeDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/');
    assert.equal(r.status, 401);
    assert.ok(r.headers['www-authenticate']);
  } finally { s.close(); }
});
test('401 错误密码', async () => {
  const { inst } = makeDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/', basicAuth('davuser', 'wrong'));
    assert.equal(r.status, 401);
  } finally { s.close(); }
});
test('OPTIONS 200 含 DAV 头', async () => {
  const { inst } = makeDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'OPTIONS', '/share1/', basicAuth('davuser', 'davpass'));
    assert.equal(r.status, 200);
    assert.equal(r.headers['dav'], '1');
    assert.ok(r.headers['allow'].indexOf('OPTIONS') >= 0);
  } finally { s.close(); }
});
test('405 写方法拒绝', async () => {
  const { inst } = makeDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PUT', '/share1/file', basicAuth('davuser', 'davpass'));
    assert.equal(r.status, 405);
    assert.ok(r.headers['allow'].indexOf('OPTIONS') >= 0);
  } finally { s.close(); }
});
test('401 未知 share', async () => {
  const { inst } = makeDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/unknown/', basicAuth('x', 'y'));
    assert.equal(r.status, 401);
  } finally { s.close(); }
});

// ---- 集成测试批2: PROPFIND Depth 0/1/infinity (假 ws 模拟 Agent ls) ----
const EventEmitter = require('node:events');
class FakeWs extends EventEmitter {
  constructor(lsHandler) { super(); this._ls = lsHandler; this.closed = false; }
  send(data, cb) {
    if (typeof data === 'string' && data !== 'c' && data !== '5') {
      try {
        const cmd = JSON.parse(data);
        if (cmd.action === 'ls') {
          const dir = this._ls(cmd);
          setImmediate(() => this.emit('message', JSON.stringify({ reqid: cmd.reqid, dir }), false));
        }
      } catch (e) {}
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}
const TEST_DIRS = {
  '/remote/root': [
    { n: 'file1.txt', t: 3, s: 100, d: 1700000000000 },
    { n: 'subdir', t: 1, d: 1700000000000 },
  ],
  '/remote/root/subdir': [{ n: 'file2.txt', t: 3, s: 50, d: 1700000000000 }],
};
// realAgentLs: 模拟真实 MeshAgent legacy getDirectoryInfo 行为
// 目录路径 → 返回该目录子项数组; 文件路径 → 返回 [] (空数组, 非 null);
// 不存在路径 → 返回 null。这与真实 Agent 一致, 旧 fake agent 对文件返回 null 是错的。
function realAgentLs(dirs, path) {
  if (dirs[path]) return dirs[path];
  var lastSlash = path.lastIndexOf('/');
  if (lastSlash > 0) {
    var parent = path.slice(0, lastSlash);
    var name = path.slice(lastSlash + 1);
    var parentDir = dirs[parent];
    if (parentDir) {
      for (var i = 0; i < parentDir.length; i++) {
        if (parentDir[i].n === name) return [];
      }
    }
  }
  return null;
}
const EMPTY_FILE_DIRS = {
  '/remote/root': [{ n: 'empty.txt', t: 3, s: 0, d: 1700000000000 }],
};
function makeLsDav(pass) {
  return makeDav(pass, (nodeid, purpose, opt, cb) => {
    cb(null, new FakeWs((cmd) => realAgentLs(TEST_DIRS, cmd.path)));
  });
}
function auth() { return basicAuth('davuser', 'davpass'); }

test('PROPFIND Depth 0 根 → 207 单项', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 207);
    assert.ok(r.body.indexOf('<D:multistatus') >= 0);
    assert.equal((r.body.match(/<D:response>/g) || []).length, 1);
  } finally { s.close(); }
});
test('PROPFIND Depth 1 根 → 207 含子项', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '1' }));
    assert.equal(r.status, 207);
    assert.equal((r.body.match(/<D:response>/g) || []).length, 3);
    assert.ok(r.body.indexOf('file1.txt') >= 0);
    assert.ok(r.body.indexOf('subdir') >= 0);
  } finally { s.close(); }
});
test('PROPFIND Depth infinity → 403', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: 'infinity' }));
    assert.equal(r.status, 403);
    assert.ok(r.body.indexOf('propfind-finite-depth') >= 0);
  } finally { s.close(); }
});
test('PROPFIND Depth 0 文件 → 207', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/file1.txt', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 207);
    assert.ok(r.body.indexOf('file1.txt') >= 0);
    assert.ok(r.body.indexOf('<D:getcontentlength>100') >= 0);
  } finally { s.close(); }
});
test('PROPFIND Depth 1 子目录 → 207 含子项', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/subdir/', Object.assign(auth(), { Depth: '1' }));
    assert.equal(r.status, 207);
    assert.equal((r.body.match(/<D:response>/g) || []).length, 2);
    assert.ok(r.body.indexOf('file2.txt') >= 0);
  } finally { s.close(); }
});
test('PROPFIND 不存在路径 → 404', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/nope', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 404);
  } finally { s.close(); }
});

// ---- 集成测试批3a: GET/HEAD/多块流/416 (假 ws 模拟协议10下载) ----
class FakeDownloadWs extends EventEmitter {
  constructor(fileData, size) { super(); this._data = fileData; this._size = size; this.closed = false; }
  send(data, cb) {
    if (data === '10') {
      setImmediate(() => {
        this.emit('message', JSON.stringify({ op: 'ok', size: this._size }), false);
        setImmediate(() => this.emit('message', this._data.slice(0, 10), true));
        setImmediate(() => this.emit('message', this._data.slice(10), true));
        setImmediate(() => this.emit('close'));
      });
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}
function makeFullDav(pass, fileData) {
  return makeDav(pass, (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(TEST_DIRS, cmd.path)));
    else cb(null, new FakeDownloadWs(fileData, fileData.length));
  });
}
const FILE_DATA = Buffer.alloc(100, 0x41);

test('GET 文件 → 200 多块流拼接', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.body, FILE_DATA.toString('utf8'));
    assert.equal(r.headers['content-length'], '100');
    assert.equal(r.headers['accept-ranges'], 'none');
  } finally { s.close(); }
});
test('HEAD 文件 → 200 无 body 有 Content-Length', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'HEAD', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.body, '');
    assert.equal(r.headers['content-length'], '100');
  } finally { s.close(); }
});
test('GET 目录 → 405', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/', auth());
    assert.equal(r.status, 405);
  } finally { s.close(); }
});
test('GET Range bytes=10- → 416', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', Object.assign(auth(), { Range: 'bytes=10-' }));
    assert.equal(r.status, 416);
    assert.ok(r.headers['content-range'].indexOf('bytes */100') >= 0);
  } finally { s.close(); }
});
test('GET 不存在文件 → 404', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/nope.txt', auth());
    assert.equal(r.status, 404);
  } finally { s.close(); }
});

class FakeDownloadWsBufferOk extends EventEmitter {
  constructor(fileData, size) { super(); this._data = fileData; this._size = size; this.closed = false; }
  send(data, cb) {
    if (data === '10') {
      setImmediate(() => {
        this.emit('message', Buffer.from(JSON.stringify({ op: 'ok', size: this._size }), 'utf8'), false);
        setImmediate(() => this.emit('message', this._data.slice(0, 10), true));
        setImmediate(() => this.emit('message', this._data.slice(10), true));
        setImmediate(() => this.emit('close'));
      });
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}
test('GET op:ok 文本帧为 Buffer 不崩溃 → 200', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(TEST_DIRS, cmd.path)));
    else cb(null, new FakeDownloadWsBufferOk(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.body, FILE_DATA.toString('utf8'));
  } finally { s.close(); }
});

// ---- 集成测试批3b: 权限拒绝 + 未知隧道关闭 ----
function makeDavCustomWs(wsModifier, pass) {
  const ws = makeMockWebserver();
  if (wsModifier) wsModifier(ws);
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain(pass || 'davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, { domain, lsIdleMs: 100 });
  return { ws, parent, domain, inst };
}
test('403 siteadmin 用户被拒', async () => {
  const { inst } = makeDavCustomWs((ws) => { ws.users['user/dom1/alice'].siteadmin = 32; });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 403);
  } finally { s.close(); }
});
test('403 无读权限 (rights & 8 == 0)', async () => {
  const { inst } = makeDavCustomWs((ws) => { ws.GetNodeWithRights = (d, u, n, cb) => cb({ meshid: 'm' }, 0, true); });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'OPTIONS', '/share1/', auth());
    assert.equal(r.status, 403);
  } finally { s.close(); }
});
test('404 节点不可见', async () => {
  const { inst } = makeDavCustomWs((ws) => { ws.GetNodeWithRights = (d, u, n, cb) => cb(null, 0, false); });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'OPTIONS', '/share1/', auth());
    assert.equal(r.status, 404);
  } finally { s.close(); }
});
test('503 Agent 离线', async () => {
  const { inst } = makeDavCustomWs((ws) => { ws.wsagents = {}; });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'OPTIONS', '/share1/', auth());
    assert.equal(r.status, 503);
  } finally { s.close(); }
});
test('未知隧道 id → ws 关闭', () => {
  const { inst } = makeDav('davpass');
  let closed = false;
  const fakeWs = new EventEmitter();
  fakeWs.close = () => { closed = true; };
  inst.handleAgentTunnel(fakeWs, { url: '/davtunnel.ashx?id=unknown' });
  assert.equal(closed, true);
});
test('隧道无 id → ws 关闭', () => {
  const { inst } = makeDav('davpass');
  let closed = false;
  const fakeWs = new EventEmitter();
  fakeWs.close = () => { closed = true; };
  inst.handleAgentTunnel(fakeWs, { url: '/davtunnel.ashx' });
  assert.equal(closed, true);
});

// ---- 集成测试批4a: 认证缓存 / setbadLogin / consent 合并 ----
test('认证缓存命中: 第二次不调 scrypt', async () => {
  const { inst } = makeDav('davpass');
  const s = await startServer(inst);
  try {
    await httpReq(s, 'OPTIONS', '/share1/', auth());
    const mid = inst._testHooks.scryptCallCount();
    await httpReq(s, 'OPTIONS', '/share1/', auth());
    const after = inst._testHooks.scryptCallCount();
    assert.equal(after, mid, '第二次应命中缓存不调 scrypt');
  } finally { s.close(); }
});
test('认证失败也调 scrypt (盲化)', async () => {
  const { inst } = makeDav('davpass');
  const s = await startServer(inst);
  try {
    const before = inst._testHooks.scryptCallCount();
    await httpReq(s, 'OPTIONS', '/share1/', basicAuth('davuser', 'wrong'));
    const after = inst._testHooks.scryptCallCount();
    assert.ok(after > before, '错误密码也应调 scrypt 盲化');
  } finally { s.close(); }
});
test('未知 share 调用 setbadLogin', async () => {
  const { inst, ws } = makeDavCustomWs((w) => {
    w.setbadLoginCalls = [];
    w.setbadLogin = (ip, user) => { w.setbadLoginCalls.push([ip, user]); };
  });
  const s = await startServer(inst);
  try {
    await httpReq(s, 'GET', '/unknown/', basicAuth('x', 'y'));
    assert.ok(ws.setbadLoginCalls.length > 0, '应调用 setbadLogin');
    assert.equal(ws.setbadLoginCalls[0][1], 'x');
  } finally { s.close(); }
});
test('consent (userconsentflags) 被合并进隧道命令', async () => {
  let capturedConsent = null;
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  domain.userconsentflags = 32;
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 100,
    openTunnel: (nodeid, purpose, opt, cb) => {
      capturedConsent = opt.consent;
      cb(null, new FakeWs((cmd) => realAgentLs(TEST_DIRS, cmd.path)));
    },
  });
  const s = await startServer(inst);
  try {
    await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.ok(capturedConsent != null, '应捕获 consent');
    assert.ok((capturedConsent & 32) !== 0, 'consent 应含 userconsentflags 位 32');
  } finally { s.close(); }
});

// ---- 集成测试批4b: 下载异常 + ls idle 竞态 ----
class FakeCloseBeforeOkWs extends EventEmitter {
  constructor() { super(); this.closed = false; }
  send(data, cb) { if (data === '10') setImmediate(() => this.emit('close')); if (cb) cb(); }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}
class FakeTruncateWs extends EventEmitter {
  constructor(sendBytes, declaredSize) { super(); this._send = sendBytes; this._size = declaredSize; this.closed = false; }
  send(data, cb) {
    if (data === '10') {
      setImmediate(() => {
        this.emit('message', JSON.stringify({ op: 'ok', size: this._size }), false);
        setImmediate(() => this.emit('message', Buffer.alloc(this._send, 0x42), true));
        setImmediate(() => this.emit('close'));
      });
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}
test('下载 op:ok 前关闭 → 502', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(TEST_DIRS, cmd.path)));
    else cb(null, new FakeCloseBeforeOkWs());
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 502);
  } finally { s.close(); }
});
test('下载中途截断 → 客户端收到不完整数据', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(TEST_DIRS, cmd.path)));
    else cb(null, new FakeTruncateWs(50, 100));
  });
  const s = await startServer(inst);
  try {
    const addr = s.address();
    const r = await new Promise((resolve, reject) => {
      const rq = http.request({ host: addr.address, port: addr.port, method: 'GET', path: '/share1/file1.txt', headers: auth() }, (res) => {
        const chunks = [];
        let ended = false;
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => { ended = true; resolve({ status: res.statusCode, body: Buffer.concat(chunks), complete: true }); });
        res.on('close', () => { if (!ended) resolve({ status: res.statusCode, body: Buffer.concat(chunks), complete: false }); });
      });
      rq.on('error', reject);
      rq.setTimeout(10000, () => { rq.destroy(); });
      rq.end();
    });
    assert.equal(r.status, 200);
    assert.equal(r.complete, false, '响应应被截断');
    assert.equal(r.body.length, 50, '只收到50字节');
  } finally { s.close(); }
});
test('ls idle 关闭后旧 ws close 不影响新连接', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    cb(null, new FakeWs((cmd) => realAgentLs(TEST_DIRS, cmd.path)));
  }, { lsIdleMs: 50 });
  const s = await startServer(inst);
  try {
    const r1 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r1.status, 207);
    await new Promise((r) => setTimeout(r, 120));
    const r2 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r2.status, 207, 'idle 关闭后新请求应正常');
  } finally { s.close(); }
});

// ---- 集成测试批5: 阶段A 下载生命周期与取消 ----
function lsDirsFor(cmd) { return realAgentLs(TEST_DIRS, cmd.path); }
function makeDownloadDav(pass, wsFactory, extra) {
  return makeDav(pass, (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
    else cb(null, wsFactory());
  }, extra || {});
}
class FakeDownloadWsNoClose extends EventEmitter {
  constructor(fileData, size) { super(); this._data = fileData; this._size = size; this.closed = false; }
  send(data, cb) {
    if (data === '10') {
      setImmediate(() => {
        this.emit('message', JSON.stringify({ op: 'ok', size: this._size }), false);
        setImmediate(() => this.emit('message', this._data, true));
      });
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}
class FakeDownloadWsEmptyNoClose extends EventEmitter {
  constructor() { super(); this.closed = false; }
  send(data, cb) {
    if (data === '10') {
      setImmediate(() => { this.emit('message', JSON.stringify({ op: 'ok', size: 0 }), false); });
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}
class FakeDownloadWsStall extends EventEmitter {
  constructor(size) { super(); this._size = size; this.closed = false; }
  send(data, cb) {
    if (data === '10') {
      setImmediate(() => { this.emit('message', JSON.stringify({ op: 'ok', size: this._size }), false); });
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}
class FakeDownloadWsBadSize extends EventEmitter {
  constructor(size) { super(); this._size = size; this.closed = false; }
  send(data, cb) {
    if (data === '10') {
      setImmediate(() => {
        this.emit('message', JSON.stringify({ op: 'ok', size: this._size }), false);
        setImmediate(() => this.emit('close'));
      });
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}
class FakeDownloadWsOverrun extends EventEmitter {
  constructor(declared, actual) { super(); this._decl = declared; this._act = actual; this.closed = false; }
  send(data, cb) {
    if (data === '10') {
      setImmediate(() => {
        this.emit('message', JSON.stringify({ op: 'ok', size: this._decl }), false);
        setImmediate(() => this.emit('message', Buffer.alloc(this._act, 0x41), true));
        setImmediate(() => this.emit('close'));
      });
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}
class FakeSlowLsWs extends EventEmitter {
  constructor() { super(); this.closed = false; }
  send(data, cb) { if (cb) cb(); }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}

test('GET 空文件 Agent 不发 close → 200 空 body', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(EMPTY_FILE_DIRS, cmd.path)));
    else cb(null, new FakeDownloadWsEmptyNoClose());
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/empty.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.body, '');
    assert.equal(r.headers['content-length'], '0');
  } finally { s.close(); }
});

test('GET 收齐字节 Agent 不发 close → 200 主动结束', async () => {
  const { inst } = makeDownloadDav('davpass', () => new FakeDownloadWsNoClose(FILE_DATA, FILE_DATA.length));
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.body, FILE_DATA.toString('utf8'));
  } finally { s.close(); }
});

test('GET op:ok 后 Agent 停滞 → 数据进度超时连接断', async () => {
  const { inst } = makeDownloadDav('davpass', () => new FakeDownloadWsStall(100), { downloadTimeoutMs: 100 });
  const s = await startServer(inst);
  try {
    const addr = s.address();
    let resolved53 = false;
    const r = await new Promise((resolve) => {
      function settle(v) { if (!resolved53) { resolved53 = true; resolve(v); } }
      const rq = http.request({ host: addr.address, port: addr.port, method: 'GET', path: '/share1/file1.txt', headers: auth() }, (res) => {
        let ended = false;
        res.on('data', () => {});
        res.on('end', () => { ended = true; settle({ status: res.statusCode, complete: true }); });
        res.on('close', () => { if (!ended) settle({ status: res.statusCode, complete: false }); });
      });
      rq.on('error', () => settle({ status: 0, complete: false, errored: true }));
      rq.setTimeout(10000, () => { rq.destroy(); });
      rq.end();
    });
    assert.ok(!r.complete, 'Agent 停滞应销毁连接');
  } finally { s.close(); }
});

for (const badSize of [-1, 1.5, 'x', null]) {
  test('GET op:ok 非法 size ' + JSON.stringify(badSize) + ' → 502', async () => {
    const { inst } = makeDownloadDav('davpass', () => new FakeDownloadWsBadSize(badSize));
    const s = await startServer(inst);
    try {
      const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
      assert.equal(r.status, 502);
    } finally { s.close(); }
  });
}

test('GET 超量数据 → 连接销毁', async () => {
  const { inst } = makeDownloadDav('davpass', () => new FakeDownloadWsOverrun(10, 11));
  const s = await startServer(inst);
  try {
    const addr = s.address();
    let resolved58 = false;
    const r = await new Promise((resolve) => {
      function settle(v) { if (!resolved58) { resolved58 = true; resolve(v); } }
      const rq = http.request({ host: addr.address, port: addr.port, method: 'GET', path: '/share1/file1.txt', headers: auth() }, (res) => {
        let ended = false;
        res.on('data', () => {});
        res.on('end', () => { ended = true; settle({ status: res.statusCode, complete: true }); });
        res.on('close', () => { if (!ended) settle({ status: res.statusCode, complete: false }); });
      });
      rq.on('error', () => settle({ status: 0, complete: false, errored: true }));
      rq.setTimeout(10000, () => { rq.destroy(); });
      rq.end();
    });
    assert.ok(!r.complete, '超量应销毁连接');
  } finally { s.close(); }
});

test('客户端在 ls 期间断开 → 不崩溃', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeSlowLsWs());
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  }, { lsTimeoutMs: 100 });
  const s = await startServer(inst);
  try {
    const addr = s.address();
    const rq = http.request({ host: addr.address, port: addr.port, method: 'GET', path: '/share1/file1.txt', headers: auth() }, () => {});
    rq.on('error', () => {});
    rq.setTimeout(10000, () => { rq.destroy(); });
    rq.end();
    await new Promise((r) => setTimeout(r, 40));
    rq.destroy();
    await new Promise((r) => setTimeout(r, 160));
    const r2 = await httpReq(s, 'OPTIONS', '/share1/', auth());
    assert.equal(r2.status, 200);
  } finally { s.close(); }
});

test('客户端在下载期间断开 → 槽位恢复后续可用', async () => {
  let first = true;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
    else if (first) { first = false; cb(null, new FakeDownloadWsStall(100)); }
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  }, { downloadTimeoutMs: 2000 });
  const s = await startServer(inst);
  try {
    const addr = s.address();
    const rq = http.request({ host: addr.address, port: addr.port, method: 'GET', path: '/share1/file1.txt', headers: auth() }, () => {});
    rq.on('error', () => {});
    rq.setTimeout(10000, () => { rq.destroy(); });
    rq.end();
    await new Promise((r) => setTimeout(r, 60));
    rq.destroy();
    await new Promise((r) => setTimeout(r, 60));
    const r2 = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r2.status, 200);
    assert.equal(r2.body, FILE_DATA.toString('utf8'));
  } finally { s.close(); }
});

test('等 Agent 回连时客户端断开 → 迟到回连被拒且槽位恢复', async () => {
  let lateCb = null;
  let cancelCalled = false;
  let first = true;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
    else if (first) {
      first = false;
      lateCb = cb;
      return function cancel() { cancelCalled = true; };
    } else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const addr = s.address();
    const rq = http.request({ host: addr.address, port: addr.port, method: 'GET', path: '/share1/file1.txt', headers: auth() }, () => {});
    rq.on('error', () => {});
    rq.setTimeout(10000, () => { rq.destroy(); });
    rq.end();
    await new Promise((r) => setTimeout(r, 150));
    assert.ok(lateCb, '应已发起下载隧道 pending');
    rq.destroy();
    await new Promise((r) => setTimeout(r, 40));
    assert.ok(cancelCalled, 'cancel 句柄应被调用');
    const lateWs = new EventEmitter();
    let lateClosed = false;
    lateWs.close = () => { if (!lateClosed) { lateClosed = true; lateWs.emit('close'); } };
    lateCb(null, lateWs);
    await new Promise((r) => setTimeout(r, 40));
    assert.ok(lateClosed, '迟到回连 ws 应被关闭');
    const r2 = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r2.status, 200);
  } finally { s.close(); }
});

test('下载失败后槽位恢复 → 后续 GET 可用 (maxDownloads=1)', async () => {
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = { id: 'dom1', url: '/', readonlydav: { shares: { share1: {
    username: 'davuser', passwordhash: meshdav.hashPassword('davpass'),
    runasuser: 'user/dom1/alice', nodeid: 'node/dom1/node1', root: '/remote/root', maxdownloads: 1,
  } } } };
  let first = true;
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 100, tunnelTimeoutMs: 5000, downloadTimeoutMs: 5000,
    openTunnel: (nodeid, purpose, opt, cb) => {
      if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
      else if (first) { first = false; cb(null, new FakeCloseBeforeOkWs()); }
      else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
    },
  });
  const s = await startServer(inst);
  try {
    const r1 = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r1.status, 502);
    const r2 = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r2.status, 200);
    assert.equal(r2.body, FILE_DATA.toString('utf8'));
  } finally { s.close(); }
});

// ---- 集成测试批6: 阶段B 同步 override + 同步 close 取消回归 ----
class FakeDownloadWsSync extends EventEmitter {
  constructor(fileData, size) { super(); this._data = fileData; this._size = size; this.closed = false; }
  send(data, cb) {
    if (data === '10') {
      this.emit('message', JSON.stringify({ op: 'ok', size: this._size }), false);
      if (this._size > 0 && this._data && this._data.length > 0) {
        this.emit('message', this._data, true);
      }
      this.emit('close');
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}

test('同步 override 回连 + 同步消息 → 200', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
    else cb(null, new FakeDownloadWsSync(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.body, FILE_DATA.toString('utf8'));
  } finally { s.close(); }
});

test('同步 override 空文件 → 200 空 body', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(EMPTY_FILE_DIRS, cmd.path)));
    else cb(null, new FakeDownloadWsSync(Buffer.alloc(0), 0));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/empty.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.body, '');
  } finally { s.close(); }
});

test('同步 override + 客户端立即断开 → 不崩溃后续可用', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
    else cb(null, new FakeDownloadWsSync(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const addr = s.address();
    const rq = http.request({ host: addr.address, port: addr.port, method: 'GET', path: '/share1/file1.txt', headers: auth() }, () => {});
    rq.on('error', () => {});
    rq.setTimeout(10000, () => { rq.destroy(); });
    rq.end();
    rq.destroy();
    await new Promise((r) => setTimeout(r, 100));
    const r2 = await httpReq(s, 'OPTIONS', '/share1/', auth());
    assert.equal(r2.status, 200);
  } finally { s.close(); }
});

test('下载中客户端断开 → cancel 句柄调用 + ws 关闭', async () => {
  let cancelCalled = false;
  let downloadWs = null;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
    else {
      downloadWs = new FakeDownloadWsStall(100);
      cb(null, downloadWs);
      return function cancel() { cancelCalled = true; };
    }
  }, { downloadTimeoutMs: 5000 });
  const s = await startServer(inst);
  try {
    const addr = s.address();
    const rq = http.request({ host: addr.address, port: addr.port, method: 'GET', path: '/share1/file1.txt', headers: auth() }, () => {});
    rq.on('error', () => {});
    rq.setTimeout(10000, () => { rq.destroy(); });
    rq.end();
    await new Promise((r) => setTimeout(r, 80));
    assert.ok(downloadWs, '下载 ws 应已创建');
    rq.destroy();
    await new Promise((r) => setTimeout(r, 80));
    assert.ok(cancelCalled, 'cancel 句柄应被调用');
    assert.ok(downloadWs.closed, 'ws 应被关闭');
  } finally { s.close(); }
});

// ---- 集成测试批7: 阶段B 跨域/consent 拒绝/非file 不误拒 ----
test('403 跨域 runAsUser 域不匹配', async () => {
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = { id: 'dom1', url: '/', readonlydav: { shares: { share1: {
    username: 'davuser', passwordhash: meshdav.hashPassword('davpass'),
    runasuser: 'user/dom2/alice', nodeid: 'node/dom1/node1', root: '/remote/root', maxdownloads: 4,
  } } } };
  const inst = meshdav.CreateMeshDav(ws, parent, { domain, lsIdleMs: 100 });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'OPTIONS', '/share1/', auth());
    assert.equal(r.status, 403);
  } finally { s.close(); }
});

function makeConsentDav(pass) {
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain(pass || 'davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 100,
    openTunnel: (nodeid, purpose, opt, cb) => {
      if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
      else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
    },
  });
  return { ws, parent, domain, inst };
}

for (const flag of [4, 32]) {
  const fname = flag === 4 ? 'filesNotify' : 'prompt';
  const sources = [
    ['domain.userconsentflags', (d, w) => { d.userconsentflags = flag; }],
    ['mesh.consent', (d, w) => { w.meshes['mesh//dom1/m1'].consent = flag; }],
    ['node.consent', (d, w) => { w.GetNodeWithRights = (dd, u, n, cb) => cb({ meshid: 'mesh//dom1/m1', consent: flag }, 0xFFFFFFFF, true); }],
    ['user.consent', (d, w) => { w.users['user/dom1/alice'].consent = flag; }],
  ];
  for (const [label, setup] of sources) {
    test('GET ' + label + '=' + flag + ' (' + fname + ') → 403', async () => {
      const { inst, domain, ws } = makeConsentDav();
      setup(domain, ws);
      const s = await startServer(inst);
      try {
        const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
        assert.equal(r.status, 403);
    } finally { s.close(); }
  });
}

// ---- 集成测试批8: 阶段B 策略变化/soptions timeout ----
test('策略变化(rights) → 旧 ls 隧道关闭开新', async () => {
  let rights = 0xFFFFFFFF;
  const createdWs = [];
  const ws = makeMockWebserver();
  ws.GetNodeWithRights = (d, u, n, cb) => cb({ meshid: 'mesh//dom1/m1' }, rights, true);
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 5000,
    openTunnel: (nodeid, purpose, opt, cb) => {
      const fake = new FakeWs(lsDirsFor);
      createdWs.push(fake);
      cb(null, fake);
    },
  });
  const s = await startServer(inst);
  try {
    const r1 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r1.status, 207);
    assert.equal(createdWs.length, 1);
    rights = 8;
    const r2 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r2.status, 207);
    assert.equal(createdWs.length, 2, '应开新隧道');
    assert.ok(createdWs[0].closed, '旧隧道应被关闭');
  } finally { s.close(); }
});

test('撤权(rights=0) → 后续请求 403', async () => {
  let rights = 0xFFFFFFFF;
  const ws = makeMockWebserver();
  ws.GetNodeWithRights = (d, u, n, cb) => cb({ meshid: 'mesh//dom1/m1' }, rights, true);
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 5000,
    openTunnel: (nodeid, purpose, opt, cb) => { cb(null, new FakeWs(lsDirsFor)); },
  });
  const s = await startServer(inst);
  try {
    const r1 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r1.status, 207);
    rights = 0;
    const r2 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r2.status, 403);
  } finally { s.close(); }
});

test('策略变化(consent) → 旧 ls 隧道关闭开新', async () => {
  let consent = 0;
  const createdWs = [];
  const ws = makeMockWebserver();
  ws.meshes['mesh//dom1/m1'].consent = 0;
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 5000,
    openTunnel: (nodeid, purpose, opt, cb) => {
      const fake = new FakeWs(lsDirsFor);
      createdWs.push(fake);
      cb(null, fake);
    },
  });
  const s = await startServer(inst);
  try {
    const r1 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r1.status, 207);
    ws.meshes['mesh//dom1/m1'].consent = 8;
    const r2 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r2.status, 207);
    assert.equal(createdWs.length, 2, '应开新隧道');
    assert.ok(createdWs[0].closed, '旧隧道应被关闭');
  } finally { s.close(); }
});

test('soptions.consentTimeout=60 → 传入隧道命令', async () => {
  let captured = null;
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  domain.consentmessages = { consenttimeout: 60 };
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 100,
    openTunnel: (nodeid, purpose, opt, cb) => {
      captured = opt.soptions;
      cb(null, new FakeWs(lsDirsFor));
    },
  });
  const s = await startServer(inst);
  try {
    await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.ok(captured != null);
    assert.equal(captured.consentTimeout, 60);
  } finally { s.close(); }
});

test('soptions 无 consentTimeout → undefined', async () => {
  let captured = null;
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 100,
    openTunnel: (nodeid, purpose, opt, cb) => {
      captured = opt.soptions;
      cb(null, new FakeWs(lsDirsFor));
    },
  });
  const s = await startServer(inst);
  try {
    await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.ok(captured != null);
    assert.equal(captured.consentTimeout, undefined);
  } finally { s.close(); }
});

test('consent=4 + lsTimeoutMs=50 → ls 用默认30s effectiveTimeout 不超时', async () => {
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  domain.userconsentflags = 4;
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 100, lsTimeoutMs: 50,
    openTunnel: (nodeid, purpose, opt, cb) => {
      if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
      else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
    },
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 207);
  } finally { s.close(); }
});

test('consent=4 + consentTimeout=1 + lsTimeoutMs=50 → ls 用1s effectiveTimeout 不超时', async () => {
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  domain.userconsentflags = 4;
  domain.consentmessages = { consenttimeout: 1 };
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 100, lsTimeoutMs: 50,
    openTunnel: (nodeid, purpose, opt, cb) => {
      if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
      else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
    },
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 207);
  } finally { s.close(); }
});

}

test('GET userGroup.consent=4 → 403', async () => {
  const { inst, ws } = makeConsentDav();
  const mesh = ws.meshes['mesh//dom1/m1'];
  mesh._id = 'mesh//dom1/m1';
  ws.GetNodeWithRights = (d, u, n, cb) => cb({ _id: 'node/dom1/node1', meshid: 'mesh//dom1/m1' }, 0xFFFFFFFF, true);
  ws.users['user/dom1/alice'].links = { 'ugrp//dom1/g1': 1 };
  ws.userGroups = { 'ugrp//dom1/g1': { consent: 4, links: { 'mesh//dom1/m1': 1 } } };
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 403);
  } finally { s.close(); }
});

for (const [label, flags] of [['1', 1], ['2', 2], ['8', 8], ['16', 16], ['27', 27]]) {
  test('GET consent=' + label + ' (非file) → 200', async () => {
    const { inst, domain } = makeConsentDav();
    domain.userconsentflags = flags;
    const s = await startServer(inst);
    try {
      const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
      assert.equal(r.status, 200);
      assert.equal(r.body, FILE_DATA.toString('utf8'));
    } finally { s.close(); }
  });
}

// ---- 集成测试批9: debug 不泄漏 token/id + 撤权关闭旧隧道 ----
test('debug openTunnel 不含 token/id 凭据', async () => {
  const debugCalls = [];
  const ws = makeMockWebserver();
  let sentToken = null;
  ws.wsagents['node/dom1/node1'].send = function (data) {
    try { sentToken = JSON.parse(data).value; } catch (e) {}
  };
  const parent = {
    args: { ignoreagenthashcheck: true },
    debug: function () { debugCalls.push(Array.from(arguments)); },
  };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 100, tunnelTimeoutMs: 200,
  });
  const s = await startServer(inst);
  try {
    await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.ok(sentToken && sentToken.indexOf('id=') >= 0, '应已发送隧道 URL');
    var token = sentToken.split('id=')[1];
    for (var i = 0; i < debugCalls.length; i++) {
      var args = debugCalls[i];
      for (var j = 0; j < args.length; j++) {
        if (typeof args[j] === 'string' && args[j].indexOf(token) >= 0) {
          assert.fail('debug 日志泄漏 token: ' + args.join(' '));
        }
      }
    }
  } finally { s.close(); }
});

test('debug handleAgentTunnel 不含 id 凭据', async () => {
  const debugCalls = [];
  const ws = makeMockWebserver();
  const parent = {
    args: { ignoreagenthashcheck: true },
    debug: function () { debugCalls.push(Array.from(arguments)); },
  };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 100, tunnelTimeoutMs: 200,
    openTunnel: (nodeid, purpose, opt, cb) => { cb(null, new FakeWs(lsDirsFor)); },
  });
  const s = await startServer(inst);
  try {
    await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    const fakeWs = new EventEmitter();
    fakeWs.close = () => {};
    inst.handleAgentTunnel(fakeWs, { url: '/davtunnel.ashx?id=unknowntestid123' });
    for (var i = 0; i < debugCalls.length; i++) {
      var args = debugCalls[i];
      for (var j = 0; j < args.length; j++) {
        if (typeof args[j] === 'string' && args[j].indexOf('unknowntestid123') >= 0) {
          assert.fail('debug 日志泄漏 id: ' + args.join(' '));
        }
      }
    }
  } finally { s.close(); }
});

test('撤权(rights=0) → 旧 ls tunnel manager 被 close+delete', async () => {
  let rights = 0xFFFFFFFF;
  const ws = makeMockWebserver();
  ws.GetNodeWithRights = (d, u, n, cb) => cb({ meshid: 'mesh//dom1/m1' }, rights, true);
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 5000,
    openTunnel: (nodeid, purpose, opt, cb) => { cb(null, new FakeWs(lsDirsFor)); },
  });
  const s = await startServer(inst);
  try {
    const r1 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r1.status, 207);
    assert.ok(inst._testHooks.lsTunnelManagers.has('share1'), '首次请求应创建 manager');
    rights = 0;
    const r2 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r2.status, 403);
    assert.ok(!inst._testHooks.lsTunnelManagers.has('share1'), '撤权后 manager 应被删除');
  } finally { s.close(); }
});

// ---- 集成测试批10: CSP/nosniff/Cache-Control/Content-Disposition 安全头 ----
function assertSecurityHeaders(h) {
  assert.ok(h['content-security-policy'], '应有 CSP');
  assert.ok(h['content-security-policy'].indexOf("default-src 'none'") >= 0, 'CSP 应含 default-src none');
  assert.ok(h['content-security-policy'].indexOf('sandbox') >= 0, 'CSP 应含 sandbox');
  assert.ok(h['content-security-policy'].indexOf('allow-scripts') < 0, 'CSP 不应含 allow-scripts');
  assert.ok(h['content-security-policy'].indexOf('allow-same-origin') < 0, 'CSP 不应含 allow-same-origin');
  assert.equal(h['x-content-type-options'], 'nosniff');
  assert.equal(h['cache-control'], 'private, no-store');
}

test('OPTIONS → CSP/nosniff/no-store 安全头', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'OPTIONS', '/share1/', auth());
    assert.equal(r.status, 200);
    assertSecurityHeaders(r.headers);
  } finally { s.close(); }
});

test('PROPFIND → CSP/nosniff/no-store 安全头', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 207);
    assertSecurityHeaders(r.headers);
  } finally { s.close(); }
});

test('401 → CSP/nosniff/no-store 安全头', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/');
    assert.equal(r.status, 401);
    assertSecurityHeaders(r.headers);
  } finally { s.close(); }
});

test('404 → CSP/nosniff/no-store 安全头', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/nope.txt', auth());
    assert.equal(r.status, 404);
    assertSecurityHeaders(r.headers);
  } finally { s.close(); }
});

test('GET 文件 → Content-Disposition attachment + 安全头', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assertSecurityHeaders(r.headers);
    assert.ok(r.headers['content-disposition'].indexOf('attachment') >= 0, '应有 Content-Disposition attachment');
    assert.ok(r.headers['content-disposition'].indexOf('file1.txt') >= 0);
  } finally { s.close(); }
});

test('HEAD 文件 → Content-Disposition attachment + 安全头', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'HEAD', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assertSecurityHeaders(r.headers);
    assert.ok(r.headers['content-disposition'].indexOf('attachment') >= 0);
  } finally { s.close(); }
});

// HTML/SVG 文件: Content-Type 允许脚本, 但 CSP sandbox 必须阻止执行
const HTML_SVG_DIRS = {
  '/remote/root': [
    { n: 'page.html', t: 3, s: 50, d: 1700000000000 },
    { n: 'icon.svg', t: 3, s: 30, d: 1700000000000 },
    { n: '中文文件.txt', t: 3, s: 10, d: 1700000000000 },
  ],
};
function makeHtmlSvgDav(pass, fileData) {
  return makeDav(pass, (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(HTML_SVG_DIRS, cmd.path)));
    else cb(null, new FakeDownloadWs(fileData, fileData.length));
  });
}
const SMALL_DATA = Buffer.alloc(50, 0x41);

test('GET HTML → CSP sandbox 阻止脚本 + Content-Disposition attachment', async () => {
  const { inst } = makeHtmlSvgDav('davpass', SMALL_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/page.html', auth());
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'text/html');
    assertSecurityHeaders(r.headers);
    assert.ok(r.headers['content-disposition'].indexOf('attachment') >= 0);
  } finally { s.close(); }
});

test('GET SVG → CSP sandbox 阻止脚本 + Content-Disposition attachment', async () => {
  const { inst } = makeHtmlSvgDav('davpass', SMALL_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/icon.svg', auth());
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-type'], 'image/svg+xml');
    assertSecurityHeaders(r.headers);
    assert.ok(r.headers['content-disposition'].indexOf('attachment') >= 0);
  } finally { s.close(); }
});

test('safeContentDisposition 防 CRLF 注入 (单元测试)', () => {
  const { inst } = makeLsDav('davpass');
  var cd = inst._testHooks.safeContentDisposition('evil\r\ninject.txt');
  assert.ok(cd.indexOf('attachment') >= 0);
  assert.ok(cd.indexOf('\r') < 0 && cd.indexOf('\n') < 0, 'Content-Disposition 不应含 CRLF');
  cd = inst._testHooks.safeContentDisposition('a"b\\c');
  assert.ok(cd.indexOf('"') < 0 || cd.indexOf('attachment; filename="a') === 0, '引号反斜杠应被清除');
});

test('GET 非 ASCII 文件名 → Content-Disposition RFC 5987 编码', async () => {
  const { inst } = makeHtmlSvgDav('davpass', SMALL_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/%E4%B8%AD%E6%96%87%E6%96%87%E4%BB%B6.txt', auth());
    assert.equal(r.status, 200);
    var cd = r.headers['content-disposition'];
    assert.ok(cd.indexOf("filename*=UTF-8''") >= 0, '非 ASCII 应有 RFC 5987 编码');
  } finally { s.close(); }
});

// ---- 集成测试批11: 同步回调 cancel 句柄断言 + err 回连清理 ----
class FakeSyncCloseBeforeOkWs extends EventEmitter {
  constructor() { super(); this.closed = false; }
  send(data, cb) { if (data === '10') this.emit('close'); if (cb) cb(); }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}

test('同步空文件 → cancel 句柄被调用 + ws 关闭', async () => {
  let cancelCalled = false;
  let dlWs = null;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(EMPTY_FILE_DIRS, cmd.path)));
    else { dlWs = new FakeDownloadWsSync(Buffer.alloc(0), 0); cb(null, dlWs); return function () { cancelCalled = true; }; }
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/empty.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.body, '');
    assert.ok(cancelCalled, 'cancel 句柄应被调用');
    assert.ok(dlWs.closed, 'ws 应被关闭');
  } finally { s.close(); }
});

test('同步数据完成 → cancel 句柄被调用 + ws 关闭', async () => {
  let cancelCalled = false;
  let dlWs = null;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
    else { dlWs = new FakeDownloadWsSync(FILE_DATA, FILE_DATA.length); cb(null, dlWs); return function () { cancelCalled = true; }; }
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.body, FILE_DATA.toString('utf8'));
    assert.ok(cancelCalled, 'cancel 句柄应被调用');
    assert.ok(dlWs.closed, 'ws 应被关闭');
  } finally { s.close(); }
});

test('同步close前ok → cancel 句柄被调用 + 502', async () => {
  let cancelCalled = false;
  let dlWs = null;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
    else { dlWs = new FakeSyncCloseBeforeOkWs(); cb(null, dlWs); return function () { cancelCalled = true; }; }
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 502);
    assert.ok(cancelCalled, 'cancel 句柄应被调用');
    assert.ok(dlWs.closed, 'ws 应被关闭');
  } finally { s.close(); }
});

test('同步 err 回连 → 502 + cancel 句柄被调用 + res 未先 destroy', async () => {
  let cancelCalled = false;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs(lsDirsFor));
    else { cb(new Error('sync tunnel error')); return function () { cancelCalled = true; }; }
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 502, 'err 回连应发 502 而非 destroy');
    assert.ok(cancelCalled, 'cancel 句柄应被调用');
  } finally { s.close(); }
});

// ---- 集成测试批12: LS 隧道管理器生命周期修复 ----
class FakeDelayedLsWs extends EventEmitter {
  constructor(lsHandler, delayMs) { super(); this._ls = lsHandler; this._delay = delayMs; this.closed = false; }
  send(data, cb) {
    if (typeof data === 'string' && data !== 'c' && data !== '5') {
      try {
        const cmd = JSON.parse(data);
        if (cmd.action === 'ls') {
          const dir = this._ls(cmd);
          var self = this;
          setTimeout(function () { if (!self.closed) self.emit('message', JSON.stringify({ reqid: cmd.reqid, dir: dir }), false); }, self._delay);
        }
      } catch (e) {}
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}

class FakeSyncCloseOnLsWs extends EventEmitter {
  constructor() { super(); this.closed = false; }
  send(data, cb) {
    if (typeof data === 'string' && data !== 'c' && data !== '5') {
      if (!this.closed) { this.closed = true; this.emit('close'); }
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}

test('多等待者撤权 → 全部有界结束 (不悬挂)', async () => {
  let rights = 0xFFFFFFFF;
  let lsCb = null;
  const ws = makeMockWebserver();
  ws.GetNodeWithRights = (d, u, n, cb) => cb({ meshid: 'mesh//dom1/m1' }, rights, true);
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 5000, tunnelTimeoutMs: 5000,
    openTunnel: (nodeid, purpose, opt, cb) => {
      if (purpose === 'ls') { lsCb = cb; return function () {}; }
      cb(null, new FakeWs(lsDirsFor));
    },
  });
  const s = await startServer(inst);
  try {
    const reqs = [];
    for (let i = 0; i < 3; i++) {
      reqs.push(httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' })));
    }
    await new Promise((r) => setTimeout(r, 100));
    assert.ok(lsCb, 'openTunnel 应已调用');
    rights = 0;
    const r4 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r4.status, 403);
    const results = await Promise.allSettled(reqs);
    for (const r of results) {
      assert.equal(r.status, 'fulfilled');
      assert.equal(r.value.status, 502);
    }
  } finally { s.close(); }
});

test('closeTunnelWs 后迟到回连 → ws 被关闭 (generation 防复活)', async () => {
  let rights = 0xFFFFFFFF;
  let lsCb = null;
  const ws = makeMockWebserver();
  ws.GetNodeWithRights = (d, u, n, cb) => cb({ meshid: 'mesh//dom1/m1' }, rights, true);
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 5000, tunnelTimeoutMs: 5000,
    openTunnel: (nodeid, purpose, opt, cb) => {
      if (purpose === 'ls') { lsCb = cb; return function () {}; }
      cb(null, new FakeWs(lsDirsFor));
    },
  });
  const s = await startServer(inst);
  try {
    const p1 = httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    await new Promise((r) => setTimeout(r, 50));
    assert.ok(lsCb);
    rights = 0;
    const r2 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r2.status, 403);
    const r1 = await p1;
    assert.equal(r1.status, 502);
    const lateWs = new EventEmitter();
    let lateClosed = false;
    lateWs.close = () => { if (!lateClosed) { lateClosed = true; lateWs.emit('close'); } };
    lateWs.send = () => {};
    lsCb(null, lateWs);
    await new Promise((r) => setTimeout(r, 50));
    assert.ok(lateClosed, '迟到回连 ws 应被关闭');
  } finally { s.close(); }
});

test('默认 openTunnel pending token → 撤权后迟到回连被拒', async () => {
  let rights = 0xFFFFFFFF;
  let sentToken = null;
  const ws = makeMockWebserver();
  ws.GetNodeWithRights = (d, u, n, cb) => cb({ meshid: 'mesh//dom1/m1' }, rights, true);
  ws.wsagents['node/dom1/node1'].send = function (data) {
    try { sentToken = JSON.parse(data).value; } catch (e) {}
  };
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 5000, tunnelTimeoutMs: 5000,
  });
  const s = await startServer(inst);
  try {
    const p1 = httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    await new Promise((r) => setTimeout(r, 50));
    assert.ok(sentToken, '应已发送隧道 URL');
    var token = sentToken.split('id=')[1];
    rights = 0;
    const r2 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r2.status, 403);
    const r1 = await p1;
    assert.equal(r1.status, 502);
    const lateWs = new EventEmitter();
    let lateClosed = false;
    lateWs.close = () => { if (!lateClosed) { lateClosed = true; lateWs.emit('close'); } };
    inst.handleAgentTunnel(lateWs, { url: '/davtunnel.ashx?id=' + token });
    assert.ok(lateClosed, '迟到回连 ws 应被关闭 (entry 已取消)');
  } finally { s.close(); }
});

test('ls 超时后 WS 不泄漏 (resetIdleTimer 重新调度)', async () => {
  let lsWs = null;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') { lsWs = new FakeSlowLsWs(); cb(null, lsWs); }
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  }, { lsIdleMs: 50, lsTimeoutMs: 100 });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 502);
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(lsWs.closed, 'ls 超时后 WS 应被 idle timer 关闭');
  } finally { s.close(); }
});

test('consent 延长 effectiveTimeout → ls 不超时 (响应延迟超过 base timeout)', async () => {
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  domain.userconsentflags = 4;
  domain.consentmessages = { consenttimeout: 1 };
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 200, lsTimeoutMs: 50,
    openTunnel: (nodeid, purpose, opt, cb) => {
      if (purpose === 'ls') cb(null, new FakeDelayedLsWs(lsDirsFor, 200));
      else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
    },
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 207, 'consent 延长 effectiveTimeout 后 ls 不应超时');
  } finally { s.close(); }
});

test('consent 长等后 ls 超时 → WS 被 idle timer 关闭 (不泄漏)', async () => {
  let lsWs = null;
  const ws = makeMockWebserver();
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  domain.userconsentflags = 4;
  domain.consentmessages = { consenttimeout: 1 };
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 50, lsTimeoutMs: 50,
    openTunnel: (nodeid, purpose, opt, cb) => {
      if (purpose === 'ls') { lsWs = new FakeSlowLsWs(); cb(null, lsWs); }
      else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
    },
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 502);
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(lsWs.closed, 'consent 长等超时后 WS 应被 idle timer 关闭');
  } finally { s.close(); }
});

test('同步 close 不导致重复队列回调或悬挂', async () => {
  let lsWs = null;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') { lsWs = new FakeSyncCloseOnLsWs(); cb(null, lsWs); }
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  }, { lsIdleMs: 100, lsTimeoutMs: 5000 });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 502);
    assert.ok(lsWs.closed, 'ws 应被关闭');
  } finally { s.close(); }
});

// ---- 集成测试批13: 初补丁精确修复验证 ----
class FakeThrowOnLsWs extends EventEmitter {
  constructor() { super(); this.closed = false; }
  send(data, cb) {
    if (typeof data === 'string' && data !== 'c' && data !== '5') {
      throw new Error('send throw');
    }
    if (cb) cb();
  }
  close() { if (!this.closed) { this.closed = true; this.emit('close'); } }
}

test('openTunnel 同步回调成功 → cancel 句柄被清理', async () => {
  let cancelCalled = false;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') {
      cb(null, new FakeWs(lsDirsFor));
      return function () { cancelCalled = true; };
    }
    cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 207);
    assert.ok(cancelCalled, '同步回调成功后 cancel 句柄应被调用清理');
  } finally { s.close(); }
});

test('openTunnel 同步回调 err → cancel 句柄被清理', async () => {
  let cancelCalled = false;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') {
      cb(new Error('sync connect error'));
      return function () { cancelCalled = true; };
    }
    cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 502);
    assert.ok(cancelCalled, '同步回调 err 后 cancel 句柄应被调用清理');
  } finally { s.close(); }
});

test('指纹换代 → 已发 LS 被 failAll reject (不依赖 ws.close emit)', async () => {
  let lsCallCount = 0;
  const ws = makeMockWebserver();
  ws.meshes['mesh//dom1/m1'].consent = 0;
  const parent = { args: { ignoreagenthashcheck: true } };
  const domain = makeDomain('davpass');
  const inst = meshdav.CreateMeshDav(ws, parent, {
    domain, lsIdleMs: 5000, lsTimeoutMs: 5000,
    openTunnel: (nodeid, purpose, opt, cb) => {
      if (purpose === 'ls') {
        lsCallCount++;
        if (lsCallCount === 1) cb(null, new FakeSlowLsWs());
        else cb(null, new FakeWs(lsDirsFor));
      } else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
    },
  });
  const s = await startServer(inst);
  try {
    const p1 = httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    await new Promise((r) => setTimeout(r, 100));
    ws.meshes['mesh//dom1/m1'].consent = 8;
    const r2 = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r2.status, 207, '第二个 PROPFIND 应开新隧道成功');
    const r1 = await p1;
    assert.equal(r1.status, 502, '已发 LS 应被 failAll reject');
  } finally { s.close(); }
});

test('drain 时前一个回调同步 close → 后续等待者 reject', async () => {
  let lateCb = null;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') { lateCb = cb; return function () {}; }
    cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  }, { lsIdleMs: 5000, lsTimeoutMs: 5000 });
  const s = await startServer(inst);
  try {
    const p1 = httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    const p2 = httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    await new Promise((r) => setTimeout(r, 100));
    assert.ok(lateCb, 'openTunnel 应已调用');
    lateCb(null, new FakeSyncCloseOnLsWs());
    const results = await Promise.allSettled([p1, p2]);
    for (const r of results) {
      assert.equal(r.status, 'fulfilled');
      assert.equal(r.value.status, 502);
    }
  } finally { s.close(); }
});

test('send throw → resetIdleTimer 安排 idle 关闭 (不泄漏)', async () => {
  let lsWs = null;
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') { lsWs = new FakeThrowOnLsWs(); cb(null, lsWs); }
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  }, { lsIdleMs: 50, lsTimeoutMs: 5000 });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 502);
    await new Promise((r) => setTimeout(r, 200));
    assert.ok(lsWs.closed, 'send throw 后 WS 应被 idle timer 关闭');
  } finally { s.close(); }
});

// ---- 集成测试批14: 真实 Agent dir:[] bug 修复验证 ----
// 真实 MeshAgent legacy getDirectoryInfo 对文件路径返回 { dir: [] } (空数组),
// 导致旧逻辑 if(result.dir) 把文件当目录。以下验证修复后行为正确。

test('真实Agent: 文件 PROPFIND Depth0 不是 collection 且有 getcontentlength', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/file1.txt', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 207);
    assert.ok(r.body.indexOf('<D:collection/>') < 0, '文件不应是 collection');
    assert.ok(r.body.indexOf('<D:getcontentlength>100') >= 0, '应有 getcontentlength 100');
    assert.ok(r.body.indexOf('/share1/file1.txt/') < 0, '文件 href 不应带尾斜杠');
  } finally { s.close(); }
});

test('真实Agent: HEAD 文件返回真实大小 (非 0)', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'HEAD', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-length'], '100', '应返回真实大小 100');
    assert.equal(r.body, '');
    assert.ok(r.headers['content-type'].indexOf('text/plain') >= 0, '应是 text/plain');
  } finally { s.close(); }
});

test('真实Agent: GET 文件进入下载 (不再 405)', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 200, 'GET 文件应 200 下载, 不再 405');
    assert.equal(r.body, FILE_DATA.toString('utf8'));
    assert.equal(r.headers['content-length'], '100');
  } finally { s.close(); }
});

test('真实Agent: 空目录 PROPFIND Depth0 仍是 collection', async () => {
  const EMPTY_DIR_DIRS = {
    '/remote/root': [
      { n: 'emptydir', t: 1, d: 1700000000000 },
      { n: 'file1.txt', t: 3, s: 100, d: 1700000000000 },
    ],
  };
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(EMPTY_DIR_DIRS, cmd.path)));
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/emptydir/', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 207);
    assert.ok(r.body.indexOf('<D:collection/>') >= 0, '空目录应是 collection');
  } finally { s.close(); }
});

test('真实Agent: 空目录 PROPFIND Depth1 只有自身 (无子项)', async () => {
  const EMPTY_DIR_DIRS2 = {
    '/remote/root': [
      { n: 'emptydir', t: 1, d: 1700000000000 },
    ],
  };
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(EMPTY_DIR_DIRS2, cmd.path)));
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/emptydir/', Object.assign(auth(), { Depth: '1' }));
    assert.equal(r.status, 207);
    assert.equal((r.body.match(/<D:response>/g) || []).length, 1, '空目录 Depth1 应只有自身');
    assert.ok(r.body.indexOf('<D:collection/>') >= 0);
  } finally { s.close(); }
});

test('真实Agent: 空目录 HEAD → 200 Content-Length 0', async () => {
  const EMPTY_DIR_DIRS3 = {
    '/remote/root': [
      { n: 'emptydir', t: 1, d: 1700000000000 },
    ],
  };
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(EMPTY_DIR_DIRS3, cmd.path)));
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'HEAD', '/share1/emptydir/', auth());
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-length'], '0');
  } finally { s.close(); }
});

test('真实Agent: 空目录 GET → 405', async () => {
  const EMPTY_DIR_DIRS4 = {
    '/remote/root': [
      { n: 'emptydir', t: 1, d: 1700000000000 },
    ],
  };
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => realAgentLs(EMPTY_DIR_DIRS4, cmd.path)));
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/emptydir/', auth());
    assert.equal(r.status, 405, '空目录 GET 应 405');
  } finally { s.close(); }
});

test('真实Agent: 不存在路径 PROPFIND → 404', async () => {
  const { inst } = makeLsDav('davpass');
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/nope', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 404);
  } finally { s.close(); }
});

test('真实Agent: 不存在路径 HEAD → 404', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'HEAD', '/share1/nope.txt', auth());
    assert.equal(r.status, 404);
  } finally { s.close(); }
});

test('真实Agent: 不存在路径 GET → 404', async () => {
  const { inst } = makeFullDav('davpass', FILE_DATA);
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/nope.txt', auth());
    assert.equal(r.status, 404);
  } finally { s.close(); }
});

// dir:null 兼容用例: 旧 fake agent 对文件返回 null, 新逻辑应仍正确 (走父目录分支)
test('dir:null 兼容: 文件 PROPFIND Depth0 仍正确 (旧 Agent 行为)', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => TEST_DIRS[cmd.path] || null));
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'PROPFIND', '/share1/file1.txt', Object.assign(auth(), { Depth: '0' }));
    assert.equal(r.status, 207);
    assert.ok(r.body.indexOf('<D:collection/>') < 0, '文件不应是 collection');
    assert.ok(r.body.indexOf('<D:getcontentlength>100') >= 0);
  } finally { s.close(); }
});

test('dir:null 兼容: HEAD 文件返回真实大小 (旧 Agent 行为)', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => TEST_DIRS[cmd.path] || null));
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'HEAD', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.headers['content-length'], '100');
  } finally { s.close(); }
});

test('dir:null 兼容: GET 文件进入下载 (旧 Agent 行为)', async () => {
  const { inst } = makeDav('davpass', (nodeid, purpose, opt, cb) => {
    if (purpose === 'ls') cb(null, new FakeWs((cmd) => TEST_DIRS[cmd.path] || null));
    else cb(null, new FakeDownloadWs(FILE_DATA, FILE_DATA.length));
  });
  const s = await startServer(inst);
  try {
    const r = await httpReq(s, 'GET', '/share1/file1.txt', auth());
    assert.equal(r.status, 200);
    assert.equal(r.body, FILE_DATA.toString('utf8'));
  } finally { s.close(); }
});
