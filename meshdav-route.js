'use strict';

// ---------------------------------------------------------------------------
// meshdav-route.js
// 只读 WebDAV 路由分发与安全日志 helper。
//
// 本模块只负责"按请求域动态选择已创建的 DAV 实例"和"日志脱敏"，
// 不创建 DAV 实例、不接触管理凭据，便于用真实 Express + express-ws 做回环测试。
// ---------------------------------------------------------------------------

// 敏感 header 名称（小写）。始终脱敏，不打印原始值。
var SENSITIVE_HEADERS = [
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-meshauth',
  'x-auth-token',
  'x-api-key',
  'x-access-token',
  'x-csrf-token',
  'x-xsrf-token'
];

// 非敏感元信息 header 白名单（小写）。仅这些头会出现在日志中。
// 凭据/cookie/referer/未知头一律不保留，避免泄漏新引入的凭据头。
var SAFE_HEADERS = [
  'host',
  'content-type',
  'content-length',
  'user-agent',
  'upgrade',
  'connection',
  'depth',
  'range',
  'accept',
  'accept-encoding'
];

// 按白名单复制 headers，仅保留非敏感元信息；不修改传入对象。
// 返回新对象；非对象原样返回。
function sanitizeHeaders(headers) {
  if (headers == null || typeof headers !== 'object') return headers;
  var copy = {};
  for (var k in headers) {
    if (Object.prototype.hasOwnProperty.call(headers, k)) {
      var lk = String(k).toLowerCase();
      if (SAFE_HEADERS.indexOf(lk) >= 0) {
        copy[k] = headers[k];
      }
    }
  }
  return copy;
}

// 所有 URL 去掉 ? 查询串和 # fragment 后缀；不修改传入原值。
// 非字符串原样返回。
function sanitizeUrl(url) {
  if (typeof url !== 'string') return url;
  var end = url.length;
  var qIdx = url.indexOf('?');
  var fIdx = url.indexOf('#');
  if (qIdx >= 0 && qIdx < end) end = qIdx;
  if (fIdx >= 0 && fIdx < end) end = fIdx;
  return url.substring(0, end);
}

// 创建 DAV 专用安全域解析器（不修改全局 getDomain 行为）。
//
// options.domains:     config.domains 映射（id -> domain，含 .id/.url/.dns）
// options.dnsDomains:  { hostnameLower -> domain }，从 config.domains 中 dns!=null 独立构建（不依赖证书）
// options.defaultHost: 默认主机名（来自 certificates.CommonName）
// options.isLoopback:  function(addr)->bool，回环地址判定
//
// 返回 resolveDomain(req) -> domain | null。
// 优先 req.xdomain 但严格校验 Host 与 originalUrl 挂载路径；未知 Host 拒绝（不退默认域）。
// DNS 域直接匹配 Host，不走路径前缀；路径域仅在默认 Host / localhost 双回环处理。
function createDavDomainResolver(options) {
  options = options || {};
  var domains = options.domains || {};
  var dnsDomains = options.dnsDomains || {};
  var defaultHost = (typeof options.defaultHost == 'string') ? options.defaultHost.toLowerCase() : null;
  var isLoopback = (typeof options.isLoopback == 'function') ? options.isLoopback : function () { return false; };

  function pathOnly(url) {
    if (typeof url != 'string') return url;
    var q = url.indexOf('?'); if (q >= 0) url = url.substring(0, q);
    var f = url.indexOf('#'); if (f >= 0) url = url.substring(0, f);
    return url;
  }

  function reqHost(req) {
    var h = null;
    if (req.headers && typeof req.headers.host == 'string') { h = req.headers.host; }
    else if (typeof req.hostname == 'string') { h = req.hostname; }
    if (typeof h != 'string' || h.length === 0) return null;
    if (h.charAt(0) === '[') { var end = h.indexOf(']'); return (end > 0) ? h.substring(1, end).toLowerCase() : null; }
    var c = h.lastIndexOf(':'); if (c >= 0) h = h.substring(0, c);
    return h.toLowerCase();
  }

  function isDoubleLoopback(req) {
    var ci = req.clientIp;
    if (ci == null || isLoopback(ci) == false) return false;
    var peer = null;
    if (req.connection != null && typeof req.connection.remoteAddress == 'string') { peer = req.connection.remoteAddress; }
    else if (req.socket != null && typeof req.socket.remoteAddress == 'string') { peer = req.socket.remoteAddress; }
    if (peer == null || isLoopback(peer) == false) return false;
    return true;
  }

  // 校验 originalUrl 是否精确匹配 domain 的 DAV 挂载路径（dav/ 或 davtunnel.ashx）。
  // allowRootTunnel: 仅双回环有效显式 domainid 允许 /davtunnel.ashx 根别名。
  function pathMatchesDomain(req, domain, allowRootTunnel) {
    var url = pathOnly(req.originalUrl);
    if (typeof url != 'string' || typeof domain.url != 'string') return true;
    if (allowRootTunnel && url.indexOf('/davtunnel.ashx') === 0) return true;
    if (url.indexOf(domain.url) !== 0) return false;
    var rest = url.substring(domain.url.length);
    return rest.indexOf('dav/') === 0 || rest.indexOf('davtunnel.ashx') === 0;
  }

  function resolvePathDomain(req) {
    var url = pathOnly(req.originalUrl);
    if (typeof url != 'string' || url.length < 2) return domains[''] || null;
    var x = url.split('/');
    if (x.length < 2 || x[1] === '') return domains[''] || null;
    var d = domains[x[1].toLowerCase()];
    if (d != null && d.dns == null) return d;
    return domains[''] || null;
  }

  function validateDomain(req, domain, host) {
    if (domain == null) return false;
    if (domain.dns != null) { return (host === String(domain.dns).toLowerCase()); }
    if (host === defaultHost) { /* ok */ }
    else if (host === 'localhost' && isDoubleLoopback(req)) { /* ok */ }
    else { return false; }
    var url = pathOnly(req.originalUrl);
    if (typeof url == 'string' && typeof domain.url == 'string' && url.indexOf(domain.url) !== 0) return false;
    return true;
  }

  function resolveDomain(req) {
    if (req == null) return null;
    var host = reqHost(req);

    // localhost 显式 domainid 校验优先于缓存 xdomain（防止缓存默认域绕过无效 domainid 拒绝）
    if (host === 'localhost') {
      if (isDoubleLoopback(req) == false) return null;
      var domainid = req.query ? req.query.domainid : null;
      if (domainid != null) {
        if (typeof domainid != 'string') return null;
        var d = domains[domainid];
        if (d == null) return null;
        return pathMatchesDomain(req, d, true) ? d : null;
      }
      // 无显式 domainid：可考虑缓存 xdomain 或路径域
      if (req.xdomain != null && validateDomain(req, req.xdomain, host) && pathMatchesDomain(req, req.xdomain)) return req.xdomain;
      var pd = resolvePathDomain(req);
      return (pd != null && pathMatchesDomain(req, pd)) ? pd : null;
    }

    // 非 localhost：优先缓存 xdomain 但严格校验
    if (req.xdomain != null && validateDomain(req, req.xdomain, host) && pathMatchesDomain(req, req.xdomain)) return req.xdomain;

    // DNS 域：直接匹配 Host，不走路径前缀
    if (host != null) { var dd = dnsDomains[host]; if (dd != null && pathMatchesDomain(req, dd)) return dd; }

    // 默认 Host 路径域
    if (host != null && host === defaultHost) {
      var pd2 = resolvePathDomain(req);
      return (pd2 != null && pathMatchesDomain(req, pd2)) ? pd2 : null;
    }
    return null;
  }

  return resolveDomain;
}

// 创建 DAV 路由分发器。
//
// options.getDomain: function(req) -> domain object（含 .id, .url）或 null
// options.lookup:    function(domainId) -> { instance, url } | null
//   instance: { handleRequest, handleAgentTunnel }
//   url: 实例创建时的 domain.url（basePath），用于防串域校验
//
// 返回 { handleRequest, handleAgentTunnel }：
//   handleRequest(req, res, next)  —— Express 中间件
//   handleAgentTunnel(ws, req)     —— WebSocket handler
//
// 当前域无实例时明确 404 / 关闭 WS，绝不退到默认实例。
function createDavDispatcher(options) {
  options = options || {};
  var getDomain = options.getDomain;
  var lookup = options.lookup;
  var resolveDomain = options.resolveDomain; // DAV 专用安全域解析（优先于 getDomain）

  if (typeof resolveDomain !== 'function' && typeof getDomain !== 'function') throw new Error('createDavDispatcher: resolveDomain or getDomain must be a function');
  if (typeof lookup !== 'function') throw new Error('createDavDispatcher: lookup must be a function');

  function sendHttp404(res) {
    try { res.status(404).end(); } catch (e) { }
  }

  function closeWs(ws) {
    try { ws.send(JSON.stringify({ action: 'close', cause: 'noauth', msg: 'noauth' })); } catch (e) { }
    try { ws.close(); } catch (e) { }
  }

  // 解析请求域并查找实例；返回 { domain, info } 或 null 表示应拒绝。
  function resolve(req) {
    var domain;
    if (typeof resolveDomain === 'function') {
      try { domain = resolveDomain(req); } catch (e) { return null; }
    } else {
      try { domain = getDomain(req); } catch (e) { return null; }
    }
    if (domain == null) return null;
    var info;
    try { info = lookup(domain.id); } catch (e) { return null; }
    if (info == null || info.instance == null) return null;
    // basePath 校验：实例创建时的 url 必须与请求域 url 一致，防止 DNS/路径域串域。
    if (info.url != null && domain.url != null && info.url !== domain.url) return null;
    return { domain: domain, info: info };
  }

  function handleRequest(req, res, next) {
    var r = resolve(req);
    if (r == null) return sendHttp404(res);
    return r.info.instance.handleRequest(req, res, next);
  }

  function handleAgentTunnel(ws, req) {
    var r = resolve(req);
    if (r == null) return closeWs(ws);
    return r.info.instance.handleAgentTunnel(ws, req);
  }

  return {
    handleRequest: handleRequest,
    handleAgentTunnel: handleAgentTunnel
  };
}

module.exports = {
  createDavDispatcher: createDavDispatcher,
  createDavDomainResolver: createDavDomainResolver,
  sanitizeHeaders: sanitizeHeaders,
  sanitizeUrl: sanitizeUrl,
  SENSITIVE_HEADERS: SENSITIVE_HEADERS,
  SAFE_HEADERS: SAFE_HEADERS
};
