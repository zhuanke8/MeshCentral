'use strict';

// MeshCentral 只读 WebDAV 网关核心模块 (meshdav.js)
// 规格: SPEC-readonly-dav.md
// 导出: CreateMeshDav, parseDavPath, buildPropfindXml, verifyPassword, hashPassword, parseBasicAuth, evaluateRange

var crypto = require('crypto');

// ---------------------------------------------------------------------------
// 纯函数 (导出供测试)
// ---------------------------------------------------------------------------

// parseBasicAuth: 解析 Authorization: Basic <base64>
// 返回 { username, password } 或 null
function parseBasicAuth(authHeader) {
  if (typeof authHeader !== 'string') return null;
  var m = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(authHeader);
  if (!m) return null;
  var decoded;
  try {
    decoded = Buffer.from(m[1], 'base64').toString('utf8');
  } catch (e) {
    return null;
  }
  var idx = decoded.indexOf(':');
  if (idx < 0) return null;
  return { username: decoded.slice(0, idx), password: decoded.slice(idx + 1) };
}

// hashPassword: 生成 scrypt:<salthex>:<hashhex> (16 字节盐, 32 字节 hash)
function hashPassword(password) {
  var salt = crypto.randomBytes(16);
  var hash = crypto.scryptSync(Buffer.from(String(password), 'utf8'), salt, 32);
  return 'scrypt:' + salt.toString('hex') + ':' + hash.toString('hex');
}

// verifyPassword: 用 timingSafeEqual 比较密码与 scrypt hash
function verifyPassword(password, passwordHash) {
  if (typeof password !== 'string' || typeof passwordHash !== 'string') return false;
  var parts = passwordHash.split(':');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  var salt, expected;
  try {
    salt = Buffer.from(parts[1], 'hex');
    expected = Buffer.from(parts[2], 'hex');
  } catch (e) {
    return false;
  }
  if (salt.length !== 16 || expected.length !== 32) return false;
  var computed;
  try {
    computed = crypto.scryptSync(Buffer.from(password, 'utf8'), salt, 32);
  } catch (e) {
    return false;
  }
  if (computed.length !== expected.length) return false;
  return crypto.timingSafeEqual(computed, expected);
}

// verifyPasswordAsync: 异步版, 使用 crypto.scrypt 不阻塞事件循环
function verifyPasswordAsync(password, passwordHash, callback) {
  if (typeof password !== 'string' || typeof passwordHash !== 'string') return callback(null, false);
  var parts = passwordHash.split(':');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return callback(null, false);
  var salt, expected;
  try {
    salt = Buffer.from(parts[1], 'hex');
    expected = Buffer.from(parts[2], 'hex');
  } catch (e) {
    return callback(null, false);
  }
  if (salt.length !== 16 || expected.length !== 32) return callback(null, false);
  crypto.scrypt(Buffer.from(password, 'utf8'), salt, 32, function (err, computed) {
    if (err) return callback(null, false);
    if (computed.length !== expected.length) return callback(null, false);
    callback(null, crypto.timingSafeEqual(computed, expected));
  });
}

// constantTimeEqualString: 常数时间字符串比较
function constantTimeEqualString(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  var ba = Buffer.from(a, 'utf8');
  var bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// parseDavPath: 解析挂载后的相对路径，安全检查每一段
// 返回 { segments, remotePath } 或抛出 Error (调用方转 400)
function parseDavPath(relPath, root) {
  if (typeof root !== 'string' || root.length === 0) throw new Error('invalid root');
  var p = (typeof relPath === 'string') ? relPath : '';
  var rawSegments = p.split('/');
  var segments = [];
  for (var i = 0; i < rawSegments.length; i++) {
    var seg = rawSegments[i];
    if (seg === '') continue; // 空段忽略
    var decoded;
    try {
      decoded = decodeURIComponent(seg);
    } catch (e) {
      throw new Error('bad encoding');
    }
    if (decoded === '.' || decoded === '..') throw new Error('traversal');
    if (decoded.indexOf('/') >= 0) throw new Error('slash in segment');
    if (decoded.indexOf('\\') >= 0) throw new Error('backslash');
    if (decoded.indexOf(':') >= 0) throw new Error('colon');
    if (decoded.indexOf('\0') >= 0) throw new Error('nul');
    for (var j = 0; j < decoded.length; j++) {
      if (decoded.charCodeAt(j) < 0x20) throw new Error('control char');
    }
    segments.push(decoded);
  }
  // 远端路径 = root 去掉末尾分隔符后 + '/' + 段.join('/')
  var rootTrimmed = root;
  while (rootTrimmed.length > 1 && rootTrimmed.charCodeAt(rootTrimmed.length - 1) === 47) {
    rootTrimmed = rootTrimmed.slice(0, -1);
  }
  var remotePath;
  if (segments.length === 0) {
    remotePath = rootTrimmed;
  } else if (rootTrimmed.charCodeAt(rootTrimmed.length - 1) === 47) {
    remotePath = rootTrimmed + segments.join('/');
  } else {
    remotePath = rootTrimmed + '/' + segments.join('/');
  }
  return { segments: segments, remotePath: remotePath };
}

// evaluateRange: Range 策略
// 无 Range 或 bytes=0- → 200; 其他 → 416 (绝不返回 206)
function evaluateRange(rangeHeader, size) {
  if (rangeHeader == null || rangeHeader === '') return { status: 200 };
  var m = /^bytes=(\d+)-$/.exec(rangeHeader);
  if (m) {
    var start = parseInt(m[1], 10);
    if (start === 0) return { status: 200 }; // bytes=0- 等价完整
  }
  return { status: 416, contentRange: 'bytes */' + size, acceptRanges: 'none' };
}

// xmlEscape: XML 特殊字符转义
function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// contentTypeFor: 扩展名 → Content-Type (简单映射, 默认 application/octet-stream)
function contentTypeFor(name) {
  if (typeof name !== 'string' || name.length === 0) return 'application/octet-stream';
  var dot = name.lastIndexOf('.');
  if (dot < 0) return 'application/octet-stream';
  var ext = name.slice(dot + 1).toLowerCase();
  var map = {
    txt: 'text/plain', log: 'text/plain', md: 'text/plain', conf: 'text/plain', ini: 'text/plain',
    html: 'text/html', htm: 'text/html', css: 'text/css', csv: 'text/csv',
    js: 'application/javascript', mjs: 'application/javascript', json: 'application/json',
    xml: 'application/xml', pdf: 'application/pdf', zip: 'application/zip',
    gz: 'application/gzip', tgz: 'application/gzip', tar: 'application/x-tar', '7z': 'application/x-7z-compressed',
    rar: 'application/x-rar-compressed', bz2: 'application/x-bzip2', xz: 'application/x-xz',
    png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
    bmp: 'image/bmp', ico: 'image/x-icon', svg: 'image/svg+xml', webp: 'image/webp', tiff: 'image/tiff', tif: 'image/tiff',
    mp3: 'audio/mpeg', ogg: 'audio/ogg', wav: 'audio/wav', flac: 'audio/flac',
    aac: 'audio/aac', m4a: 'audio/mp4', wma: 'audio/x-ms-wma', mid: 'audio/midi', midi: 'audio/midi',
    mp4: 'video/mp4', m4v: 'video/mp4', mkv: 'video/x-matroska', avi: 'video/x-msvideo',
    mov: 'video/quicktime', wmv: 'video/x-ms-wmv', webm: 'video/webm', flv: 'video/x-flv',
    ts: 'video/mp2t', mpg: 'video/mpeg', mpeg: 'video/mpeg', vob: 'video/dvd', '3gp': 'video/3gpp', '3g2': 'video/3gpp2',
    wasm: 'application/wasm', woff: 'font/woff', woff2: 'font/woff2',
    ttf: 'font/ttf', otf: 'font/otf', eot: 'application/vnd.ms-fontobject',
    exe: 'application/octet-stream', msi: 'application/octet-stream',
    deb: 'application/octet-stream', rpm: 'application/octet-stream',
    dmg: 'application/octet-stream', iso: 'application/octet-stream',
    img: 'application/octet-stream', bin: 'application/octet-stream', dat: 'application/octet-stream',
    sh: 'application/x-sh', bat: 'application/x-msdownload', cmd: 'application/x-msdownload', ps1: 'application/x-msdownload',
    java: 'text/x-java-source', c: 'text/x-csrc', h: 'text/x-csrc',
    cpp: 'text/x-c++src', hpp: 'text/x-c++src', cc: 'text/x-c++src', cxx: 'text/x-c++src',
    py: 'text/x-python', rb: 'application/x-ruby', php: 'application/x-httpd-php',
    pl: 'application/x-perl', rs: 'text/x-rust', go: 'text/x-golang', swift: 'text/x-swift',
    kt: 'text/x-kotlin', scala: 'text/x-scala', lua: 'text/x-lua', r: 'text/x-rsrc',
    tsx: 'application/typescript', jsx: 'application/javascript',
    yaml: 'text/plain', yml: 'text/plain', toml: 'text/plain',
    srt: 'text/plain', vtt: 'text/vtt', ass: 'text/plain', ssa: 'text/plain',
    sql: 'application/sql', graphql: 'application/graphql', proto: 'text/plain',
    patch: 'text/plain', diff: 'text/plain', rtf: 'application/rtf',
    doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    epub: 'application/epub+zip', mobi: 'application/x-mobipocket-ebook', azw3: 'application/x-mobipocket-ebook',
  };
  return map[ext] || 'application/octet-stream';
}

// buildPropfindXml: 生成 207 multistatus XML
// entries: [{ href, displayname, isCollection, size, mtime, name }]
function buildPropfindXml(entries) {
  if (!Array.isArray(entries)) entries = [];
  var out = '<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:">\n';
  for (var i = 0; i < entries.length; i++) {
    var e = entries[i];
    out += ' <D:response>\n  <D:href>' + xmlEscape(e.href) + '</D:href>\n  <D:propstat>\n   <D:prop>\n';
    if (e.displayname != null) {
      out += '    <D:displayname>' + xmlEscape(e.displayname) + '</D:displayname>\n';
    }
    if (e.isCollection) {
      out += '    <D:resourcetype><D:collection/></D:resourcetype>\n';
    } else {
      out += '    <D:resourcetype/>\n';
    }
    if (!e.isCollection && typeof e.size === 'number') {
      out += '    <D:getcontentlength>' + e.size + '</D:getcontentlength>\n';
    }
    if (e.mtime != null) {
      var u = new Date(e.mtime).toUTCString();
      if (u && u !== 'Invalid Date') {
        out += '    <D:getlastmodified>' + xmlEscape(u) + '</D:getlastmodified>\n';
      }
    }
    if (!e.isCollection && typeof e.size === 'number' && e.mtime != null) {
      var etag = 'W/"' + e.size + '-' + new Date(e.mtime).getTime() + '"';
      out += '    <D:getetag>' + xmlEscape(etag) + '</D:getetag>\n';
    }
    if (!e.isCollection) {
      out += '    <D:getcontenttype>' + xmlEscape(contentTypeFor(e.name || '')) + '</D:getcontenttype>\n';
    }
    out += '   </D:prop>\n   <D:status>HTTP/1.1 200 OK</D:status>\n  </D:propstat>\n </D:response>\n';
  }
  out += '</D:multistatus>\n';
  return out;
}

// ---------------------------------------------------------------------------
// CreateMeshDav
// ---------------------------------------------------------------------------
function CreateMeshDav(webserver, parent, options) {
  options = options || {};
  var domain = options.domain;
  var openTunnelOverride = options.openTunnel;
  var davConfig = (domain && domain.readonlydav) || {};
  var realm = davConfig.realm || 'MeshCentral Read-Only DAV';
  var shares = {};       // 校验后的 share 配置: name -> config
  var shareNames = [];   // 有序 share 名列表

  // 可配置超时（供测试覆盖）
  var lsIdleMs = options.lsIdleMs || 60000;
  var tunnelTimeoutMs = options.tunnelTimeoutMs || 30000;
  var lsTimeoutMs = options.lsTimeoutMs || 35000;
  var downloadTimeoutMs = options.downloadTimeoutMs || 20000;

  // pending 隧道表: token -> { nodeid, purpose, callback, timer }
  var pendingTunnels = new Map();

  // 下载并发计数: shareName -> count
  var downloadCounters = new Map();

  // 协议5 复用隧道管理器: shareName -> manager
  var lsTunnelManagers = new Map();

  // 认证成功缓存: HMAC-SHA256(进程随机密钥, shareName + '\0' + Authorization头) -> expires
  var authCacheKey = crypto.randomBytes(32);
  var authCache = new Map();
  var AUTH_CACHE_TTL = 5 * 60 * 1000; // 5 分钟
  var AUTH_CACHE_MAX = 1000;

  function getAuthCacheKey(shareName, authHeader) {
    return crypto.createHmac('sha256', authCacheKey)
      .update(shareName + '\0' + (authHeader || ''))
      .digest('hex');
  }

  function checkAuthCache(key) {
    var expires = authCache.get(key);
    if (expires && expires > Date.now()) return true;
    if (expires) authCache.delete(key);
    return false;
  }

  function setAuthCache(key) {
    if (authCache.size >= AUTH_CACHE_MAX) {
      var now = Date.now();
      var ck = Array.from(authCache.keys());
      for (var i = 0; i < ck.length; i++) {
        if (authCache.get(ck[i]) <= now) authCache.delete(ck[i]);
      }
      if (authCache.size >= AUTH_CACHE_MAX) {
        authCache.delete(Array.from(authCache.keys())[0]);
      }
    }
    authCache.set(key, Date.now() + AUTH_CACHE_TTL);
  }

  // 未知 share 用的假 hash（启动时随机生成，消除时间差）
  var dummyHash = hashPassword('');

  // 认证 scrypt 调用计数（供测试验证缓存命中）
  var scryptCallCount = 0;

  // ---- 配置校验 ----
  function validatePasswordHash(hash) {
    if (typeof hash !== 'string') return false;
    var parts = hash.split(':');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    try {
      var salt = Buffer.from(parts[1], 'hex');
      var h = Buffer.from(parts[2], 'hex');
      return salt.length === 16 && h.length === 32;
    } catch (e) {
      return false;
    }
  }

  function loadShares() {
    var rawShares = davConfig.shares || {};
    var keys = Object.keys(rawShares);
    for (var i = 0; i < keys.length; i++) {
      var name = keys[i]; // 已小写
      var raw = rawShares[name];
      if (!raw || typeof raw !== 'object') {
        console.log('[meshdav] share "' + name + '" skipped: not an object');
        continue;
      }
      if (typeof raw.username !== 'string' || raw.username.length === 0) {
        console.log('[meshdav] share "' + name + '" skipped: missing username');
        continue;
      }
      if (!validatePasswordHash(raw.passwordhash)) {
        console.log('[meshdav] share "' + name + '" skipped: invalid passwordHash');
        continue;
      }
      if (typeof raw.runasuser !== 'string' || raw.runasuser.length === 0) {
        console.log('[meshdav] share "' + name + '" skipped: missing runAsUser');
        continue;
      }
      if (typeof raw.nodeid !== 'string' || raw.nodeid.length === 0) {
        console.log('[meshdav] share "' + name + '" skipped: missing nodeId');
        continue;
      }
      var nodePrefix = 'node/' + (domain ? domain.id : '') + '/';
      if (raw.nodeid.indexOf(nodePrefix) !== 0) {
        console.log('[meshdav] share "' + name + '" skipped: nodeId does not belong to domain');
        continue;
      }
      if (typeof raw.root !== 'string' || raw.root.length === 0) {
        console.log('[meshdav] share "' + name + '" skipped: missing root');
        continue;
      }
      var maxDownloads = 4;
      if (typeof raw.maxdownloads === 'number' && raw.maxdownloads > 0) {
        maxDownloads = Math.floor(raw.maxdownloads);
      }
      shares[name] = {
        name: name,
        username: raw.username,
        passwordHash: raw.passwordhash,
        runAsUser: raw.runasuser,
        nodeId: raw.nodeid,
        root: raw.root,
        maxDownloads: maxDownloads,
      };
      shareNames.push(name);
    }
  }

  loadShares();

  // ---- 辅助函数 ----
  function debug() {
    if (parent && typeof parent.debug === 'function') {
      var args = ['dav'];
      for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
      try { parent.debug.apply(parent, args); } catch (e) {}
    }
  }

  function getClientIp(req) {
    return req.clientIp || (req.socket && req.socket.remoteAddress) || '';
  }

  function sendError(res, status, message, extraHeaders) {
    if (res.headersSent || res.destroyed || res.writableEnd) return;
    var headers = { 'Content-Type': 'text/plain; charset=utf-8' };
    if (extraHeaders) {
      var hkeys = Object.keys(extraHeaders);
      for (var i = 0; i < hkeys.length; i++) headers[hkeys[i]] = extraHeaders[hkeys[i]];
    }
    withSecurityHeaders(headers);
    res.writeHead(status, headers);
    res.end(message || '');
  }

  function sendAuthRequired(res) {
    sendError(res, 401, 'Authentication required', {
      'WWW-Authenticate': 'Basic realm="' + realm + '"',
    });
  }

  // ---- DAV 安全响应头: 独立 CSP sandbox, nosniff, no-store ----
  var DAV_CSP = "default-src 'none'; sandbox";
  function withSecurityHeaders(headers) {
    headers = headers || {};
    headers['Content-Security-Policy'] = DAV_CSP;
    headers['X-Content-Type-Options'] = 'nosniff';
    headers['Cache-Control'] = 'private, no-store';
    return headers;
  }
  // 安全 Content-Disposition: 防 CRLF 注入, 非 ASCII 用 RFC 5987
  function safeContentDisposition(name) {
    var raw = String(name || 'file');
    var base = raw.slice(raw.lastIndexOf('/') + 1);
    // 防 CRLF 注入: 去掉 \r \n 及其他控制字符、引号、反斜杠
    var ascii = base.replace(/[\x00-\x1F\x7F"\\]/g, '');
    var hasNonAscii = /[^\x20-\x7E]/.test(ascii);
    // filename= 只放 ASCII, 非 ASCII 用 ? 占位
    var safeAscii = hasNonAscii ? ascii.replace(/[^\x20-\x7E]/g, '?') : ascii;
    var cd = 'attachment; filename="' + safeAscii + '"';
    if (hasNonAscii) {
      var enc = encodeURIComponent(base).replace(/['()]/g, escape).replace(/\*/g, '%2A');
      cd += "; filename*=UTF-8''" + enc;
    }
    return cd;
  }

  // ls 错误: 权限错误有 status, 隧道错误 → 502
  function sendLsError(res, err) {
    if (err && err.status) sendError(res, err.status, err.message);
    else sendError(res, 502, 'Bad Gateway');
  }

  // 从 req.path 提取 share 名和剩余路径
  function extractShareAndPath(pathStr) {
    var parts = pathStr.split('/');
    if (parts.length < 2 || parts[1] === '') return { share: null, rest: '' };
    var share;
    try {
      share = decodeURIComponent(parts[1]);
    } catch (e) {
      return { share: null, rest: '', error: true };
    }
    var rest = '';
    for (var i = 2; i < parts.length; i++) {
      rest += '/' + parts[i];
    }
    return { share: share, rest: rest };
  }

  // Basic 认证 (异步, 不读取 req.session / cookie, 成功缓存)
  function authenticateShare(req, share, callback) {
    var authHeader = req.headers['authorization'];
    var cacheKey = getAuthCacheKey(share.name, authHeader);
    if (checkAuthCache(cacheKey)) return callback(null, true);

    var auth = parseBasicAuth(authHeader);
    if (!auth) return callback(null, false);
    var usernameMatch = constantTimeEqualString(auth.username, share.username);
    if (!usernameMatch) return callback(null, false);

    scryptCallCount++;
    verifyPasswordAsync(auth.password, share.passwordHash, function (err, passwordMatch) {
      if (passwordMatch) setAuthCache(cacheKey); // 只缓存成功结果
      callback(null, passwordMatch);
    });
  }

  // 权限检查: GetNodeWithRights + Agent 在线
  function checkPermissions(share, callback) {
    var userid = share.runAsUser;
    // 验证 runAsUser 所属域: user/<domainid>/<username>
    var userDomain = null;
    var slashParts = userid.split('/');
    if (slashParts.length >= 2 && slashParts[0] === 'user') {
      userDomain = slashParts[1];
    }
    var expectedDomain = domain ? domain.id : '';
    if (userDomain !== expectedDomain) {
      return callback({ status: 403, message: 'Forbidden' });
    }
    var user = webserver.users[userid];
    if (!user || (user.siteadmin && user.siteadmin != 0xFFFFFFFF && (user.siteadmin & 32))) {
      return callback({ status: 403, message: 'Forbidden' });
    }
    if (typeof webserver.GetNodeWithRights !== 'function') {
      return callback({ status: 500, message: 'Server error' });
    }
    webserver.GetNodeWithRights(domain, user, share.nodeId, function (node, rights, visible) {
      if (!node || !visible) {
        return callback({ status: 404, message: 'Not Found' });
      }
      if (!(rights & 8)) {
        return callback({ status: 403, message: 'Forbidden' });
      }
      if (rights !== 0xFFFFFFFF && (rights & 0x400)) {
        return callback({ status: 403, message: 'Forbidden' });
      }
      if (!webserver.wsagents || !webserver.wsagents[share.nodeId]) {
        return callback({ status: 503, message: 'Agent offline' });
      }
      var mesh = webserver.meshes ? webserver.meshes[node.meshid] : null;
      callback(null, { user: user, node: node, rights: rights, mesh: mesh });
    });
  }

  // 构造 soptions (照 meshuser.js ~1076-1100, 传完整 consent/notification 消息)
  function buildSoptions() {
    var soptions = {};
    if (domain && typeof domain.consentmessages === 'object') {
      var cm = domain.consentmessages;
      if (typeof cm.title === 'string') soptions.consentTitle = cm.title;
      if (typeof cm.desktop === 'string') soptions.consentMsgDesktop = cm.desktop;
      if (typeof cm.terminal === 'string') soptions.consentMsgTerminal = cm.terminal;
      if (typeof cm.files === 'string') soptions.consentMsgFiles = cm.files;
      if (typeof cm.consenttimeout === 'number' && cm.consenttimeout > 0) soptions.consentTimeout = cm.consenttimeout;
      if (cm.autoacceptontimeout === true) soptions.consentAutoAccept = true;
      if (cm.autoacceptifnouser === true) soptions.consentAutoAcceptIfNoUser = true;
      if (cm.autoacceptifdesktopnouser === true) soptions.consentAutoAcceptIfDesktopNoUser = true;
      if (cm.autoacceptifterminalnouser === true) soptions.consentAutoAcceptIfTerminalNoUser = true;
      if (cm.autoacceptiffilenouser === true) soptions.consentAutoAcceptIfFileNoUser = true;
      if (cm.autoacceptiflocked === true) soptions.consentAutoAcceptIfLocked = true;
      if (cm.autoacceptifdesktoplocked === true) soptions.consentAutoAcceptIfDesktopLocked = true;
      if (cm.autoacceptifterminallocked === true) soptions.consentAutoAcceptIfTerminalLocked = true;
      if (cm.autoacceptiffilelocked === true) soptions.consentAutoAcceptIfFileLocked = true;
      if (cm.oldstyle === true) soptions.oldStyle = true;
    }
    if (domain && typeof domain.notificationmessages === 'object') {
      var nm = domain.notificationmessages;
      if (typeof nm.title === 'string') soptions.notifyTitle = nm.title;
      if (typeof nm.desktop === 'string') soptions.notifyMsgDesktop = nm.desktop;
      if (typeof nm.terminal === 'string') soptions.notifyMsgTerminal = nm.terminal;
      if (typeof nm.files === 'string') soptions.notifyMsgFiles = nm.files;
    }
    if (domain && typeof domain.terminaluservariable === 'string') soptions.terminalUserVariable = domain.terminaluservariable;
    return soptions;
  }

  // 构造 tunnelOptions (用于通知 Agent 回连)
  function buildTunnelOptions(ctx, req) {
    var user = ctx.user, node = ctx.node, mesh = ctx.mesh;
    var consent = 0;
    if (domain && typeof domain.userconsentflags === 'number') consent |= domain.userconsentflags;
    if (mesh && typeof mesh.consent === 'number') consent |= mesh.consent;
    if (node && typeof node.consent === 'number') consent |= node.consent;
    if (user && typeof user.consent === 'number') consent |= user.consent;
    // 用户组 consent (照搬 meshuser.js 逻辑)
    if (user && user.links && mesh && node) {
      if (user.links[mesh._id] == null && user.links[node._id] == null) {
        var linkKeys = Object.keys(user.links);
        for (var li = 0; li < linkKeys.length; li++) {
          var ugrp = webserver.userGroups ? webserver.userGroups[linkKeys[li]] : null;
          if (ugrp && ugrp.consent != null && ugrp.links && (ugrp.links[mesh._id] != null || ugrp.links[node._id] != null)) {
            consent |= ugrp.consent;
          }
        }
      }
    }
    var servertlshash = null;
    if (!(parent && parent.args && parent.args.ignoreagenthashcheck)) {
      var certHash = webserver.webCertificateFullHashs && webserver.webCertificateFullHashs[domain ? domain.id : ''];
      if (certHash) {
        servertlshash = Buffer.from(certHash, 'binary').toString('hex');
      }
    }
    return {
      domain: domain,
      rights: ctx.rights,
      consent: consent,
      username: (user && user.name) || '',
      realname: (user && user.realname) || '',
      userid: (user && user._id) || '',
      remoteaddr: getClientIp(req),
      servertlshash: servertlshash,
      soptions: buildSoptions(),
    };
  }

  // 策略指纹: 权限/consent/soptions/TLS 变化时需关旧隧道开新
  function computePolicyFingerprint(tunnelOptions) {
    var parts = [
      'r=' + tunnelOptions.rights,
      'c=' + tunnelOptions.consent,
      't=' + (tunnelOptions.servertlshash || ''),
    ];
    if (tunnelOptions.soptions) {
      var skeys = Object.keys(tunnelOptions.soptions).sort();
      for (var i = 0; i < skeys.length; i++) {
        parts.push(skeys[i] + '=' + tunnelOptions.soptions[skeys[i]]);
      }
    }
    return parts.join('|');
  }

  // 并发下载槽管理
  function acquireDownloadSlot(shareName, max) {
    var count = downloadCounters.get(shareName) || 0;
    if (count >= max) return false;
    downloadCounters.set(shareName, count + 1);
    return true;
  }

  function releaseDownloadSlot(shareName) {
    var count = downloadCounters.get(shareName) || 0;
    if (count <= 1) downloadCounters.delete(shareName);
    else downloadCounters.set(shareName, count - 1);
  }

  // ---- openTunnel: 通知 Agent 回连, 通过 pending 表匹配 WS ----
  // 返回 cancel 句柄；cancel 删 token 清 timer，迟到回连在 handleAgentTunnel 找不到 entry 被拒。
  function noopCancel() {}
  function openTunnel(nodeid, purpose, tunnelOptions, callback) {
    if (typeof openTunnelOverride === 'function') {
      var ret = openTunnelOverride(nodeid, purpose, tunnelOptions, callback);
      return (typeof ret === 'function') ? ret : noopCancel;
    }
    if (!webserver.wsagents || !webserver.wsagents[nodeid]) {
      callback(new Error('agent offline'));
      return noopCancel;
    }
    var token = crypto.randomBytes(16).toString('hex'); // 128bit
    var entry = { nodeid: nodeid, purpose: purpose, callback: callback, timer: null, cancelled: false };
    entry.timer = setTimeout(function () {
      if (pendingTunnels.has(token)) {
        pendingTunnels.delete(token);
        if (!entry.cancelled) callback(new Error('tunnel timeout'));
      }
    }, tunnelTimeoutMs); // 可配置过期
    pendingTunnels.set(token, entry);
    var domainUrl = (domain && domain.url) ? domain.url : '/';
    var tunnelUrl = '*' + domainUrl + 'davtunnel.ashx?id=' + token;
    var cmd = {
      action: 'msg', type: 'tunnel', value: tunnelUrl,
      rights: tunnelOptions.rights, consent: tunnelOptions.consent,
      username: tunnelOptions.username, realname: tunnelOptions.realname,
      userid: tunnelOptions.userid, remoteaddr: tunnelOptions.remoteaddr,
      servertlshash: tunnelOptions.servertlshash,
      soptions: Object.assign({}, tunnelOptions.soptions || {}, { usages: (purpose === 'download') ? [10] : [5] }),
    };
    try {
      webserver.wsagents[nodeid].send(JSON.stringify(cmd));
      debug('openTunnel', purpose);
    } catch (e) {
      if (pendingTunnels.has(token)) {
        pendingTunnels.delete(token);
        clearTimeout(entry.timer);
      }
      callback(new Error('send failed: ' + e.message));
      return noopCancel;
    }
    return function cancelTunnel() {
      if (entry.cancelled) return;
      entry.cancelled = true;
      if (pendingTunnels.has(token)) {
        pendingTunnels.delete(token);
        if (entry.timer) clearTimeout(entry.timer);
      }
    };
  }

  // ---- handleAgentTunnel: davtunnel.ashx WS 端点 ----
  function handleAgentTunnel(ws, req) {
    var id = null;
    try {
      var urlStr = req.url || '';
      var qIdx = urlStr.indexOf('?');
      if (qIdx >= 0) {
        var query = urlStr.slice(qIdx + 1);
        var idMatch = /(?:^|&)id=([^&]+)/.exec(query);
        if (idMatch) id = decodeURIComponent(idMatch[1]);
      }
    } catch (e) {}
    if (!id) {
      debug('tunnel: no id, closing');
      try { ws.close(); } catch (e) {}
      return;
    }
    var entry = pendingTunnels.get(id);
    if (!entry) {
      debug('tunnel: unknown id, closing');
      try { ws.close(); } catch (e) {}
      return;
    }
    pendingTunnels.delete(id);
    if (entry.timer) clearTimeout(entry.timer);
    debug('tunnel: connected', entry.purpose);
    entry.callback(null, ws);
  }

  // ---- 协议5 复用隧道管理器 (每 share 一个, 惰性建立) ----
  // refreshFn(callback): 每次 ls 前重新评估权限, 返回 (err, tunnelOptions, fingerprint)
  function createLsTunnelManager(share, refreshFn) {
    var state = 'idle'; // idle | connecting | connected | closed
    var tunnelWs = null;
    var reqidCounter = 1;
    var pendingRequests = new Map(); // reqid -> { resolve, reject, timer }
    var idleTimer = null;
    var connectQueue = [];
    var currentFingerprint = null;
    var generation = 0;
    var pendingCancel = null;
    var currentRefreshFn = refreshFn;

    function setRefreshFn(fn) { currentRefreshFn = fn; }

    function closeTunnelWs() {
      generation++; // 使 pending connect 回调失效
      var oldCancel = pendingCancel; pendingCancel = null;
      var oldWs = tunnelWs; tunnelWs = null;
      state = 'idle';
      failConnectQueue('tunnel closed');
      if (oldCancel) { try { oldCancel(); } catch (e) {} }
      if (oldWs) { try { oldWs.close(); } catch (e) {} }
    }

    function failAll(reason) {
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
      var keys = Array.from(pendingRequests.keys());
      for (var i = 0; i < keys.length; i++) {
        var p = pendingRequests.get(keys[i]);
        pendingRequests.delete(keys[i]);
        if (p.timer) clearTimeout(p.timer);
        p.reject(new Error(reason));
      }
    }

    function failConnectQueue(reason) {
      var queue = connectQueue;
      connectQueue = [];
      for (var i = 0; i < queue.length; i++) queue[i](new Error(reason));
    }

    function resetIdleTimer() {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(function () {
        idleTimer = null;
        if (pendingRequests.size === 0 && tunnelWs) {
          debug('ls: idle timeout, closing', share.name);
          var oldWs = tunnelWs;
          state = 'idle';
          tunnelWs = null; // 先置空, 旧 ws close 事件不会影响新连接
          currentFingerprint = null; // idle close → 下次 ls 重新评估
          try { oldWs.close(); } catch (e) {}
        }
      }, lsIdleMs);
    }

    function setupWsHandlers() {
      var thisWs = tunnelWs; // 捕获本次 ws
      // 协议5: 先发 'c'，再发 '5'
      try { thisWs.send('c'); } catch (e) {}
      try { thisWs.send('5'); } catch (e) {}
      thisWs.on('message', function (data, isBinary) {
        if (tunnelWs !== thisWs) return; // 旧 ws 事件忽略
        var text;
        if (typeof data === 'string') text = data;
        else if (isBinary === false) text = data.toString('utf8');
        else text = data.toString('utf8'); // 二进制帧含 JSON
        var msg;
        try { msg = JSON.parse(text); } catch (e) { return; }
        if (msg.reqid == null) return; // 忽略 ctrlChannel 控制消息
        var p = pendingRequests.get(msg.reqid);
        if (!p) return;
        pendingRequests.delete(msg.reqid);
        if (p.timer) clearTimeout(p.timer);
        p.resolve(msg);
        resetIdleTimer();
      });
      thisWs.on('close', function () {
        if (tunnelWs !== thisWs) return; // 旧 ws close 不影响新连接
        debug('ls: tunnel closed', share.name);
        failAll('tunnel closed');
        state = 'closed';
        tunnelWs = null;
      });
      thisWs.on('error', function (err) {
        if (tunnelWs !== thisWs) return;
        debug('ls: tunnel error', share.name, err);
        failAll('tunnel error');
        state = 'closed';
        tunnelWs = null;
      });
    }

    function ensureConnected(tunnelOptions, callback) {
      if (state === 'connected' && tunnelWs) {
        return callback(null, tunnelWs);
      }
      if (state === 'connecting') {
        connectQueue.push(callback);
        return;
      }
      state = 'connecting';
      generation++;
      var myGen = generation;
      connectQueue.push(callback);
      debug('ls: connecting', share.name);
      var myCancel = null;
      var ret = openTunnel(share.nodeId, 'ls', tunnelOptions, function (err, ws) {
        if (myGen !== generation) { if (ws) { try { ws.close(); } catch (e) {} } return; }
        pendingCancel = null;
        var queue = connectQueue;
        connectQueue = [];
        if (err) {
          state = 'idle';
          debug('ls: connect failed', share.name, err.message);
          for (var i = 0; i < queue.length; i++) queue[i](err);
          return;
        }
        var connectedWs = ws;
        tunnelWs = ws;
        state = 'connected';
        setupWsHandlers();
        debug('ls: connected', share.name);
        for (var j = 0; j < queue.length; j++) {
          if (myGen !== generation || state !== 'connected' || tunnelWs !== connectedWs) {
            for (var k = j; k < queue.length; k++) queue[k](new Error('tunnel closed'));
            return;
          }
          queue[j](null, connectedWs);
        }
      });
      myCancel = (typeof ret === 'function') ? ret : null;
      if (myGen === generation && state === 'connecting') {
        pendingCancel = myCancel;
      } else if (myCancel) {
        try { myCancel(); } catch (e) {}
      }
    }

    function ls(path, timeoutMs) {
      return new Promise(function (resolve, reject) {
        currentRefreshFn(function (err, tunnelOptions, fingerprint) {
          if (err) {
            // 权限拒绝 → failAll 已发 LS + 关闭旧隧道
            failAll('permission denied');
            closeTunnelWs();
            currentFingerprint = null;
            return reject(err);
          }
          // 指纹变化 → failAll 已发 LS + 关闭旧隧道再开
          if (currentFingerprint !== null && currentFingerprint !== fingerprint) {
            failAll('fingerprint changed');
            closeTunnelWs();
          }
          currentFingerprint = fingerprint;
          // 有效超时: consent 等待需覆盖 consentTimeout + 余量
          var effectiveTimeout = timeoutMs || lsTimeoutMs;
          if (tunnelOptions.consent & (32 | 4)) {
            var ct = (tunnelOptions.soptions && tunnelOptions.soptions.consentTimeout) || 30;
            effectiveTimeout = Math.max(effectiveTimeout, ct * 1000 + 5000);
          }
          ensureConnected(tunnelOptions, function (err, ws) {
            if (err) return reject(err);
            var reqid = reqidCounter++;
            var timer = setTimeout(function () {
              if (pendingRequests.has(reqid)) {
                pendingRequests.delete(reqid);
                reject(new Error('ls timeout'));
                resetIdleTimer();
              }
            }, effectiveTimeout);
            pendingRequests.set(reqid, { resolve: resolve, reject: reject, timer: timer });
            var cmd = JSON.stringify({ action: 'ls', reqid: reqid, path: path });
            try {
              ws.send(cmd);
              resetIdleTimer();
            } catch (e) {
              pendingRequests.delete(reqid);
              clearTimeout(timer);
              reject(new Error('send failed'));
              resetIdleTimer();
            }
          });
        });
      });
    }

    function close() {
      generation++;
      var oldCancel = pendingCancel; pendingCancel = null;
      var oldWs = tunnelWs; tunnelWs = null;
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
      state = 'closed';
      failAll('closing');
      failConnectQueue('closing');
      if (oldCancel) { try { oldCancel(); } catch (e) {} }
      if (oldWs) { try { oldWs.close(); } catch (e) {} }
    }

    return { ls: ls, close: close, setRefreshFn: setRefreshFn };
  }

  // 获取或创建 share 的 ls 隧道管理器
  function getLsTunnelManager(share, refreshFn) {
    var mgr = lsTunnelManagers.get(share.name);
    if (!mgr) {
      mgr = createLsTunnelManager(share, refreshFn);
      lsTunnelManagers.set(share.name, mgr);
    } else {
      mgr.setRefreshFn(refreshFn);
    }
    return mgr;
  }

  // ---- 协议10 下载隧道 (每次下载一个) ----
  // onReady(err, size): 收到 op:ok 或错误时调用(仅一次); 之后文件数据流式写入 res
  function downloadFile(share, remotePath, res, tunnelOptions, onReady) {
    var onReadyCalled = false;
    var finished = false;       // 终结清理只一次
    var ws = null;
    var progressTimer = null;
    var gotOk = false;
    var written = 0;
    var expectedSize = 0;
    var agentPaused = false;    // 背压 pause 标志, 避免把慢客户端等待误判为 Agent 停滞
    var cancelTunnel = null;
    var resCloseListener = null;

    function onReadyOnce(err, size) {
      if (onReadyCalled) return;
      onReadyCalled = true;
      onReady(err, size);
    }
    function clearProgress() { if (progressTimer) { clearTimeout(progressTimer); progressTimer = null; } }
    // 统一终结清理: cancel 句柄 + timer + res close 监听 + res end/destroy + ws close
    function finalize(ok) {
      if (finished) return;
      finished = true;
      clearProgress();
      if (typeof cancelTunnel === 'function') { try { cancelTunnel(); } catch (e) {} }
      if (resCloseListener) { try { res.removeListener('close', resCloseListener); } catch (e) {} }
      if (ok) { if (!res.writableEnded && !res.destroyed) res.end(); }
      else { if (!res.writableEnded && !res.destroyed) res.destroy(); }
      if (ws) { try { ws.close(); } catch (e) {} }
    }
    function finishOk() { finalize(true); }
    function finishError() { finalize(false); }
    // err 回连或取消: 清理隧道资源但不 destroy res, 保留 caller 发错误 HTTP 响应
    function failBeforeReady(err) {
      if (finished) { onReadyOnce(err); return; }
      finished = true;
      clearProgress();
      if (typeof cancelTunnel === 'function') { try { cancelTunnel(); } catch (e) {} }
      if (resCloseListener) { try { res.removeListener('close', resCloseListener); } catch (e) {} }
      if (ws) { try { ws.close(); } catch (e) {} }
      onReadyOnce(err);
    }

    // 开隧道前检查取消
    if (res.destroyed || res.writableEnded) {
      return onReadyOnce(new Error('cancelled'));
    }

    // 先注册 res close 监听, 再开隧道 (确保 openTunnel 同步回调期间 res close 不漏)
    resCloseListener = function () {
      if (typeof cancelTunnel === 'function') { try { cancelTunnel(); } catch (e) {} }
      if (ws) { try { ws.close(); } catch (e) {} }
      if (!finished) { finished = true; clearProgress(); }
    };
    res.on('close', resCloseListener);

    cancelTunnel = openTunnel(share.nodeId, 'download', tunnelOptions, function (err, connectedWs) {
      // 迟到回调 (已 finalize) → 拒绝, 不复活
      if (finished) { if (connectedWs) { try { connectedWs.close(); } catch (e) {} } return; }
      if (err) return failBeforeReady(err);
      ws = connectedWs;
      // 回连后再次检查取消 (客户端可能在等回连期间断开)
      if (res.destroyed || res.writableEnded) {
        return failBeforeReady(new Error('cancelled'));
      }
      // 先注册 WS 监听再 send 握手 (避免 Agent 同步回发消息漏掉)
      ws.on('message', onMessage);
      ws.on('close', onWsClose);
      ws.on('error', onWsError);
      // op:ok 等待超时; 收到数据后转为数据进度超时
      progressTimer = setTimeout(onProgressTimeout, downloadTimeoutMs);
      // 协议10: 发 'c'，发 JSON options，发 '10'
      try { ws.send('c'); } catch (e) {}
      try { ws.send(JSON.stringify({ type: 'options', file: remotePath })); } catch (e) {}
      try { ws.send('10'); } catch (e) {}
    });

    // 同步 override 回调可能已触发 finish, 此时 cancelTunnel 刚赋值, 需补调幂等清理
    if (finished && typeof cancelTunnel === 'function') {
      try { cancelTunnel(); } catch (e) {}
    }

    function onMessage(data, isBinary) {
      if (finished) return;
      var isText = (typeof data === 'string') || (isBinary === false);
      if (!gotOk) {
        // 收到 op 之前，把任何以 '{' 开头的消息当控制 JSON
        var text = typeof data === 'string' ? data : data.toString('utf8');
        if (text.length === 0 || text.charAt(0) !== '{') return;
        var msg;
        try { msg = JSON.parse(text); } catch (e) { return; }
        if (msg.op === 'ok') {
          // 严格校验 size 为非负安全整数
          if (typeof msg.size !== 'number' || !Number.isSafeInteger(msg.size) || msg.size < 0) {
            onReadyOnce(new Error('invalid size'));
            return finishError();
          }
          gotOk = true;
          expectedSize = msg.size;
          clearProgress();
          onReadyOnce(null, msg.size);
          // 空文件立即完成 (onReady 已 writeHead)
          if (expectedSize === 0) {
            finishOk();
          } else {
            progressTimer = setTimeout(onProgressTimeout, downloadTimeoutMs);
          }
        } else if (msg.op === 'cancel') {
          onReadyOnce(new Error('cancel'));
          finishError();
        }
      } else {
        // 收到 op:'ok' 后，只把二进制帧当文件数据，文本帧当控制消息
        if (!isText && isBinary !== false) {
          if (finished || res.destroyed || res.writableEnded) return;
          var buf = Buffer.from(data);
          // 超量 → 销毁
          if (written + buf.length > expectedSize) {
            return finishError();
          }
          // 先更新 written, 兼容 res.write 同步回调里 written===expectedSize 判定
          written += buf.length;
          // 背压: pause agent socket, res.write 回调里 resume (同 meshdevicefile.js)
          if (ws && ws._socket) { try { ws._socket.pause(); } catch (e) {} agentPaused = true; }
          res.write(buf, function () {
            // 先检查已终结, 不得 resume/复活已关连接
            if (finished || res.destroyed || res.writableEnded) return;
            if (ws && ws._socket) { try { ws._socket.resume(); } catch (e) {} }
            agentPaused = false;
            // 收齐 → 主动完成, 不依赖 Agent EOF/WS close
            if (written === expectedSize) {
              finishOk();
            } else {
              resetProgressTimer();
            }
          });
          // 收到数据重置进度超时 (Agent 有进展)
          resetProgressTimer();
        }
      }
    }

    function onProgressTimeout() {
      if (finished) return;
      if (agentPaused) {
        // 背压等待客户端消费, 不是 Agent 停滞 → 重置继续等
        progressTimer = setTimeout(onProgressTimeout, downloadTimeoutMs);
        return;
      }
      if (!gotOk) onReadyOnce(new Error('download timeout'));
      finishError();
    }
    function resetProgressTimer() {
      if (finished) return;
      clearProgress();
      progressTimer = setTimeout(onProgressTimeout, downloadTimeoutMs);
    }

    function onWsClose() {
      if (finished) return;
      clearProgress();
      if (!gotOk) {
        // op:ok 前关闭 → 502, 不要 res.end() 空正文
        onReadyOnce(new Error('tunnel closed'));
        finishError();
      } else if (written < expectedSize) {
        // 截断 → 销毁
        finishError();
      } else if (written === expectedSize) {
        // 收齐, 兜底完成 (正常情况 res.write 回调已 finishOk)
        finishOk();
      }
    }
    function onWsError() {
      if (finished) return;
      clearProgress();
      if (!gotOk) onReadyOnce(new Error('tunnel error'));
      finishError();
    }
  }

  // ---- HTTP 方法处理 ----
  var ALLOW_HEADER = { 'Allow': 'OPTIONS, PROPFIND, GET, HEAD' };

  function computeRemotePath(root, segments) {
    var rootTrimmed = root;
    while (rootTrimmed.length > 1 && rootTrimmed.charCodeAt(rootTrimmed.length - 1) === 47) {
      rootTrimmed = rootTrimmed.slice(0, -1);
    }
    if (segments.length === 0) return rootTrimmed;
    if (rootTrimmed.charCodeAt(rootTrimmed.length - 1) === 47) {
      return rootTrimmed + segments.join('/');
    }
    return rootTrimmed + '/' + segments.join('/');
  }

  function buildHref(shareName, segments, isCollection) {
    var base = (domain ? domain.url : '/') + 'dav/' + encodeURIComponent(shareName);
    if (segments.length === 0) return base + '/';
    for (var i = 0; i < segments.length; i++) {
      base += '/' + encodeURIComponent(segments[i]);
    }
    if (isCollection) base += '/';
    return base;
  }

  function dirEntryToPropfindEntry(shareName, parentSegments, item) {
    var isCollection = (item.t === 1 || item.t === 2);
    var segs = parentSegments.concat([item.n]);
    return {
      href: buildHref(shareName, segs, isCollection),
      displayname: item.n,
      isCollection: isCollection,
      size: (item.t === 3) ? item.s : undefined,
      mtime: item.d,
      name: item.n,
    };
  }

  function sendPropfindResponse(res, entries) {
    var body = buildPropfindXml(entries);
    var bodyBuf = Buffer.from(body, 'utf8');
    res.writeHead(207, withSecurityHeaders({
      'Content-Type': 'application/xml; charset="utf-8"',
      'Content-Length': bodyBuf.length,
    }));
    res.end(bodyBuf);
  }

  function drainBody(req, callback) {
    var total = 0;
    var finished = false;
    function done() {
      if (finished) return;
      finished = true;
      callback();
    }
    req.on('data', function (chunk) {
      total += chunk.length;
      if (total > 65536) { // 64KB 上限
        if (typeof req.pause === 'function') req.pause();
        done();
      }
    });
    req.on('end', done);
    req.on('error', done);
    if (req.complete) done();
  }

  // resolvePathTypeUnified: 统一判定路径类型
  // 真实 MeshAgent legacy getDirectoryInfo 对普通文件路径返回 { dir: [] } (空数组),
  // 只有路径不存在时返回 { dir: null }。因此不能仅用 ls(path).dir 判断目录 (空数组是 truthy)。
  // 对 segments.length>0 的路径, 以父目录 ls 中同名条目类型为准:
  //   t===1/2 → directory, t===3 → file, 不存在 → notfound。
  // 当 ls(path).dir 为非空数组时, 直接判定为目录并复用子项 (真实 Agent 对文件只返回空数组)。
  // 当 dir 为空数组或 null 时, 查父目录确认类型; 父目录确认是目录时复用第一次 ls 的子项。
  // share 根 (segments.length===0): dir 为数组即目录, null 即 notfound。
  // callback(err, { type, entry, dirListing })
  //   type: 'directory' | 'file' | 'notfound'
  //   entry: 父目录中同名条目 (file/directory 时), 根目录时 null
  //   dirListing: 目录自身的子项数组 (directory 时), 否则 null
  function resolvePathTypeUnified(mgr, share, segments, callback) {
    var remotePath = computeRemotePath(share.root, segments);
    mgr.ls(remotePath).then(function (result) {
      if (segments.length === 0) {
        if (Array.isArray(result.dir)) {
          return callback(null, { type: 'directory', entry: null, dirListing: result.dir });
        }
        return callback(null, { type: 'notfound', entry: null, dirListing: null });
      }
      // 非根: dir 为非空数组 → 确定是目录 (真实 Agent 对文件返回空数组)
      if (Array.isArray(result.dir) && result.dir.length > 0) {
        return callback(null, { type: 'directory', entry: null, dirListing: result.dir });
      }
      // dir 为空数组或 null: 查父目录确认类型
      var parentSegments = segments.slice(0, -1);
      var parentRemotePath = computeRemotePath(share.root, parentSegments);
      var lastName = segments[segments.length - 1];
      mgr.ls(parentRemotePath).then(function (parentResult) {
        if (!Array.isArray(parentResult.dir)) {
          return callback(null, { type: 'notfound', entry: null, dirListing: null });
        }
        var found = null;
        for (var i = 0; i < parentResult.dir.length; i++) {
          if (parentResult.dir[i].n === lastName) {
            found = parentResult.dir[i];
            break;
          }
        }
        if (!found) {
          return callback(null, { type: 'notfound', entry: null, dirListing: null });
        }
        if (found.t === 3) {
          return callback(null, { type: 'file', entry: found, dirListing: null });
        }
        // 父目录确认是目录 (t===1 或 t===2), 复用第一次 ls 的子项 (若为数组)
        var dirListing = Array.isArray(result.dir) ? result.dir : [];
        return callback(null, { type: 'directory', entry: found, dirListing: dirListing });
      }).catch(function (err) { callback(err); });
    }).catch(function (err) { callback(err); });
  }

  // resolvePathType: 确定路径是 directory/file/notfound (基于统一判定)
  // callback(err, { type, entry })
  function resolvePathType(mgr, share, segments, callback) {
    resolvePathTypeUnified(mgr, share, segments, function (err, info) {
      if (err) return callback(err);
      callback(null, { type: info.type, entry: info.entry });
    });
  }

  function handleOptions(req, res) {
    res.writeHead(200, withSecurityHeaders({
      'DAV': '1',
      'Allow': 'OPTIONS, PROPFIND, GET, HEAD',
      'MS-Author-Via': 'DAV',
      'Content-Length': '0',
    }));
    res.end();
  }

  function handleMethodNotAllowed(req, res) {
    sendError(res, 405, 'Method Not Allowed', ALLOW_HEADER);
  }

  function handlePropfind(req, res, share, ctx, pathInfo, refreshFn) {
    var depth = req.headers['depth'];
    if (depth && String(depth).trim().toLowerCase() === 'infinity') {
      res.writeHead(403, withSecurityHeaders({ 'Content-Type': 'application/xml; charset="utf-8"' }));
      res.end('<?xml version="1.0" encoding="utf-8"?>\n<D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>\n');
      return;
    }
    depth = depth ? String(depth).trim() : '1';
    var depth1 = (depth !== '0');

    drainBody(req, function () {
      doPropfind(req, res, share, ctx, pathInfo, refreshFn, depth1);
    });
  }

  function doPropfind(req, res, share, ctx, pathInfo, refreshFn, depth1) {
    var mgr = getLsTunnelManager(share, refreshFn);
    var segments = pathInfo.segments;
    var remotePath = pathInfo.remotePath;

    if (segments.length === 0) {
      // share 根
      mgr.ls(remotePath).then(function (result) {
        if (!result.dir) {
          return sendError(res, 404, 'Not Found');
        }
        var entries = [{
          href: buildHref(share.name, [], true),
          displayname: share.name,
          isCollection: true,
          name: share.name,
        }];
        if (depth1 && Array.isArray(result.dir)) {
          for (var i = 0; i < result.dir.length; i++) {
            entries.push(dirEntryToPropfindEntry(share.name, [], result.dir[i]));
          }
        }
        sendPropfindResponse(res, entries);
      }).catch(function (err) {
        debug('PROPFIND root ls error', err.message);
        sendLsError(res, err);
      });
      return;
    }

    // 非根: 用统一路径类型判定 (修复真实 Agent 对文件路径返回 dir:[] 的 bug)
    resolvePathTypeUnified(mgr, share, segments, function (err, info) {
      if (err) {
        debug('PROPFIND resolve error', err.message);
        return sendLsError(res, err);
      }
      if (info.type === 'notfound') {
        return sendError(res, 404, 'Not Found');
      }
      if (info.type === 'file') {
        var found = info.entry;
        return sendPropfindResponse(res, [{
          href: buildHref(share.name, segments, false),
          displayname: found.n,
          isCollection: false,
          size: found.s,
          mtime: found.d,
          name: found.n,
        }]);
      }
      // directory
      var entries = [{
        href: buildHref(share.name, segments, true),
        displayname: segments[segments.length - 1],
        isCollection: true,
        name: segments[segments.length - 1],
      }];
      if (depth1 && Array.isArray(info.dirListing)) {
        for (var i = 0; i < info.dirListing.length; i++) {
          entries.push(dirEntryToPropfindEntry(share.name, segments, info.dirListing[i]));
        }
      }
      sendPropfindResponse(res, entries);
    });
  }

  function handleHead(req, res, share, ctx, pathInfo, refreshFn) {
    var segments = pathInfo.segments;
    var remotePath = pathInfo.remotePath;
    var mgr = getLsTunnelManager(share, refreshFn);

    if (segments.length === 0) {
      // share 根
      mgr.ls(remotePath).then(function (result) {
        if (result.dir) {
          res.writeHead(200, withSecurityHeaders({ 'Content-Type': 'text/plain', 'Content-Length': '0' }));
          res.end();
        } else {
          sendError(res, 404, 'Not Found');
        }
      }).catch(function (err) {
        debug('HEAD root ls error', err.message);
        sendLsError(res, err);
      });
      return;
    }

    // 非根: 用统一路径类型判定 (修复真实 Agent 对文件路径返回 dir:[] 的 bug)
    resolvePathTypeUnified(mgr, share, segments, function (err, info) {
      if (err) {
        debug('HEAD resolve error', err.message);
        return sendLsError(res, err);
      }
      if (info.type === 'notfound') {
        return sendError(res, 404, 'Not Found');
      }
      if (info.type === 'directory') {
        res.writeHead(200, withSecurityHeaders({ 'Content-Type': 'text/plain', 'Content-Length': '0' }));
        return res.end();
      }
      // file
      var found = info.entry;
      var size = found.s || 0;
      var headers = withSecurityHeaders({
        'Content-Length': String(size),
        'Content-Type': contentTypeFor(found.n),
        'Accept-Ranges': 'none',
        'Content-Disposition': safeContentDisposition(found.n),
      });
      if (found.d != null) {
        var u = new Date(found.d).toUTCString();
        if (u && u !== 'Invalid Date') headers['Last-Modified'] = u;
        headers['ETag'] = 'W/"' + size + '-' + new Date(found.d).getTime() + '"';
      }
      res.writeHead(200, headers);
      res.end();
    });
  }

  function handleGet(req, res, share, ctx, pathInfo, refreshFn) {
    var segments = pathInfo.segments;
    var remotePath = pathInfo.remotePath;
    var mgr = getLsTunnelManager(share, refreshFn);

    resolvePathType(mgr, share, segments, function (err, info) {
      if (res.destroyed || res.writableEnded) return; // 客户端在 ls 期间断开
      if (err) {
        debug('GET resolve error', err.message);
        return sendLsError(res, err);
      }
      if (info.type === 'notfound') {
        return sendError(res, 404, 'Not Found');
      }
      if (info.type === 'directory') {
        return sendError(res, 405, 'Method Not Allowed', ALLOW_HEADER);
      }
      // 文件: 路径解析完成后, 真正开 download 前再次权限/consent 检查
      refreshFn(function (permErr, freshTunnelOptions, fingerprint) {
        if (res.destroyed || res.writableEnded) return;
        if (permErr) {
          return sendError(res, permErr.status, permErr.message);
        }
        // 协议10 不检查 consent → fail closed: 有效 consent 带 (32|4) 时禁止下载
        if (freshTunnelOptions.consent & (32 | 4)) {
          return sendError(res, 403, 'Forbidden');
        }

        var found = info.entry;
        var size = found.s || 0;

        // Range 策略
        var rangeResult = evaluateRange(req.headers['range'], size);
        if (rangeResult.status === 416) {
          return sendError(res, 416, 'Range Not Satisfiable', {
            'Content-Range': rangeResult.contentRange,
            'Accept-Ranges': 'none',
          });
        }

        // 占槽前再次检查取消
        if (res.destroyed || res.writableEnded) return;
        // 并发上限
        if (!acquireDownloadSlot(share.name, share.maxDownloads)) {
          return sendError(res, 503, 'Service Unavailable', { 'Retry-After': '5' });
        }
        var slotReleased = false;
        function releaseSlot() {
          if (!slotReleased) {
            slotReleased = true;
            releaseDownloadSlot(share.name);
          }
        }
        res.on('close', releaseSlot);
        res.on('finish', releaseSlot);

        // 文件头
        var headers = withSecurityHeaders({
          'Content-Type': contentTypeFor(found.n),
          'Accept-Ranges': 'none',
          'Content-Disposition': safeContentDisposition(found.n),
        });
        if (found.d != null) {
          var u = new Date(found.d).toUTCString();
          if (u && u !== 'Invalid Date') headers['Last-Modified'] = u;
          headers['ETag'] = 'W/"' + size + '-' + new Date(found.d).getTime() + '"';
        }

        // 审计日志 (不记录凭证)
        try {
          if (parent && typeof parent.DispatchEvent === 'function') {
            parent.DispatchEvent(['*', ctx.user._id], webserver, {
              etype: 'relay', action: 'relaylog',
              domain: domain ? domain.id : '', userid: ctx.user._id,
              username: ctx.user.name,
              msg: 'Read-only DAV download "' + remotePath + '"',
              protocol: 10, nodeid: share.nodeId,
            });
          }
        } catch (e) {}

        // 协议10 下载隧道流式输出 (用 fresh tunnelOptions)
        downloadFile(share, remotePath, res, freshTunnelOptions, function (dlErr, dlSize) {
          if (dlErr) {
            releaseSlot();
            if (!res.headersSent && !res.destroyed && !res.writableEnded) {
              if (dlErr.message === 'cancel') {
                sendError(res, 404, 'Not Found');
              } else if (dlErr.message === 'download timeout') {
                sendError(res, 504, 'Gateway Timeout');
              } else if (dlErr.message === 'agent offline') {
                sendError(res, 503, 'Agent offline');
              } else {
                sendError(res, 502, 'Bad Gateway');
              }
            } else if (!res.destroyed && !res.writableEnded) {
              res.destroy();
            }
            return;
          }
          // op:ok → 写头, 之后文件数据流式写入 res
          if (res.destroyed || res.writableEnded) { releaseSlot(); return; }
          headers['Content-Length'] = String(dlSize);
          res.writeHead(200, headers);
        });
      });
    });
  }

  // ---- handleRequest: HTTP 入口 ----
  function handleRequest(req, res, next) {
    req.meshdav = true;

    // 尽早建立请求取消状态, 贯穿异步认证/权限/ls/下载占槽与等回连
    var aborted = false;
    res.on('close', function () { aborted = true; });
    function gone() { return aborted || res.destroyed || res.writableEnded; }

    // 提取 share 名和剩余路径
    var pathStr = req.path || req.url || '';
    var qIdx = pathStr.indexOf('?');
    if (qIdx >= 0) pathStr = pathStr.slice(0, qIdx);

    var sp = extractShareAndPath(pathStr);
    if (sp.error) {
      return sendError(res, 400, 'Bad Request');
    }
    // 解析 Basic auth 获取 username（用于限流和 setbadLogin）
    var ip = getClientIp(req);
    var parsedAuth = parseBasicAuth(req.headers['authorization']);
    var authUsername = parsedAuth ? parsedAuth.username : '';

    // 限流检查
    if (webserver.checkAllowLogin && !webserver.checkAllowLogin(ip, authUsername)) {
      return sendError(res, 429, 'Too Many Requests');
    }

    if (!sp.share || !shares[sp.share]) {
      // 未知 share → 对假 hash 跑异步 scrypt 消除时间差, 计入 setbadLogin, 然后 401
      var dummyPassword = parsedAuth ? parsedAuth.password : '';
      verifyPasswordAsync(dummyPassword, dummyHash, function () {
        if (gone()) return;
        if (webserver.setbadLogin) webserver.setbadLogin(ip, authUsername);
        sendAuthRequired(res);
      });
      return;
    }
    var share = shares[sp.share];

    // Basic 认证 (异步, 不读取 req.session / cookie)
    authenticateShare(req, share, function (authErr, authOk) {
      if (gone()) return;
      if (!authOk) {
        if (webserver.setbadLogin) webserver.setbadLogin(ip, authUsername);
        return sendAuthRequired(res);
      }

      // 路径解析
      var pathInfo;
      try {
        pathInfo = parseDavPath(sp.rest, share.root);
      } catch (e) {
        return sendError(res, 400, 'Bad Request');
      }

      // 权限检查 (异步)
      checkPermissions(share, function (permErr, ctx) {
        if (gone()) return;
        if (permErr) {
          var oldMgr = lsTunnelManagers.get(share.name);
          if (oldMgr) { try { oldMgr.close(); } catch (e) {} lsTunnelManagers.delete(share.name); }
          return sendError(res, permErr.status, permErr.message);
        }

        // refreshFn: 每次 ls / download 前重新评估权限, 返回 (err, tunnelOptions, fingerprint)
        var refreshFn = function (callback) {
          checkPermissions(share, function (err, ctx2) {
            if (err) return callback(err);
            var tunnelOptions = buildTunnelOptions(ctx2, req);
            var fingerprint = computePolicyFingerprint(tunnelOptions);
            callback(null, tunnelOptions, fingerprint);
          });
        };

        // 方法分发
        var method = (req.method || 'GET').toUpperCase();
        switch (method) {
          case 'OPTIONS':
            handleOptions(req, res);
            break;
          case 'PROPFIND':
            handlePropfind(req, res, share, ctx, pathInfo, refreshFn);
            break;
          case 'HEAD':
            handleHead(req, res, share, ctx, pathInfo, refreshFn);
            break;
          case 'GET':
            handleGet(req, res, share, ctx, pathInfo, refreshFn);
            break;
          default:
            handleMethodNotAllowed(req, res);
            break;
        }
      });
    });
  }

  return {
    handleRequest: handleRequest,
    handleAgentTunnel: handleAgentTunnel,
    _testHooks: {
      authCache: authCache,
      dummyHash: dummyHash,
      scryptCallCount: function () { return scryptCallCount; },
      lsTunnelManagers: lsTunnelManagers,
      shares: shares,
      safeContentDisposition: safeContentDisposition,
    },
  };
}

// ---------------------------------------------------------------------------
// module.exports
// ---------------------------------------------------------------------------
module.exports = {
  CreateMeshDav: CreateMeshDav,
  parseBasicAuth: parseBasicAuth,
  hashPassword: hashPassword,
  verifyPassword: verifyPassword,
  verifyPasswordAsync: verifyPasswordAsync,
  parseDavPath: parseDavPath,
  evaluateRange: evaluateRange,
  buildPropfindXml: buildPropfindXml,
};

// ---------------------------------------------------------------------------
// CLI: node meshdav.js hash (从 stdin 读密码, 不放命令参数)
// ---------------------------------------------------------------------------
if (require.main === module && process.argv[2] === 'hash') {
  var cliData = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', function (chunk) { cliData += chunk; });
  process.stdin.on('end', function () {
    var password = cliData.replace(/\r?\n$/, '');
    process.stdout.write(hashPassword(password) + '\n');
  });
}
