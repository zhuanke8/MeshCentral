/**
* @description MeshCentral WebDAV gateway. Exposes the file system of MeshAgent managed devices
*              over WebDAV (alist, rclone, RaiDrive, Windows Explorer, Finder, browsers...).
*              The server asks the agent to open a reverse tunnel back to the server
*              (webdavrelay.ashx) and then speaks the agent "remote files" protocol (protocol 5)
*              directly. No inbound port is needed on the device and the agent is not modified.
* @license Apache-2.0
*/

/*jslint node: true */
/*jshint node: true */
/*jshint strict:false */
/*jshint -W097 */
/*jshint esversion: 8 */
'use strict';

module.exports.CreateWebDav = function (parent) {
    const obj = {};
    const crypto = require('crypto');
    const PassThrough = require('stream').PassThrough;
    const pass = require('../pass.js');

    const MESHRIGHT_REMOTECONTROL = 0x00000008;
    const MESHRIGHT_NOFILES = 0x00000400;
    const MESHRIGHT_ADMIN = 0xFFFFFFFF;
    const SITERIGHT_LOCKED = 0x00000020;
    const DBTYPE = 'webdavaccount';
    const WINDOWS_AGENT_IDS = [1, 2, 3, 4, 21, 22, 34, 42, 43];
    const USERNAME_REGEX = /^[A-Za-z0-9][A-Za-z0-9._@-]{2,63}$/;

    // Tunables, can be overridden with "settings": { "webdav": { ... } } in config.json
    const CFG = Object.assign({
        maxTunnelsPerDevice: 3,      // Concurrent agent tunnels per account and device
        tunnelConnectTimeout: 45000, // Time for the agent to connect back (includes a possible user consent prompt)
        tunnelIdleTimeout: 60000,    // Idle agent tunnels are closed after this time
        commandTimeout: 30000,       // Agent command / transfer inactivity timeout
        listCacheTime: 4000,         // Directory listing cache
        deviceCacheTime: 15000,      // Account device list cache
        authCacheTime: 300000,       // Successful Basic auth cache, avoids running PBKDF2 on every request
        downloadWindow: 16,          // Download blocks (16k) in flight
        uploadBlockSize: 65536,
        uploadWindow: 8,             // Upload blocks in flight
        maxAccountsPerUser: 50,
        maxFailedLogins: 10,         // Failed Basic auth attempts per IP before blocking
        failedLoginWindow: 600000
    }, ((parent.config != null) && (parent.config.settings != null) && (typeof parent.config.settings.webdav == 'object')) ? parent.config.settings.webdav : {});

    function web() { return parent.webserver; }
    function debug(msg) { try { parent.debug('webdav', msg); } catch (ex) { } }
    function randomId() { return crypto.randomBytes(16).toString('hex'); }
    function userError(id, message) { const e = new Error(message); e.errorId = id; return e; } // Panel errors, id is translated by the web page
    function httpError(status, message) { const e = new Error(message || ('HTTP ' + status)); e.status = status; return e; }

    // ===================================================================================
    // Account storage
    // Record: { _id:'webdav/<domain>/<username>', type, domain, username, owner, salt, hash,
    //           readOnly, allDevices, deviceIds[], rootPath, enabled, created, updated }
    // The account works as an "app password" of its owner: it never has more rights than the owner.
    // ===================================================================================
    const accountCache = new Map(); // _id -> { t, doc }
    const lastUsed = new Map();     // _id -> time

    function accountKey(domainid, username) { return 'webdav/' + domainid + '/' + String(username).toLowerCase(); }
    function dbGet(id) { return new Promise(function (resolve) { parent.db.Get(id, function (err, docs) { resolve(((err == null) && (docs != null) && (docs.length == 1)) ? docs[0] : null); }); }); }
    function dbSet(doc) { return new Promise(function (resolve) { parent.db.Set(doc, function () { resolve(); }); }); }
    function dbRemove(id) { return new Promise(function (resolve) { parent.db.Remove(id, function () { resolve(); }); }); }
    function dbGetAllType(type) { return new Promise(function (resolve) { parent.db.GetAllType(type, function (err, docs) { resolve(((err == null) && Array.isArray(docs)) ? docs : []); }); }); }

    async function getAccount(domainid, username) {
        const id = accountKey(domainid, username);
        const c = accountCache.get(id);
        if ((c != null) && (c.t > Date.now())) { return c.doc; }
        const doc = await dbGet(id);
        accountCache.set(id, { t: Date.now() + 10000, doc: doc });
        return doc;
    }

    function invalidateAccount(id) {
        accountCache.delete(id);
        deviceCache.delete(id);
        for (const [k, v] of authCache) { if (v.id == id) { authCache.delete(k); } }
        closeAccountTunnels(id);
    }

    function hashPassword(password) {
        return new Promise(function (resolve, reject) { pass.hash(password, function (err, salt, hash) { if (err) { reject(err); } else { resolve({ salt: salt, hash: hash }); } }); });
    }
    function verifyPassword(password, salt, hash) {
        return new Promise(function (resolve) {
            pass.hash(password, salt, function (err, h) {
                if (err || (typeof h != 'string') || (typeof hash != 'string') || (h.length != hash.length)) { resolve(false); return; }
                resolve(crypto.timingSafeEqual(Buffer.from(h), Buffer.from(hash)));
            }, 0);
        });
    }

    // Root path restriction, stored as normalized segments joined by '/'
    function normalizeRootPath(p) {
        if ((p == null) || (p === '')) return '';
        if ((typeof p != 'string') || (p.length > 1024)) throw userError(9, 'Invalid root folder');
        const segs = p.split(/[\/\\]+/).filter(function (s) { return s.length > 0; });
        for (const s of segs) { if ((s == '.') || (s == '..') || (s.indexOf('\0') >= 0)) throw userError(9, 'Invalid root folder'); }
        return segs.join('/');
    }
    function rootSegments(account) { return ((typeof account.rootPath == 'string') && (account.rootPath.length > 0)) ? account.rootPath.split('/') : []; }
    function displayRootPath(rp) { if (!rp) return ''; return /^[A-Za-z]:/.test(rp) ? rp : ('/' + rp); }

    // ===================================================================================
    // Rights, devices
    // ===================================================================================
    function getOwner(account) {
        const u = web().users[account.owner];
        if (u == null) return null;
        if ((u.siteadmin != null) && (u.siteadmin != MESHRIGHT_ADMIN) && ((u.siteadmin & SITERIGHT_LOCKED) != 0)) return null; // Locked account
        return u;
    }

    function fileRights(user, node) {
        if ((user == null) || (node == null) || (node.mtype != 2) || (typeof node.meshid != 'string')) return 0;
        const r = web().GetNodeRights(user, node.meshid, node._id);
        if ((r & MESHRIGHT_REMOTECONTROL) == 0) return 0;
        if ((r != MESHRIGHT_ADMIN) && ((r & MESHRIGHT_NOFILES) != 0)) return 0;
        return r;
    }

    function isWindowsNode(node) { return (node.agent != null) && (WINDOWS_AGENT_IDS.indexOf(node.agent.id) >= 0); }

    // All agent devices this user can use remote files on
    function getUserFileNodes(user, domain) {
        return new Promise(function (resolve) {
            const meshIds = web().GetAllMeshIdWithRights(user);
            var extraids = null;
            if (user.links != null) {
                for (var i in user.links) {
                    if (i.startsWith('node/')) { if (extraids == null) { extraids = []; } extraids.push(i); }
                    else if (i.startsWith('ugrp/')) {
                        const g = web().userGroups[i];
                        if ((g != null) && (g.links != null)) { for (var j in g.links) { if (j.startsWith('node/')) { if (extraids == null) { extraids = []; } extraids.push(j); } } }
                    }
                }
            }
            parent.db.GetAllTypeNoTypeFieldMeshFiltered(meshIds, extraids, domain.id, 'node', null, 0, 0, null, function (err, docs) {
                if ((err != null) || !Array.isArray(docs)) { resolve([]); return; }
                resolve(docs.filter(function (n) { return fileRights(user, n) != 0; }));
            });
        });
    }

    function sanitizeFolderName(n) {
        n = String(n || '').replace(/[\/\\\x00-\x1f:*?"<>|]/g, '_').trim();
        if ((n == '') || (n == '.') || (n == '..')) { n = 'device'; }
        return n.substring(0, 100);
    }

    // Folder names shown at the WebDAV root, one per device, made unique
    function assignFolders(nodes) {
        nodes.sort(function (a, b) { const x = String(a.name || '').localeCompare(String(b.name || '')); return (x != 0) ? x : a._id.localeCompare(b._id); });
        const counts = {};
        for (const n of nodes) { const f = sanitizeFolderName(n.name).toLowerCase(); counts[f] = (counts[f] || 0) + 1; }
        return nodes.map(function (n) {
            var f = sanitizeFolderName(n.name);
            if (counts[f.toLowerCase()] > 1) { f += ' (' + n._id.split('/')[2].substring(0, 6).replace(/[@$]/g, '_') + ')'; }
            return { folder: f, node: n };
        });
    }

    const deviceCache = new Map(); // account._id -> { t, list }
    async function getAccountDevices(account, user, domain) {
        const c = deviceCache.get(account._id);
        if ((c != null) && (c.t > Date.now())) return c.list;
        var nodes;
        if (account.allDevices === true) {
            nodes = await getUserFileNodes(user, domain);
        } else {
            const ids = Array.isArray(account.deviceIds) ? account.deviceIds : [];
            nodes = (await Promise.all(ids.map(dbGet))).filter(function (n) { return (n != null) && (n.domain == domain.id) && (fileRights(user, n) != 0); });
        }
        const list = assignFolders(nodes);
        deviceCache.set(account._id, { t: Date.now() + CFG.deviceCacheTime, list: list });
        return list;
    }

    // ===================================================================================
    // Agent tunnel sessions (protocol 5 = remote files)
    // ===================================================================================
    const pools = new Map();          // account._id|nodeid -> pool
    const pendingTunnels = new Map(); // tunnel id -> session waiting for the agent to connect

    function getPool(ctx, dev) {
        const key = ctx.account._id + '|' + dev.node._id;
        var pool = pools.get(key);
        if (pool == null) { pool = { key: key, accountId: ctx.account._id, nodeid: dev.node._id, sessions: [], waiters: [] }; pools.set(key, pool); }
        pool.ctx = { account: ctx.account, user: ctx.user, domain: ctx.domain, node: dev.node, clientIp: ctx.clientIp };
        return pool;
    }

    function closeAccountTunnels(accountId) {
        for (const pool of Array.from(pools.values())) {
            if (pool.accountId != accountId) continue;
            for (const w of pool.waiters.splice(0)) { clearTimeout(w.timer); w.reject(httpError(503, 'Account changed')); }
            for (const s of pool.sessions.slice()) { s.close(); }
        }
    }

    function TunnelSession(pool) {
        const s = this;
        s.pool = pool;
        s.id = randomId();
        s.ws = null;
        s.state = 0;       // 0 = connecting, 1 = open, 2 = closed
        s.busy = false;
        s.dirty = false;   // Agent stream state is uncertain, do not reuse this tunnel
        s.handler = null;  // Current operation: { json(msg), binary(buf), fail(err) }
        s.idleTimer = null;

        s.open = function () {
            return new Promise(function (resolve, reject) {
                const c = pool.ctx, node = c.node, domain = c.domain, user = c.user;
                const agent = web().wsagents[node._id];
                if (agent == null) { reject(httpError(503, 'Device is offline')); return; }
                const rights = fileRights(user, node);
                if (rights == 0) { reject(httpError(403, 'No file access rights on this device')); return; }
                const mesh = web().meshes[node.meshid];
                const command = {
                    action: 'msg', type: 'tunnel',
                    value: '*' + domain.url + 'webdavrelay.ashx?id=' + s.id,
                    rights: rights,
                    consent: ((mesh != null) && (typeof mesh.consent == 'number')) ? mesh.consent : 0,
                    username: user.name,
                    realname: user.realname ? user.realname : user.name,
                    userid: user._id,
                    guestname: 'WebDAV ' + c.account.username,
                    remoteaddr: c.clientIp,
                    soptions: { usages: [5] }
                };
                if (typeof domain.userconsentflags == 'number') { command.consent |= domain.userconsentflags; }
                if (typeof domain.consentmessages == 'object') {
                    const cm = domain.consentmessages;
                    if (typeof cm.title == 'string') { command.soptions.consentTitle = cm.title; }
                    if (typeof cm.files == 'string') { command.soptions.consentMsgFiles = cm.files; }
                    if ((typeof cm.consenttimeout == 'number') && (cm.consenttimeout > 0)) { command.soptions.consentTimeout = cm.consenttimeout; }
                    if (cm.autoacceptontimeout === true) { command.soptions.consentAutoAccept = true; }
                    if (cm.autoacceptifnouser === true) { command.soptions.consentAutoAcceptIfNoUser = true; }
                    if (cm.autoacceptiffilenouser === true) { command.soptions.consentAutoAcceptIfFileNoUser = true; }
                    if (cm.autoacceptiflocked === true) { command.soptions.consentAutoAcceptIfLocked = true; }
                    if (cm.autoacceptiffilelocked === true) { command.soptions.consentAutoAcceptIfFileLocked = true; }
                }
                if ((parent.args.ignoreagenthashcheck == null) || (parent.args.ignoreagenthashcheck === false)) {
                    const tlsCertHash = (web().webCertificateFullHashs != null) ? web().webCertificateFullHashs[domain.id] : null;
                    if (tlsCertHash != null) { command.servertlshash = Buffer.from(tlsCertHash, 'binary').toString('hex'); }
                }
                s.openResolve = resolve;
                s.openTimer = setTimeout(function () { s.close(); reject(httpError(504, 'Device did not open a tunnel in time (offline, or file access consent not granted)')); }, CFG.tunnelConnectTimeout);
                pendingTunnels.set(s.id, s);
                try { agent.send(JSON.stringify(command)); } catch (ex) { clearTimeout(s.openTimer); pendingTunnels.delete(s.id); reject(httpError(503, 'Unable to contact device')); return; }
                debug('Tunnel ' + s.id + ' requested to ' + node._id);
            });
        };

        s.attach = function (ws) {
            clearTimeout(s.openTimer);
            if (s.state != 0) { try { ws.close(); } catch (ex) { } return; }
            s.ws = ws;
            s.state = 1;
            try { ws._socket.setKeepAlive(true, 240000); } catch (ex) { }
            ws.on('message', function (data) { s.onData(data); });
            ws.on('close', function () { s.onClosed(); });
            ws.on('error', function () { s.onClosed(); });
            try { ws.send('c'); ws.send('5'); } catch (ex) { } // Connect, then select protocol 5 (remote files)
            debug('Tunnel ' + s.id + ' connected');
            s.openResolve(s);
        };

        s.onData = function (data) {
            if (!Buffer.isBuffer(data)) { data = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data); }
            if (data.length == 0) return;
            if (data[0] == 123) { // JSON, sent as text or binary frames by the agent
                var msg = null;
                try { msg = JSON.parse(data.toString('utf8')); } catch (ex) { return; }
                if ((msg == null) || (typeof msg != 'object')) return;
                if (msg.ctrlChannel == '102938') { debug('Tunnel ' + s.id + ' control: ' + JSON.stringify(msg)); return; } // Consent prompts, etc.
                if (s.handler && s.handler.json) { s.handler.json(msg); }
            } else if (s.handler && s.handler.binary) {
                s.handler.binary(data);
            }
        };

        s.onClosed = function () {
            if (s.state == 2) return;
            s.state = 2;
            clearTimeout(s.idleTimer);
            clearTimeout(s.openTimer);
            pendingTunnels.delete(s.id);
            const i = pool.sessions.indexOf(s);
            if (i >= 0) { pool.sessions.splice(i, 1); }
            if (s.handler && s.handler.fail) { const h = s.handler; s.handler = null; h.fail(httpError(503, 'Device tunnel closed')); }
            debug('Tunnel ' + s.id + ' closed');
            pumpWaiters(pool);
        };

        s.close = function () {
            if (s.ws != null) { try { s.ws.close(); } catch (ex) { } }
            s.onClosed();
        };

        s.sendJson = function (o) { if (s.state != 1) throw httpError(503, 'Device tunnel closed'); s.ws.send(JSON.stringify(o)); };
        s.sendBinary = function (b) { if (s.state != 1) throw httpError(503, 'Device tunnel closed'); s.ws.send(b); };

        // Run one operation until "finish" is called. The inactivity timeout is reset with "touch".
        s.run = function (setup) {
            return new Promise(function (resolve, reject) {
                var finished = false, timer = null;
                function touch() { clearTimeout(timer); timer = setTimeout(function () { s.dirty = true; finish(httpError(504, 'Device did not respond in time')); }, CFG.commandTimeout); }
                function finish(err, result) {
                    if (finished) return;
                    finished = true;
                    clearTimeout(timer);
                    s.handler = null;
                    if (err) { reject(err); } else { resolve(result); }
                }
                s.handler = { fail: function (err) { finish(err); } };
                touch();
                try { setup(s.handler, touch, finish); } catch (ex) { finish(ex); }
            });
        };

        // List a folder. Returns the entry array, or null if the folder does not exist.
        s.ls = function (path) {
            return s.run(function (h, touch, finish) {
                const reqid = randomId();
                h.json = function (m) { if (m.reqid === reqid) { finish(null, Array.isArray(m.dir) ? m.dir : null); } };
                s.sendJson({ action: 'ls', reqid: reqid, path: path });
            });
        };

        // Commands the agent does not answer (mkdir, rm, rename, copy). Order is kept in the tunnel,
        // so a following "ls" tells when they are done.
        s.fire = function (cmd) { cmd.reqid = randomId(); s.sendJson(cmd); };

        // Download a file into sink: { write(buf) -> bool, onDrain(fn), aborted() -> bool, setStart(offset) }
        // The agent sends one 16k block per "ack", we keep "downloadWindow" acks outstanding.
        // range { offset, length } asks the agent to read only part of the file. Agents running an older
        // meshcore ignore it and send the whole file: sink.setStart() is then not called and data starts at 0.
        s.download = function (path, sink, range) {
            return s.run(function (h, touch, finish) {
                const id = randomId();
                var started = false, total = 0;
                function ack() { if (s.state == 1) { try { s.sendJson({ action: 'download', sub: 'ack', id: id }); } catch (ex) { } } }
                function abort(err) { try { s.sendJson({ action: 'download', sub: 'stop', id: id }); } catch (ex) { } s.dirty = true; finish(err); }
                h.json = function (m) {
                    if ((m.action != 'download') || (m.id != id)) return;
                    touch();
                    if (m.sub == 'start') {
                        started = true;
                        if ((m.partial == 1) && (typeof m.offset == 'number') && (typeof sink.setStart == 'function')) { sink.setStart(m.offset); }
                        s.sendJson({ action: 'download', sub: 'startack', id: id, ack: CFG.downloadWindow });
                        for (var i = 1; i < CFG.downloadWindow; i++) { ack(); } // Each extra ack makes the agent send one more block
                    } else if (m.sub == 'cancel') {
                        finish(httpError(404, 'Unable to read file'));
                    }
                };
                h.binary = function (data) {
                    if (!started || (data.length < 4)) return;
                    touch();
                    const last = ((data.readUInt32BE(0) & 1) == 1);
                    const payload = data.subarray(4);
                    total += payload.length;
                    var more = true;
                    if (payload.length > 0) { more = sink.write(payload); }
                    if (last) { finish(null, total); return; }
                    if (sink.aborted()) { abort(httpError(499, 'Transfer stopped')); return; }
                    if (more !== false) { ack(); } else { sink.onDrain(function () { if (sink.aborted()) { abort(httpError(499, 'Transfer stopped')); } else { ack(); } }); }
                };
                const startCmd = { action: 'download', sub: 'start', id: id, path: path };
                if (range != null) { if (range.offset > 0) { startCmd.offset = range.offset; } if (range.length > 0) { startCmd.length = range.length; } }
                s.sendJson(startCmd);
            });
        };

        // Upload a readable stream to dir/name
        s.upload = function (dir, name, source) {
            return s.run(function (h, touch, finish) {
                const reqid = randomId();
                var inflight = 0, ended = false, doneSent = false, paused = false, started = false, total = 0;
                function sendDone() { if (!doneSent) { doneSent = true; s.sendJson({ action: 'uploaddone', reqid: reqid }); } }
                function onData(chunk) {
                    touch();
                    for (var i = 0; i < chunk.length; i += CFG.uploadBlockSize) {
                        const part = chunk.subarray(i, Math.min(chunk.length, i + CFG.uploadBlockSize));
                        const b = Buffer.allocUnsafe(part.length + 1);
                        b[0] = 0; // A leading zero tells the agent this is file data, not a JSON command
                        part.copy(b, 1);
                        inflight++; // Count before sending, the ack can come back before send() returns
                        total += part.length;
                        try { s.sendBinary(b); } catch (ex) { fail(ex); return; }
                    }
                    if ((inflight >= CFG.uploadWindow) && !paused) { paused = true; source.pause(); }
                }
                function onEnd() { ended = true; if (inflight == 0) { sendDone(); } }
                function onClose() { if (!ended) { fail(httpError(499, 'Client aborted upload')); } }
                function onError() { fail(httpError(400, 'Upload stream error')); }
                function detach() { source.removeListener('data', onData); source.removeListener('end', onEnd); source.removeListener('close', onClose); source.removeListener('error', onError); }
                function fail(err) {
                    detach();
                    if (started) { try { s.sendJson({ action: 'uploadcancel', reqid: reqid }); } catch (ex) { } }
                    s.dirty = true;
                    finish(err);
                }
                h.json = function (m) {
                    if (m.reqid != reqid) return;
                    touch();
                    switch (m.action) {
                        case 'uploadstart':
                            started = true;
                            source.on('data', onData);
                            source.on('end', onEnd);
                            source.on('close', onClose);
                            source.on('error', onError);
                            source.resume();
                            break;
                        case 'uploadack':
                            if (inflight > 0) { inflight--; }
                            if (paused && (inflight < CFG.uploadWindow)) { paused = false; source.resume(); }
                            if (ended && (inflight == 0)) { sendDone(); }
                            break;
                        case 'uploaddone': detach(); finish(null, total); break;
                        case 'uploaderror': detach(); source.resume(); finish(httpError(403, 'Unable to write file on device')); break;
                        case 'uploadcancel': detach(); finish(httpError(500, 'Upload cancelled by device')); break;
                    }
                };
                h.fail = function (err) { detach(); finish(err); };
                source.pause();
                s.sendJson({ action: 'upload', reqid: reqid, path: dir, name: name });
            });
        };
    }

    function pumpWaiters(pool) {
        while (pool.waiters.length > 0) {
            const idle = pool.sessions.find(function (x) { return (x.state == 1) && !x.busy; });
            if (idle != null) { const w = pool.waiters.shift(); clearTimeout(w.timer); clearTimeout(idle.idleTimer); idle.busy = true; w.resolve(idle); continue; }
            if (pool.sessions.length < CFG.maxTunnelsPerDevice) { const w = pool.waiters.shift(); clearTimeout(w.timer); newSession(pool).then(w.resolve, w.reject); continue; }
            break;
        }
        if ((pool.sessions.length == 0) && (pool.waiters.length == 0) && (pools.get(pool.key) === pool)) { pools.delete(pool.key); }
    }

    function newSession(pool) {
        const s = new TunnelSession(pool);
        s.busy = true;
        pool.sessions.push(s);
        if (pools.get(pool.key) !== pool) { pools.set(pool.key, pool); }
        return s.open().catch(function (err) { s.close(); throw err; });
    }

    function acquire(pool) {
        const idle = pool.sessions.find(function (x) { return (x.state == 1) && !x.busy; });
        if (idle != null) { clearTimeout(idle.idleTimer); idle.busy = true; return Promise.resolve(idle); }
        if (pool.sessions.length < CFG.maxTunnelsPerDevice) { return newSession(pool); }
        return new Promise(function (resolve, reject) {
            const w = { resolve: resolve, reject: reject };
            w.timer = setTimeout(function () { const i = pool.waiters.indexOf(w); if (i >= 0) { pool.waiters.splice(i, 1); } reject(httpError(503, 'Device is busy, try again')); }, CFG.tunnelConnectTimeout);
            pool.waiters.push(w);
        });
    }

    function release(s) {
        s.busy = false;
        s.handler = null;
        if ((s.state != 1) || s.dirty) { s.close(); return; }
        clearTimeout(s.idleTimer);
        s.idleTimer = setTimeout(function () { if (!s.busy) { s.close(); } }, CFG.tunnelIdleTimeout);
        pumpWaiters(s.pool);
    }

    async function withSession(ctx, dev, fn) {
        const s = await acquire(getPool(ctx, dev));
        try { return await fn(s); } finally { release(s); }
    }

    // Called by the web server when the agent connects back to webdavrelay.ashx
    obj.handleRelayWebSocket = function (ws, req) {
        ws.on('error', function () { });
        const id = (req.query != null) ? req.query.id : null;
        const s = (typeof id == 'string') ? pendingTunnels.get(id) : null;
        if (s == null) { try { ws.close(); } catch (ex) { } return; }
        pendingTunnels.delete(id);
        s.attach(ws);
    };

    // ===================================================================================
    // File system helpers (with a short directory listing cache)
    // ===================================================================================
    const lsCache = new Map(), lsInflight = new Map();

    function fullSegments(account, rel) { return rootSegments(account).concat(rel); }
    function agentPath(dev, account, rel) {
        const all = fullSegments(account, rel);
        if (isWindowsNode(dev.node)) {
            if (all.length == 0) return ''; // Drive list
            if (!/^[A-Za-z]:$/.test(all[0])) throw httpError(404, 'Not found');
            return all.join('/');
        }
        return '/' + all.join('/');
    }

    function listDir(ctx, dev, path) {
        const key = dev.node._id + '|' + path;
        const c = lsCache.get(key);
        if ((c != null) && (c.t > Date.now())) return Promise.resolve(c.dir);
        var p = lsInflight.get(key);
        if (p == null) {
            p = withSession(ctx, dev, function (s) { return s.ls(path); });
            lsInflight.set(key, p);
            p.then(function (dir) { lsCache.set(key, { t: Date.now() + CFG.listCacheTime, dir: dir }); }, function () { }).then(function () { lsInflight.delete(key); });
        }
        return p;
    }

    function invalidateNode(nodeid) { const pfx = nodeid + '|'; for (const k of Array.from(lsCache.keys())) { if (k.startsWith(pfx)) { lsCache.delete(k); } } }

    function entryInfo(e) {
        const dir = (e.t != 3); // 1 = drive, 2 = folder, 3 = file
        var mtime = null;
        if (e.d != null) { const d = new Date(e.d); if (!isNaN(d.getTime())) { mtime = d; } }
        return { name: String(e.n), dir: dir, size: dir ? 0 : (e.s || 0), mtime: mtime };
    }

    // Stat a path relative to the device folder, returns null if not found
    async function statPath(ctx, dev, rel) {
        if (rel.length == 0) { return { name: dev.folder, dir: true, size: 0, mtime: null, root: true }; }
        const all = fullSegments(ctx.account, rel);
        const name = rel[rel.length - 1];
        if (isWindowsNode(dev.node) && (all.length == 1) && !/^[A-Za-z]:$/.test(name)) return null;
        const dir = await listDir(ctx, dev, agentPath(dev, ctx.account, rel.slice(0, -1)));
        if (dir == null) return null;
        var e = dir.find(function (x) { return x.n === name; });
        if ((e == null) && isWindowsNode(dev.node)) { const ln = name.toLowerCase(); e = dir.find(function (x) { return String(x.n).toLowerCase() === ln; }); }
        return (e != null) ? entryInfo(e) : null;
    }

    // ===================================================================================
    // HTTP helpers
    // ===================================================================================
    function send(res, status, body, headers) {
        if (res.headersSent) { try { res.end(); } catch (ex) { } return; }
        res.statusCode = status;
        if (headers) { for (var h in headers) { res.setHeader(h, headers[h]); } }
        if (body != null) {
            if (!res.getHeader('Content-Type')) { res.setHeader('Content-Type', 'text/plain; charset=utf-8'); }
            res.setHeader('Content-Length', Buffer.byteLength(body));
            res.end(body);
        } else {
            if ((status != 304) && (res.getHeader('Content-Length') == null)) { res.setHeader('Content-Length', 0); }
            res.end();
        }
    }

    function sendError(res, err) {
        const status = (err && err.status) ? err.status : 500;
        if (status == 500) { debug('Error: ' + ((err && err.stack) ? err.stack : err)); }
        if (res.headersSent || (status == 499)) { try { res.destroy(); } catch (ex) { } return; }
        const headers = {};
        if (status == 503) { headers['Retry-After'] = '10'; }
        try { res.removeHeader('Content-Length'); res.removeHeader('Content-Range'); res.removeHeader('Content-Disposition'); } catch (ex) { }
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        send(res, status, (status == 500) ? 'Internal server error' : String(err.message), headers);
    }

    function readBody(req, limit) {
        return new Promise(function (resolve, reject) {
            const chunks = []; var size = 0;
            req.on('data', function (c) { size += c.length; if (size > limit) { reject(httpError(413, 'Request body too large')); req.destroy(); return; } chunks.push(c); });
            req.on('end', function () { resolve(Buffer.concat(chunks).toString('utf8')); });
            req.on('error', reject);
        });
    }

    function xmlEscape(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
    function htmlEscape(s) { return xmlEscape(s).replace(/'/g, '&#39;'); }
    function hrefFor(base, segs, dir) { return base + '/' + segs.map(encodeURIComponent).join('/') + ((dir && (segs.length > 0)) ? '/' : ''); }
    function etagFor(info) { return '"' + info.size.toString(16) + '-' + (info.mtime ? info.mtime.getTime().toString(16) : '0') + '"'; }
    function formatSize(n) { if (n < 1024) return n + ' B'; const u = ['KB', 'MB', 'GB', 'TB']; var i = -1; do { n /= 1024; i++; } while ((n >= 1024) && (i < u.length - 1)); return n.toFixed(1) + ' ' + u[i]; }

    const MIME = {
        txt: 'text/plain; charset=utf-8', log: 'text/plain; charset=utf-8', md: 'text/plain; charset=utf-8', ini: 'text/plain; charset=utf-8', conf: 'text/plain; charset=utf-8', csv: 'text/csv; charset=utf-8',
        json: 'application/json', pdf: 'application/pdf', zip: 'application/zip', gz: 'application/gzip', '7z': 'application/x-7z-compressed', rar: 'application/vnd.rar', tar: 'application/x-tar',
        jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp', ico: 'image/x-icon', svg: 'image/svg+xml', avif: 'image/avif',
        mp4: 'video/mp4', m4v: 'video/mp4', webm: 'video/webm', mkv: 'video/x-matroska', mov: 'video/quicktime', avi: 'video/x-msvideo', ts: 'video/mp2t', flv: 'video/x-flv',
        mp3: 'audio/mpeg', m4a: 'audio/mp4', flac: 'audio/flac', wav: 'audio/wav', ogg: 'audio/ogg', aac: 'audio/aac',
        html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', xml: 'application/xml', css: 'text/css', js: 'text/javascript'
    };
    function mimeOf(name) { const i = name.lastIndexOf('.'); const t = (i >= 0) ? MIME[name.substring(i + 1).toLowerCase()] : null; return t || 'application/octet-stream'; }

    // Files are served from the panel origin: never let them run scripts there.
    const FILE_CSP = "sandbox; default-src 'none'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'unsafe-inline'";

    function parseDavPath(url) {
        var p = url, q = p.indexOf('?');
        if (q >= 0) { p = p.substring(0, q); }
        const segs = [];
        for (const raw of p.split('/')) {
            if (raw.length == 0) continue;
            var s;
            try { s = decodeURIComponent(raw); } catch (ex) { throw httpError(400, 'Bad path encoding'); }
            if ((s == '.') || (s == '..') || (s.indexOf('/') >= 0) || (s.indexOf('\\') >= 0) || (s.indexOf('\0') >= 0)) throw httpError(400, 'Invalid path');
            segs.push(s);
        }
        return segs;
    }

    // Resolve request segments into the root, or a device folder + relative path
    async function resolveTarget(ctx, segs) {
        if (segs.length == 0) return { root: true, segs: segs };
        const devices = await getAccountDevices(ctx.account, ctx.user, ctx.domain);
        var dev = devices.find(function (d) { return d.folder === segs[0]; });
        if (dev == null) { const l = segs[0].toLowerCase(); dev = devices.find(function (d) { return d.folder.toLowerCase() === l; }); }
        if (dev == null) throw httpError(404, 'Device not found');
        return { root: false, dev: dev, rel: segs.slice(1), segs: segs };
    }

    // ===================================================================================
    // Basic authentication
    // ===================================================================================
    const authCache = new Map(), failedLogins = new Map();

    async function authenticate(req, domain) {
        const h = req.headers['authorization'];
        if ((typeof h != 'string') || !h.startsWith('Basic ')) return null;
        const ip = req.clientIp || ((req.socket != null) ? req.socket.remoteAddress : '') || '';
        const fl = failedLogins.get(ip);
        if ((fl != null) && (Date.now() - fl.first < CFG.failedLoginWindow) && (fl.count >= CFG.maxFailedLogins)) return 'blocked';
        const cred = Buffer.from(h.substring(6).trim(), 'base64').toString('utf8');
        const i = cred.indexOf(':');
        if (i < 1) return null;
        const username = cred.substring(0, i), password = cred.substring(i + 1);
        var account = null, ok = false;
        if (USERNAME_REGEX.test(username)) { account = await getAccount(domain.id, username); }
        if ((account != null) && (account.enabled !== false)) {
            const key = crypto.createHash('sha256').update(account._id + '\n' + account.hash + '\n' + password).digest('hex');
            const c = authCache.get(key);
            if ((c != null) && (c.t > Date.now())) { ok = true; }
            else if (await verifyPassword(password, account.salt, account.hash)) { ok = true; authCache.set(key, { t: Date.now() + CFG.authCacheTime, id: account._id }); }
        }
        if (!ok) {
            if ((fl == null) || (Date.now() - fl.first >= CFG.failedLoginWindow)) { failedLogins.set(ip, { first: Date.now(), count: 1 }); } else { fl.count++; }
            debug('Failed WebDAV login for "' + username + '" from ' + ip);
            return null;
        }
        failedLogins.delete(ip);
        return account;
    }

    // ===================================================================================
    // WebDAV request handling, called by webserver.js for <domain>/webdav/*
    // req.baseUrl is the mount point, req.url the path below it.
    // ===================================================================================
    obj.handleWebDavRequest = function (req, res, domain) {
        handleRequest(req, res, domain).catch(function (err) { sendError(res, err); });
    };

    async function handleRequest(req, res, domain) {
        res.setHeader('DAV', '1, 2');
        res.setHeader('MS-Author-Via', 'DAV');
        res.setHeader('Cache-Control', 'no-store, no-transform');
        if ((domain == null) || (domain.webdav === false)) { req.resume(); send(res, 404, 'Not found'); return; }
        if (req.method == 'OPTIONS') {
            req.resume();
            send(res, 200, null, { 'Allow': 'OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK' });
            return;
        }
        const m = req.method;
        if ((m != 'PUT') && (m != 'PROPPATCH') && (m != 'LOCK') && (m != 'MKCOL')) { req.resume(); } // Discard unused request bodies

        const account = await authenticate(req, domain);
        if (account === 'blocked') { req.resume(); send(res, 429, 'Too many failed logins, try again later', { 'Retry-After': '600' }); return; }
        if (account == null) { req.resume(); send(res, 401, 'Authentication required', { 'WWW-Authenticate': 'Basic realm="MeshCentral WebDAV", charset="UTF-8"' }); return; }
        const user = getOwner(account);
        if (user == null) { req.resume(); send(res, 403, 'The owner of this WebDAV account is missing or locked'); return; }
        lastUsed.set(account._id, Date.now());

        const ctx = { req: req, res: res, domain: domain, account: account, user: user, base: (req.baseUrl || '').replace(/\/+$/, ''), clientIp: req.clientIp || '' };
        const segs = parseDavPath(req.url || '/');
        switch (m) {
            case 'PROPFIND': return davPropfind(ctx, segs);
            case 'GET': return davGet(ctx, segs, false);
            case 'HEAD': return davGet(ctx, segs, true);
            case 'PUT': return davPut(ctx, segs);
            case 'MKCOL': return davMkcol(ctx, segs);
            case 'DELETE': return davDelete(ctx, segs);
            case 'MOVE': return davMoveCopy(ctx, segs, true);
            case 'COPY': return davMoveCopy(ctx, segs, false);
            case 'LOCK': return davLock(ctx, segs);
            case 'UNLOCK': send(res, 204); return;
            case 'PROPPATCH': return davProppatch(ctx, segs);
            default: send(res, 405, 'Method not allowed'); return;
        }
    }

    function propEntry(href, info) {
        var x = '<D:response><D:href>' + xmlEscape(href) + '</D:href><D:propstat><D:prop>';
        x += '<D:displayname>' + xmlEscape(info.name) + '</D:displayname>';
        if (info.dir) {
            x += '<D:resourcetype><D:collection/></D:resourcetype>';
        } else {
            x += '<D:resourcetype/><D:getcontentlength>' + info.size + '</D:getcontentlength><D:getcontenttype>' + xmlEscape(mimeOf(info.name)) + '</D:getcontenttype><D:getetag>' + xmlEscape(etagFor(info)) + '</D:getetag>';
        }
        if (info.mtime) { x += '<D:getlastmodified>' + info.mtime.toUTCString() + '</D:getlastmodified><D:creationdate>' + info.mtime.toISOString() + '</D:creationdate>'; }
        x += '<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>';
        x += '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>';
        return x;
    }

    function sendMultistatus(res, entries, nsAttrs) {
        send(res, 207, '<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:"' + (nsAttrs || '') + '>' + entries.join('') + '</D:multistatus>', { 'Content-Type': 'application/xml; charset=utf-8' });
    }

    async function davPropfind(ctx, segs) {
        const depth = (ctx.req.headers['depth'] == '0') ? 0 : 1; // "infinity" is served as depth 1
        const t = await resolveTarget(ctx, segs);
        const out = [];
        if (t.root) {
            out.push(propEntry(hrefFor(ctx.base, [], true), { name: 'webdav', dir: true }));
            if (depth == 1) {
                const devices = await getAccountDevices(ctx.account, ctx.user, ctx.domain);
                for (const d of devices) { out.push(propEntry(hrefFor(ctx.base, [d.folder], true), { name: d.folder, dir: true })); }
            }
            sendMultistatus(ctx.res, out);
            return;
        }
        const info = await statPath(ctx, t.dev, t.rel);
        if (info == null) throw httpError(404, 'Not found');
        out.push(propEntry(hrefFor(ctx.base, segs, info.dir), info));
        if (info.dir && (depth == 1)) {
            const dir = await listDir(ctx, t.dev, agentPath(t.dev, ctx.account, t.rel));
            if (dir == null) throw httpError(404, 'Not found');
            for (const e of dir) { const ei = entryInfo(e); out.push(propEntry(hrefFor(ctx.base, segs.concat([ei.name]), ei.dir), ei)); }
        }
        sendMultistatus(ctx.res, out);
    }

    // Simple HTML index so a browser can browse the WebDAV tree directly
    async function sendIndex(ctx, segs, t, headOnly) {
        var rows = [];
        if (t.root) {
            rows = (await getAccountDevices(ctx.account, ctx.user, ctx.domain)).map(function (d) { return { name: d.folder, dir: true, size: 0, mtime: null }; });
        } else {
            const dir = await listDir(ctx, t.dev, agentPath(t.dev, ctx.account, t.rel));
            if (dir == null) throw httpError(404, 'Not found');
            rows = dir.map(entryInfo);
        }
        rows.sort(function (a, b) { return (a.dir != b.dir) ? (a.dir ? -1 : 1) : a.name.localeCompare(b.name); });
        const title = '/' + segs.join('/');
        var h = '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>' + htmlEscape(title) + '</title>';
        h += '<style>body{font-family:sans-serif;margin:16px}td{padding:3px 14px 3px 0}a{text-decoration:none}tr:hover{background:#eee}.s{text-align:right;color:#666}.d{color:#666}</style></head><body>';
        h += '<h3>' + htmlEscape(title) + '</h3><table>';
        if (segs.length > 0) { h += '<tr><td><a href="' + htmlEscape(hrefFor(ctx.base, segs.slice(0, -1), true)) + '">..</a></td><td></td><td></td></tr>'; }
        for (const r of rows) {
            h += '<tr><td><a href="' + htmlEscape(hrefFor(ctx.base, segs.concat([r.name]), r.dir)) + '">' + (r.dir ? '&#128193; ' : '&#128196; ') + htmlEscape(r.name) + (r.dir ? '/' : '') + '</a></td>';
            h += '<td class="s">' + (r.dir ? '' : formatSize(r.size)) + '</td><td class="d">' + (r.mtime ? r.mtime.toISOString().replace('T', ' ').substring(0, 19) : '') + '</td></tr>';
        }
        h += '</table></body></html>';
        const headers = { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'", 'X-Content-Type-Options': 'nosniff' };
        if (headOnly) { headers['Content-Length'] = Buffer.byteLength(h); send(ctx.res, 200, null, headers); } else { send(ctx.res, 200, h, headers); }
    }

    function parseRange(h, size) {
        if ((typeof h != 'string') || (h.indexOf(',') >= 0)) return null;
        const m = /^bytes=(\d*)-(\d*)$/.exec(h.trim());
        if (m == null) return null;
        var start, end;
        if (m[1] === '') { if (m[2] === '') return null; const n = parseInt(m[2]); if (n == 0) return 'invalid'; start = Math.max(0, size - n); end = size - 1; }
        else { start = parseInt(m[1]); end = (m[2] === '') ? (size - 1) : Math.min(parseInt(m[2]), size - 1); }
        if ((start >= size) || (start > end)) return 'invalid';
        return { start: start, end: end };
    }

    async function davGet(ctx, segs, headOnly) {
        const t = await resolveTarget(ctx, segs);
        if (t.root) { return sendIndex(ctx, segs, t, headOnly); }
        const info = await statPath(ctx, t.dev, t.rel);
        if (info == null) throw httpError(404, 'Not found');
        if (info.dir) { return sendIndex(ctx, segs, t, headOnly); }

        const res = ctx.res, req = ctx.req, etag = etagFor(info);
        const headers = {
            'Content-Type': mimeOf(info.name), 'Accept-Ranges': 'bytes', 'ETag': etag,
            'Content-Disposition': "inline; filename*=UTF-8''" + encodeURIComponent(info.name),
            'Content-Security-Policy': FILE_CSP, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'private, no-cache, no-transform'
        };
        if (info.mtime) { headers['Last-Modified'] = info.mtime.toUTCString(); }
        if ((req.headers['if-none-match'] === etag) || (info.mtime && (req.headers['if-none-match'] == null) && req.headers['if-modified-since'] && (new Date(req.headers['if-modified-since']).getTime() >= Math.floor(info.mtime.getTime() / 1000) * 1000))) { send(res, 304, null, headers); return; }

        var range = null;
        if ((req.headers['range'] != null) && ((req.headers['if-range'] == null) || (req.headers['if-range'] === etag))) { range = parseRange(req.headers['range'], info.size); }
        if (range === 'invalid') { send(res, 416, null, { 'Content-Range': 'bytes */' + info.size }); return; }
        const start = range ? range.start : 0, end = range ? range.end : (info.size - 1), length = Math.max(0, end - start + 1);
        headers['Content-Length'] = length;
        if (range) { headers['Content-Range'] = 'bytes ' + start + '-' + end + '/' + info.size; }
        if (headOnly || (length == 0)) { send(res, range ? 206 : 200, null, headers); return; }

        const path = agentPath(t.dev, ctx.account, t.rel);
        var clientGone = false, pos = 0, sent = 0, headersOut = false;
        res.on('close', function () { if (!res.writableFinished) { clientGone = true; } });
        function startResponse() { if (!headersOut) { headersOut = true; res.statusCode = range ? 206 : 200; for (var hk in headers) { res.setHeader(hk, headers[hk]); } } }
        // Ranges are read directly by the agent (meshcore offset/length). Older agents send the file from the
        // start: the data before the range is then skipped, short tails are drained and long ones are stopped.
        const sink = {
            setStart: function (offset) { pos = offset; },
            write: function (buf) {
                const p0 = pos;
                pos += buf.length;
                if (sent >= length) { return true; }
                const a = Math.max(0, start - p0), b = Math.min(buf.length, end + 1 - p0);
                if (b <= a) { return true; }
                startResponse();
                const chunk = buf.subarray(a, b);
                sent += chunk.length;
                const r = res.write(chunk);
                if (sent >= length) { res.end(); return true; }
                return r;
            },
            onDrain: function (fn) { if (clientGone || res.writableEnded) { fn(); } else { res.once('drain', fn); } },
            aborted: function () { return clientGone || ((sent >= length) && ((info.size - pos) > 4194304)); }
        };
        try {
            await withSession(ctx, t.dev, function (s) { return s.download(path, sink, range ? { offset: start, length: length } : null); });
        } catch (err) {
            if ((err.status == 499) && (sent >= length)) { return; } // Range complete, transfer stopped early
            if (!headersOut) { throw err; }
            try { res.destroy(); } catch (ex) { }
            return;
        }
        if (sent < length) { if (!headersOut) { throw httpError(409, 'File changed during transfer'); } try { res.destroy(); } catch (ex) { } }
    }

    function requireWritable(ctx) { if (ctx.account.readOnly === true) throw httpError(403, 'This WebDAV account is read-only'); }

    // Check that rel can be created: the parent folder exists, and it is not the Windows drive list
    async function checkParent(ctx, t) {
        if (t.root || (t.rel.length == 0)) throw httpError(403, 'Not allowed here');
        if (isWindowsNode(t.dev.node) && (fullSegments(ctx.account, t.rel).length < 2)) throw httpError(403, 'Not allowed here');
        const parentRel = t.rel.slice(0, -1);
        if (parentRel.length == 0) {
            if ((await listDir(ctx, t.dev, agentPath(t.dev, ctx.account, []))) == null) throw httpError(409, 'Parent folder does not exist');
        } else {
            const p = await statPath(ctx, t.dev, parentRel);
            if ((p == null) || !p.dir) throw httpError(409, 'Parent folder does not exist');
        }
        return agentPath(t.dev, ctx.account, parentRel);
    }

    async function davPut(ctx, segs) {
        requireWritable(ctx);
        const t = await resolveTarget(ctx, segs);
        const parentPath = await checkParent(ctx, t);
        const existing = await statPath(ctx, t.dev, t.rel);
        if ((existing != null) && existing.dir) throw httpError(405, 'A folder with this name exists');
        const name = t.rel[t.rel.length - 1];
        try {
            await withSession(ctx, t.dev, function (s) { return s.upload(parentPath, name, ctx.req); });
        } finally { invalidateNode(t.dev.node._id); }
        send(ctx.res, (existing != null) ? 204 : 201);
    }

    async function davMkcol(ctx, segs) {
        const body = await readBody(ctx.req, 65536);
        if (body.length > 0) throw httpError(415, 'MKCOL with a body is not supported');
        requireWritable(ctx);
        const t = await resolveTarget(ctx, segs);
        await checkParent(ctx, t);
        if ((await statPath(ctx, t.dev, t.rel)) != null) throw httpError(405, 'Already exists');
        const path = agentPath(t.dev, ctx.account, t.rel);
        await withSession(ctx, t.dev, function (s) { s.fire({ action: 'mkdir', path: path }); return s.ls(path); });
        invalidateNode(t.dev.node._id);
        const info = await statPath(ctx, t.dev, t.rel);
        if ((info == null) || !info.dir) throw httpError(403, 'Unable to create folder on device');
        send(ctx.res, 201);
    }

    async function davDelete(ctx, segs) {
        requireWritable(ctx);
        const t = await resolveTarget(ctx, segs);
        if (t.root || (t.rel.length == 0)) throw httpError(403, 'Not allowed');
        if (isWindowsNode(t.dev.node) && (fullSegments(ctx.account, t.rel).length < 2)) throw httpError(403, 'Not allowed');
        const info = await statPath(ctx, t.dev, t.rel);
        if (info == null) throw httpError(404, 'Not found');
        const parentPath = agentPath(t.dev, ctx.account, t.rel.slice(0, -1));
        await withSession(ctx, t.dev, function (s) { s.fire({ action: 'rm', path: parentPath, delfiles: [t.rel[t.rel.length - 1]], rec: info.dir }); return s.ls(parentPath); });
        invalidateNode(t.dev.node._id);
        if ((await statPath(ctx, t.dev, t.rel)) != null) throw httpError(403, 'Unable to delete on device');
        send(ctx.res, 204);
    }

    // Move inside one device. The agent "rename" joins path + names, so it is anchored at the root (or drive).
    function renameCommand(dev, account, srcRel, dstRel) {
        const a = fullSegments(account, srcRel), b = fullSegments(account, dstRel);
        if (isWindowsNode(dev.node)) {
            if (a[0].toUpperCase() != b[0].toUpperCase()) throw httpError(502, 'Moving between drives is not supported');
            return { action: 'rename', path: a[0], oldname: a.slice(1).join('/'), newname: b.slice(1).join('/') };
        }
        return { action: 'rename', path: '/', oldname: a.join('/'), newname: b.join('/') };
    }

    async function copyDirectory(ctx, dev, srcRel, dstRel, depth) {
        if (depth > 32) throw httpError(507, 'Folder tree too deep');
        const src = agentPath(dev, ctx.account, srcRel), dst = agentPath(dev, ctx.account, dstRel);
        const entries = await withSession(ctx, dev, function (s) { s.fire({ action: 'mkdir', path: dst }); return s.ls(src); });
        if (entries == null) throw httpError(404, 'Not found');
        const files = entries.filter(function (e) { return e.t == 3; }).map(function (e) { return e.n; });
        if (files.length > 0) { await withSession(ctx, dev, function (s) { s.fire({ action: 'copy', scpath: src, dspath: dst, names: files }); return s.ls(dst); }); }
        for (const e of entries) { if (e.t != 3) { await copyDirectory(ctx, dev, srcRel.concat([e.n]), dstRel.concat([e.n]), depth + 1); } }
    }

    // Copy a file through the server, used when the file name changes (the agent copy keeps names)
    async function streamCopy(ctx, dev, srcRel, dstRel) {
        const src = agentPath(dev, ctx.account, srcRel), dstDir = agentPath(dev, ctx.account, dstRel.slice(0, -1)), name = dstRel[dstRel.length - 1];
        const pt = new PassThrough({ highWaterMark: 1048576 });
        var failed = false;
        const sink = { write: function (b) { return pt.write(b); }, onDrain: function (fn) { pt.once('drain', fn); }, aborted: function () { return failed; } };
        const up = withSession(ctx, dev, function (s) { return s.upload(dstDir, name, pt); }).catch(function (err) { failed = true; throw err; });
        const down = withSession(ctx, dev, function (s) { return s.download(src, sink); }).then(function () { pt.end(); }, function (err) { failed = true; pt.destroy(); throw err; });
        await Promise.all([up, down]);
    }

    async function davMoveCopy(ctx, segs, isMove) {
        requireWritable(ctx);
        const destHeader = ctx.req.headers['destination'];
        if (typeof destHeader != 'string') throw httpError(400, 'Missing Destination header');
        var destPath;
        try { destPath = new URL(destHeader, 'http://localhost').pathname; } catch (ex) { throw httpError(400, 'Bad Destination header'); }
        if ((destPath != ctx.base) && !destPath.startsWith(ctx.base + '/')) throw httpError(502, 'Destination is on another server');
        const dsegs = parseDavPath(destPath.substring(ctx.base.length));
        const t = await resolveTarget(ctx, segs), d = await resolveTarget(ctx, dsegs);
        if (t.root || d.root || (t.rel.length == 0) || (d.rel.length == 0)) throw httpError(403, 'Not allowed');
        if (t.dev.node._id != d.dev.node._id) throw httpError(502, 'Copy or move between devices is not supported');
        const srcKey = t.rel.join('/'), dstKey = d.rel.join('/');
        if (srcKey == dstKey) throw httpError(403, 'Source and destination are the same');
        if (dstKey.startsWith(srcKey + '/')) throw httpError(409, 'Cannot copy or move a folder into itself');
        const info = await statPath(ctx, t.dev, t.rel);
        if (info == null) throw httpError(404, 'Not found');
        await checkParent(ctx, d);
        const existing = await statPath(ctx, d.dev, d.rel);
        const overwrite = String(ctx.req.headers['overwrite'] || 'T').toUpperCase() != 'F';
        if ((existing != null) && !overwrite) throw httpError(412, 'Destination exists');
        const dev = t.dev;
        try {
            if (existing != null) {
                const dParent = agentPath(dev, ctx.account, d.rel.slice(0, -1));
                await withSession(ctx, dev, function (s) { s.fire({ action: 'rm', path: dParent, delfiles: [d.rel[d.rel.length - 1]], rec: existing.dir }); return s.ls(dParent); });
            }
            if (isMove) {
                const cmd = renameCommand(dev, ctx.account, t.rel, d.rel);
                await withSession(ctx, dev, function (s) { s.fire(cmd); return s.ls(agentPath(dev, ctx.account, d.rel.slice(0, -1))); });
            } else if (info.dir) {
                await copyDirectory(ctx, dev, t.rel, d.rel, 0);
            } else if ((t.rel[t.rel.length - 1] == d.rel[d.rel.length - 1]) && (t.rel.slice(0, -1).join('/') != d.rel.slice(0, -1).join('/'))) {
                const src = agentPath(dev, ctx.account, t.rel.slice(0, -1)), dst = agentPath(dev, ctx.account, d.rel.slice(0, -1));
                await withSession(ctx, dev, function (s) { s.fire({ action: 'copy', scpath: src, dspath: dst, names: [t.rel[t.rel.length - 1]] }); return s.ls(dst); });
            } else {
                await streamCopy(ctx, dev, t.rel, d.rel);
            }
        } finally { invalidateNode(dev.node._id); }
        if ((await statPath(ctx, dev, d.rel)) == null) throw httpError(403, (isMove ? 'Move' : 'Copy') + ' failed on device');
        send(ctx.res, (existing != null) ? 204 : 201);
    }

    // Locks are not enforced, a token is returned so that Windows Explorer, Finder and Office can write.
    async function davLock(ctx, segs) {
        const body = await readBody(ctx.req, 65536);
        const ownerMatch = /<(?:[\w.-]+:)?owner[^>]*>([\s\S]*?)<\/(?:[\w.-]+:)?owner>/i.exec(body);
        const token = 'opaquelocktoken:' + crypto.randomUUID();
        var x = '<?xml version="1.0" encoding="utf-8"?>\n<D:prop xmlns:D="DAV:"><D:lockdiscovery><D:activelock>';
        x += '<D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope><D:depth>' + ((ctx.req.headers['depth'] == '0') ? '0' : 'infinity') + '</D:depth>';
        if (ownerMatch) { x += '<D:owner>' + ownerMatch[1] + '</D:owner>'; }
        x += '<D:timeout>Second-3600</D:timeout><D:locktoken><D:href>' + token + '</D:href></D:locktoken><D:lockroot><D:href>' + xmlEscape(hrefFor(ctx.base, segs, false)) + '</D:href></D:lockroot>';
        x += '</D:activelock></D:lockdiscovery></D:prop>';
        send(ctx.res, 200, x, { 'Content-Type': 'application/xml; charset=utf-8', 'Lock-Token': '<' + token + '>' });
    }

    // Dead properties can not be stored on the device, report success so clients (Windows) carry on.
    async function davProppatch(ctx, segs) {
        const body = await readBody(ctx.req, 262144);
        const ns = {}, props = []; var m;
        const nsRegex = /xmlns:([\w.-]+)\s*=\s*"([^"]*)"/g;
        while ((m = nsRegex.exec(body)) != null) { ns[m[1]] = m[2]; }
        const blockRegex = /<(?:[\w.-]+:)?prop(?:\s[^>]*)?>([\s\S]*?)<\/(?:[\w.-]+:)?prop>/g;
        while ((m = blockRegex.exec(body)) != null) {
            const tagRegex = /<([\w.-]+:)?([\w.-]+)(?:\s[^>]*)?\/?>/g; var tm;
            while ((tm = tagRegex.exec(m[1])) != null) { const n = (tm[1] || '') + tm[2]; if (props.indexOf(n) < 0) { props.push(n); } }
        }
        var attrs = '';
        for (var p in ns) { if ((p != 'D') && /^[\w.-]+$/.test(p)) { attrs += ' xmlns:' + p + '="' + xmlEscape(ns[p]) + '"'; } }
        const inner = props.filter(function (p) { const pf = p.split(':'); return (pf.length == 1) || (pf[0] == 'D') || (ns[pf[0]] != null); }).map(function (p) { return (p.indexOf(':') < 0) ? ('<' + p + ' xmlns=""/>') : ('<' + p + '/>'); }).join('');
        sendMultistatus(ctx.res, ['<D:response><D:href>' + xmlEscape(hrefFor(ctx.base, segs, false)) + '</D:href><D:propstat><D:prop>' + inner + '</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>'], attrs);
    }

    // ===================================================================================
    // Panel management, called from meshuser.js for { action: 'webdav', sub: ... }
    // ===================================================================================
    obj.handleUserCommand = function (userConn, user, domain, command) {
        const reply = { action: 'webdav', sub: command.sub };
        if (command.responseid != null) { reply.responseid = command.responseid; }
        userCommand(user, domain, command).then(function (r) { userConn.send(Object.assign(reply, r)); }, function (err) { reply.error = (err && err.message) ? err.message : String(err); if (err && err.errorId) { reply.errorId = err.errorId; } userConn.send(reply); });
    };

    async function publicAccount(a) {
        const owner = web().users[a.owner];
        const devices = [];
        if ((a.allDevices !== true) && Array.isArray(a.deviceIds)) {
            for (const id of a.deviceIds) { const n = await dbGet(id); devices.push({ id: id, name: (n != null) ? n.name : null }); }
        }
        return {
            username: a.username, owner: a.owner, ownerName: (owner != null) ? owner.name : null,
            readOnly: a.readOnly === true, allDevices: a.allDevices === true, devices: devices,
            rootPath: displayRootPath(a.rootPath), enabled: a.enabled !== false,
            created: a.created, updated: a.updated, lastUsed: lastUsed.get(a._id) || null
        };
    }

    function validateDeviceSelection(command, allowedIds) {
        const allDevices = (command.allDevices === true);
        const ids = [];
        if (!allDevices) {
            if (!Array.isArray(command.deviceIds) || (command.deviceIds.length == 0)) throw userError(6, 'Select at least one device');
            if (command.deviceIds.length > 1000) throw userError(7, 'Too many devices');
            for (const id of command.deviceIds) {
                if ((typeof id != 'string') || (allowedIds.indexOf(id) < 0)) throw userError(8, 'No file access rights on a selected device');
                if (ids.indexOf(id) < 0) { ids.push(id); }
            }
        }
        return { allDevices: allDevices, deviceIds: ids };
    }

    function validatePassword(p) { if ((typeof p != 'string') || (p.length < 8) || (p.length > 256)) throw userError(3, 'Password must be at least 8 characters'); }

    function auditEvent(user, domain, msgid, msg, username) {
        try { parent.DispatchEvent(['*', user._id], obj, { etype: 'user', userid: user._id, username: user.name, action: 'webdav', msgid: msgid, msgArgs: [username], msg: msg + ' ' + username, domain: domain.id }); } catch (ex) { }
    }

    async function loadManagedAccount(user, domain, username, isAdmin) {
        const a = (typeof username == 'string') ? await dbGet(accountKey(domain.id, username)) : null;
        if ((a == null) || (a.domain != domain.id)) throw userError(10, 'Account not found');
        if (!isAdmin && (a.owner != user._id)) throw userError(11, 'Access denied');
        return a;
    }

    async function userCommand(user, domain, command) {
        if ((domain == null) || (domain.webdav === false)) throw userError(1, 'WebDAV is disabled on this server');
        user = web().users[user._id] || user;
        const isAdmin = (user.siteadmin == MESHRIGHT_ADMIN);
        switch (command.sub) {
            case 'list': {
                const docs = (await dbGetAllType(DBTYPE)).filter(function (a) { return (a.domain == domain.id) && (isAdmin || (a.owner == user._id)); });
                docs.sort(function (a, b) { return a.username.localeCompare(b.username); });
                const accounts = [];
                for (const a of docs) { accounts.push(await publicAccount(a)); }
                return { accounts: accounts, isAdmin: isAdmin, path: domain.url + 'webdav/' };
            }
            case 'devices': {
                const nodes = await getUserFileNodes(user, domain);
                nodes.sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
                return {
                    devices: nodes.map(function (n) {
                        const mesh = web().meshes[n.meshid];
                        return { id: n._id, name: n.name, mesh: (mesh != null) ? mesh.name : '', online: (web().wsagents[n._id] != null), windows: isWindowsNode(n) };
                    })
                };
            }
            case 'create': {
                if ((typeof command.username != 'string') || !USERNAME_REGEX.test(command.username)) throw userError(2, 'Username must be 3 to 64 characters: letters, digits, dot, underscore, @ or dash');
                validatePassword(command.password);
                if ((await getAccount(domain.id, command.username)) != null) throw userError(4, 'This WebDAV username is already used');
                const mine = (await dbGetAllType(DBTYPE)).filter(function (a) { return a.owner == user._id; });
                if (mine.length >= CFG.maxAccountsPerUser) throw userError(5, 'Too many WebDAV accounts');
                const allowed = (await getUserFileNodes(user, domain)).map(function (n) { return n._id; });
                const sel = validateDeviceSelection(command, allowed);
                const rootPath = normalizeRootPath(command.rootPath);
                const pw = await hashPassword(command.password);
                const doc = {
                    _id: accountKey(domain.id, command.username), type: DBTYPE, domain: domain.id, username: command.username, owner: user._id,
                    salt: pw.salt, hash: pw.hash, readOnly: command.readOnly === true, allDevices: sel.allDevices, deviceIds: sel.deviceIds,
                    rootPath: rootPath, enabled: true, created: Date.now(), updated: Date.now()
                };
                await dbSet(doc);
                invalidateAccount(doc._id);
                auditEvent(user, domain, 901, 'Created WebDAV account', doc.username);
                return { result: 'ok', username: doc.username };
            }
            case 'update': {
                const a = await loadManagedAccount(user, domain, command.username, isAdmin);
                if (typeof command.enabled == 'boolean') { a.enabled = command.enabled; }
                if (typeof command.readOnly == 'boolean') { a.readOnly = command.readOnly; }
                if (typeof command.rootPath == 'string') { a.rootPath = normalizeRootPath(command.rootPath); }
                if ((command.password != null) && (command.password !== '')) {
                    validatePassword(command.password);
                    const pw = await hashPassword(command.password);
                    a.salt = pw.salt; a.hash = pw.hash;
                }
                if ((command.allDevices != null) || (command.deviceIds != null)) {
                    const owner = web().users[a.owner];
                    if (owner == null) throw userError(12, 'The owner of this account no longer exists');
                    const allowed = (await getUserFileNodes(owner, domain)).map(function (n) { return n._id; });
                    const sel = validateDeviceSelection(command, allowed);
                    a.allDevices = sel.allDevices; a.deviceIds = sel.deviceIds;
                }
                a.updated = Date.now();
                await dbSet(a);
                invalidateAccount(a._id);
                auditEvent(user, domain, 902, 'Changed WebDAV account', a.username);
                return { result: 'ok', username: a.username };
            }
            case 'delete': {
                const a = await loadManagedAccount(user, domain, command.username, isAdmin);
                await dbRemove(a._id);
                invalidateAccount(a._id);
                lastUsed.delete(a._id);
                auditEvent(user, domain, 903, 'Deleted WebDAV account', a.username);
                return { result: 'ok', username: a.username };
            }
            default: throw new Error('Unknown command');
        }
    }

    // Periodic cache cleanup
    const cleanupTimer = setInterval(function () {
        const now = Date.now();
        for (const [k, v] of Array.from(authCache)) { if (v.t <= now) authCache.delete(k); }
        for (const [k, v] of Array.from(lsCache)) { if (v.t <= now) lsCache.delete(k); }
        for (const [k, v] of Array.from(deviceCache)) { if (v.t <= now) deviceCache.delete(k); }
        for (const [k, v] of Array.from(accountCache)) { if (v.t <= now) accountCache.delete(k); }
        for (const [k, v] of Array.from(failedLogins)) { if (now - v.first >= CFG.failedLoginWindow) failedLogins.delete(k); }
    }, 60000);
    if (cleanupTimer.unref) { cleanupTimer.unref(); }

    return obj;
};
