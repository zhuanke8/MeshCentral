# MeshCentral 只读 WebDAV 网关

> **状态说明**：本模块属于 `feat/readonly-webdav` 分支的新增功能，**不是 MeshCentral 上游内置功能**。代码由 `meshdav.js` + `meshdav-route.js`（域路由分发与日志脱敏）+ `webserver.js` 路由补丁组成，尚未与真实 Agent / AList 做端到端联调，以下说明基于源码与单元测试，实际部署前请自行验证。

MeshCentral 只读 WebDAV 网关以标准 WebDAV 协议暴露 Agent 文件系统，供 AList、rclone 等外部工具挂载访问。仅支持读操作，拒绝所有写方法。

## 启用配置

在 `config.json` 的对应 domain 下添加 `readOnlyDav` 段：

```json
{
  "domains": {
    "": {
      "readOnlyDav": {
        "enabled": true,
        "realm": "MeshCentral Read-Only DAV",
        "shares": {
          "nas1": {
            "username": "alist-nas1",
            "passwordHash": "scrypt:...",
            "runAsUser": "user//davreader",
            "nodeId": "node//xxxxxxxx",
            "root": "/srv/media",
            "maxDownloads": 4
          }
        }
      }
    }
  }
}
```

- **enabled**：`true` 启用该 domain 的 WebDAV 网关。
- **realm**：HTTP 401 认证 realm，默认 `MeshCentral Read-Only DAV`。
- **shares**：share 名为键（MeshCentral 会自动转小写）。每个 share 独立 Basic 认证。
  - **配置键归一**：配置对象键名会由 MeshCentral 归一为小写（例如 `readOnlyDav`→`readonlydav`、`passwordHash`→`passwordhash`，`shares` 中的 share 名也属键）；这不代表 `username`/`passwordHash`/`runAsUser`/`nodeId`/`root` 等字符串值转为小写，不得据此改写值。独立调用 `CreateMeshDav` 须提供已归一的配置键。若不确定可 `grep objKeysToLower meshcentral.js` 确认。
  - **username / passwordHash**：WebDAV 客户端使用的用户名与密码哈希。
  - **runAsUser**：执行文件操作的 MeshCentral 用户 ID，应为专用低权限账号。
  - **nodeId**：目标 Agent 节点 ID，必须以 `node/<domain.id>/` 开头。
  - **root**：Agent 上的远端根目录绝对路径。
  - **maxDownloads**：该 share 最大并发下载数，默认 4，超出返回 503（`Retry-After: 5`）。

访问地址：`https://<server><domain.url>dav/<share>/<路径>`。

## 域路由安全（meshdav-route.js）

DAV 域解析使用专用 `createDavDomainResolver`，**不修改全局 `getDomain` 行为**。生产 `webserver.js` 将 `config.domains`、DNS 映射、默认 Host 和回环判定传入该解析器，main 与 agent 端口共享同一 dispatcher。

- **DNS 映射不依赖证书**：从 `config.domains` 中 `dns != null` 的域独立构建，即使无对应 TLS 证书也能按 Host 路由。DNS 域直接匹配 Host 头，**不走路径前缀**（`/team/dav/` 请求到 DNS Host → 404）。
- **默认 Host 严格来源**：取 `certificates.CommonName`（非空、非 `un-configured`），回退到 `args.cert`。允许 IP / 短名 / FQDN / IPv6。**无有效默认 Host 时 `defaultHost=null`，未知 Host 一律拒绝（不退默认域，不默认允许所有 Host）**。
- **localhost 显式 domainid**：仅双回环（`req.clientIp` 与真实 `remoteAddress` 均为回环）且 domainid 为已知非空字符串时生效。未知 / 非字符串 domainid → 直接拒绝（404），**即使 `req.xdomain` 已被全局 `getDomain` 缓存为默认域也不绕过**。远程请求的 domainid 不生效。
- **根 tunnel 内部别名**：双回环 + 有效显式 domainid 时，`/davtunnel.ashx?domainid=<team>` 允许作为路径域 `<team>` 的根 tunnel 别名（WS）。
- **`req.xdomain` 校验**：优先使用但严格校验 Host 与 `originalUrl` 挂载路径。校验失败时重新安全解析，不信任缓存。
- **精确路径匹配**：`pathMatchesDomain` 校验 `originalUrl` 精确以 `domain.url + 'dav/'` 或 `domain.url + 'davtunnel.ashx'` 开头，不匹配 `/dave` 等前缀别名。
- **IPv6 Host 解析**：`[::1]:port` 正确提取 `::1`，不因冒号截断产生空串误配。

## 生成密码哈希

密码哈希使用 scrypt。**不要用 `echo` 传密码**——字面值会进入 shell history。用 `read -s` 交互输入（无回显、不进 history），再通过 stdin 喂给 `meshdav.js`：

```bash
read -r -s -p "DAV 密码: " PW; echo      # -s 关闭回显，read 不写入 history；echo 仅输出换行，不碰密码
printf '%s' "$PW" | node meshdav.js hash # 输出: scrypt:<salthex>:<hashhex>
unset PW                                 # 立即清除变量
```

将输出的 `scrypt:...` 字符串填入 `passwordHash` 字段。格式为 `scrypt:<盐>:<哈希>`——盐 16 字节（32 个 hex 字符），哈希 32 字节（64 个 hex 字符），即 `scrypt:<32hex>:<64hex>`。

## 创建专用低权限账号

**不要使用管理员账号作为 runAsUser。** 步骤：

1. 在 MeshCentral 创建一个专用用户（如 `davreader`）。
2. 仅授予该用户对目标设备/设备组的**远程控制 + 文件权限**（rights 包含位 8）。
3. 不要授予 siteadmin 或其他管理权限。
4. 将该用户的完整 ID 填入 `runAsUser`。完整 ID 格式取决于 domain：
   - **默认域**（domain id 为空字符串 `""`）：`user//davreader`
   - **非默认域**（domain id 为 `mydomain`）：`user/mydomain/davreader`

   > ⚠️ 不要写成 `user//<domain>//davreader`——这是把两种格式拼在一起的常见错误。默认域是 `user//davreader`（domain 段为空，两个斜杠连写），非默认域是 `user/<domain>/davreader`（单斜杠分隔 domain）。

## AList 挂载

在 AList 中添加 **WebDAV 存储**：

- 地址：`https://<server>/dav/<share>`
- 用户名 / 密码：share 配置的 username / 对应密码
- 建议开启「Web 代理 / 本地代理」以由服务端中转流量。

**Range 限制**：本网关不返回 206 Partial Content。无 `Range` 头与 `Range: bytes=0-` 均返回 200 完整文件；任何其他 Range 请求（如 `bytes=10-`、`bytes=0-99`）返回 416。因此**视频无法拖动进度条**，只能从头顺序播放。**不承诺** AList 侧代理缓存/整文件缓存能实现拖动，不要依赖该能力。

## Docker 部署

**上游镜像 `ghcr.io/ylianst/meshcentral:latest` 不包含本功能**（无 `meshdav.js`、`meshdav-route.js`、无 `webserver.js` 路由补丁）。`docker/compose.yaml` 直接引用该上游镜像，**不能用于启用本功能**。必须从本分支检出代码自行构建。

### 从本检出构建（推荐）

在 **source 根目录**（含 `meshdav.js`、`webserver.js`、`package.json` 的检出根）执行：

```bash
docker build -f docker/Dockerfile -t meshcentral-readonly-dav:local .
```

`docker/Dockerfile` 与 `docker/readonly-dav.Dockerfile` 构建流程相同，都通过 `COPY ./` 把本检出（含 `meshdav.js`、`meshdav-route.js`、`webserver.js` 补丁）打入镜像。运行：

```bash
docker run --name meshcentral-dav -d --restart unless-stopped \
  -p 443:443 \
  -v ./meshcentral-data:/opt/meshcentral/meshcentral-data \
  meshcentral-readonly-dav:local
```

- **端口**：容器默认 `PORT=443`（HTTPS，WebDAV 走此端口）、`REDIR_PORT=80`（HTTP 重定向，可选；上面命令仅映射 443，不暴露 80）。
- **配置持久化**：`config.json` 位于卷 `/opt/meshcentral/meshcentral-data/config.json`。首次启动 entrypoint 会从 `config.json.template` 拷贝；要启用 `readOnlyDav`，编辑该持久化文件后重启容器。
- **凭证隔离**：`config.json.template` 不含 `readOnlyDav` 段，DAV 凭证（`passwordHash`）由用户独立配置，**不复用 admin 密码或 `sessionKey`**。entrypoint 仅将 `_sessionKey` 转为 `sessionKey`，不涉及 DAV 凭证。
- WebDAV 复用 MeshCentral 已有 HTTPS 端口，不需要额外端口。

### 关于已有 compose 文件

- `docker/compose.yaml`：**上游 compose**，`image: ghcr.io/ylianst/meshcentral:latest`，镜像不含补丁。若要用它启用本功能，必须把 `image:` 换成本地构建的 `meshcentral-readonly-dav:local`，或改为 `build:` 从本检出构建（新增 build context）。
- `docker/readonly-dav-compose.yaml`：已用 `build:`（context 为仓库根）从本地源构建，含补丁：

```bash
docker compose -f docker/readonly-dav-compose.yaml up --build
```

## Windows Agent

- **root 写法**：使用正斜杠，如 `"root": "C:/Data"` 或 `"root": "D:/Shares/Media"`。
- **文件名含 `:` `\\` 或控制字符**的项：会在 PROPFIND 列出，但无法通过 GET 访问（路径安全检查拒绝这些字符）。
- **大小写匹配**：Windows 下名称大小写匹配为**精确匹配**（`File.txt` 与 `file.txt` 视为不同项）。

## 安全说明与已知限制

- **只读**：仅支持 OPTIONS、PROPFIND、GET、HEAD；PUT/DELETE/MKCOL 等写方法返回 405。
- **协议10 下载与 consent**：协议10（文件流下载）不检查 consent。当有效 consent 带有 flag 4（notify）或 32（prompt）时，**fail closed → 403 Forbidden**，不静默放行。其他 consent flag（如 desktop=2、terminal=8）不影响下载，不误拒。
- **协议5 ls 超时**：ls 请求默认超时 35s。当 consent 带 (32|4) 时，有效超时覆盖 `consentTimeout`（默认 30s，可通过 `domain.consentmessages.consenttimeout` 自定义）+ 余量。Agent 隧道建立超时 30s，ls 隧道空闲关闭 60s，下载 op:ok 等待 20s。**状态码区分**：consent / ls 超时、Agent 隧道建立超时、隧道异常关闭 → **502**；下载 op:ok 等待超时 → **504**。
- **策略变更 / 撤权关闭旧 ls**：每次 ls / download 前重新评估权限并计算策略指纹（rights / consent / soptions / TLS）。指纹变化时关闭旧 ls 隧道、开新隧道。新 share 认证时关闭同名旧 manager。idle 关闭后下次 ls 重新评估。
- **独立 Basic 认证（异步 scrypt）**：每个 share 独立 Basic 认证，**不读取 `req.session` / cookie**，不复用管理员登录。密码用 `crypto.scrypt`（异步，不阻塞事件循环）验证，成功缓存 5 分钟（最多 1000 条），失败不缓存。未知 share 对假哈希跑 scrypt 消除时间差。
- **DAV 统一安全响应头**：所有 DAV 响应附加 `Content-Security-Policy: default-src 'none'; sandbox`、`X-Content-Type-Options: nosniff`、`Cache-Control: private, no-store`。文件下载附加 `Content-Disposition: attachment`（防 CRLF 注入，非 ASCII 用 RFC 5987 编码）。
- **无 Range / seek**：无 `Range` 头与 `bytes=0-` 返回 200 完整文件，其他 Range 返回 **416**（`Accept-Ranges: none`），**绝不返回 206**。大文件只能顺序读取。
- **符号链接**：服务端无法阻止 root 内的 symlink/junction 指向 root 外部。**不要在 root 下放置指向外部的链接**。未做符号链接隔离。
- **路径穿越防护**：parseDavPath 拒绝 `..`、`%2e%2e`、反斜杠、冒号、NUL、控制字符；坏编码返回 400。
- **限流**：若 `webserver.checkAllowLogin` 返回 false，返回 429。
- **多服务器不支持**：Agent 必须在本服务器在线（`wsagents`），首版不支持多服务器路由。Agent 离线返回 503。
- **需 HTTPS / TLS 反代**：Basic 认证明文传密码，必须通过 HTTPS 或 TLS 反向代理访问。
- **未验证项**：尚未与真实 Agent / AList / Docker 做端到端联调。Range、超时、consent、策略撤权等行为基于源码与单元测试，实际部署前请自行验证。
