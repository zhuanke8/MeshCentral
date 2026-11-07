# MeshCentral 只读 WebDAV 网关 — 状态说明

> **实验版，非 MeshCentral 上游内置功能。** 本快照自 `feat/readonly-webdav` 分支导出，源码 commit `3e6248e73a55c07fcb98d52cb04717112b77377c`。

## 镜像发布状态

| 架构 | 状态 | GitCode Release tag | 附件 |
|------|------|---------------------|------|
| ARM64 | **已发布** | `v1.3.1-dav-experimental-20261107-arm64` | `meshcentral-readonly-dav-experimental-linux-arm64.tar.gz` |
| AMD64 | **实验版，即将上传附件** | `v1.3.1-dav-experimental-20261107-amd64` | `meshcentral-readonly-dav-experimental-linux-amd64.tar.gz` |

> 附件上传后以 GitCode Release 页面实物为准。本文档不声称已上传，仅写发布地址与核验条件。

### 导入与架构核验

```sh
# ARM64
docker load -i meshcentral-readonly-dav-experimental-linux-arm64.tar.gz
docker inspect meshcentral-readonly-dav:experimental-arm64 --format '{{.Architecture}}'  # 期望 arm64

# AMD64
docker load -i meshcentral-readonly-dav-experimental-linux-amd64.tar.gz
docker inspect meshcentral-readonly-dav:experimental-amd64 --format '{{.Architecture}}'  # 期望 amd64
```

## 测试状态

- **AMD64 原始模拟测试：153/161 通过，8 项失败**（`test/meshdav.test.js`、`test/meshdav-route.test.js`、`test/meshdav-log.test.js`，exit=1）。
- 五模块 require（ws / modern-syslog / telegram / bufferutil / utf-8-validate）+ `meshcentral --help` smoke 通过（exit=0）。
- `apk del .build-deps` 后模块复验通过（exit=0）。
- 8 项失败可能与测试固定 50/100ms 超时且尚未创建隧道有关，**不声称 161 全过或已确认**。
- **未做容器启动验证，未做 Agent / AList 端到端联调。**

## 已知未修复项（不得谎称已修）

1. **close 后迟到权限 refresh 复活 manager**：已关闭的下载 / ls manager 在迟到的权限刷新时可能被复活，尚未修复。
2. **撤权测试缺断言**：撤权场景测试缺少「已连接的旧 WS 隧道被立即关闭」的断言，覆盖不完整。

## 构建与文档

- 构建与配置说明见 `docs/readonly-webdav.md`（启用配置、域路由安全、密码哈希生成、Docker 部署、AList 挂载）。
- 离线镜像构建 / `docker save` / `docker load` 用法见 `docker/README-offline-image.md`。
- AMD64 镜像通过 QEMU 10.0.13 + proot master 在独立 rootfs 中构建，`docker import` 导入（Dockerfile build 不成功）。

## 已知限制

- **Range / seek**：仅无 `Range` 头与 `Range: bytes=0-` 返回 200 完整文件，其他 Range 返回 416，**绝不返回 206**，不支持拖动进度条 / seek。
- **符号链接**：不提供 symlink / junction 物理隔离，`root` 不得含指向许可范围外的链接。
- **多服务器不支持**：Agent 须在本服务器在线，首版不支持多服务器路由。
