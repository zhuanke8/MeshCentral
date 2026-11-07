# 离线 Docker 镜像构建说明 — 只读 WebDAV 网关

> **实验版。** 本镜像在 MeshCentral 源码基础上加入实验性只读 WebDAV 网关，**非上游官方镜像**。源码 commit `3e6248e73a55c07fcb98d52cb04717112b77377c`。

## 镜像发布状态（2026-11-07）

| 架构 | 状态 | GitCode Release tag | 附件文件 | 镜像标签 |
|------|------|---------------------|----------|----------|
| ARM64 | **已发布** | `v1.3.1-dav-experimental-20261107-arm64` | `meshcentral-readonly-dav-experimental-linux-arm64.tar.gz` | `meshcentral-readonly-dav:experimental-arm64` |
| AMD64 | **实验版，即将上传附件** | `v1.3.1-dav-experimental-20261107-amd64` | `meshcentral-readonly-dav-experimental-linux-amd64.tar.gz` | `meshcentral-readonly-dav:experimental-amd64` |

> 附件上传后以 GitCode Release 页面实物为准。本文档不声称已上传，仅写发布地址与核验条件。

### AMD64 构建方式

AMD64 镜像未通过 `docker build` 构建（Dockerfile build 在嵌套环境中被权限阻断），而是：

1. 在独立 rootfs 中使用 **QEMU 10.0.13 + proot master** 运行来宾构建脚本（`image-build/amd64-build.sh`）
2. 来宾脚本完成 npm 依赖安装、语法检查、单元测试、模块验证
3. 宿主脚本（`image-build/finalize-amd64.py`）通过 `docker import` 将 rootfs tar 包导入为镜像
4. 经 `docker save` → gzip 打包，再 `docker load` 回验完整性

### AMD64 测试结果（原始模拟，非容器内）

- **单元测试：153/161 通过，8 项失败**（exit=1）
- 五模块 require + `meshcentral --help` smoke：exit=0（通过）
- `apk del .build-deps` 后模块复验：exit=0（通过）
- QEMU scrypt 耗时约 1.4s
- 8 项失败可能与测试固定 50/100ms 超时且尚未创建隧道有关，**不声称 161 全过**
- **未做容器启动验证，未做 Agent / AList E2E 联调**

## 离线包导入与架构核验

```sh
# ARM64（已发布）
docker load -i meshcentral-readonly-dav-experimental-linux-arm64.tar.gz
docker inspect meshcentral-readonly-dav:experimental-arm64 --format '{{.Architecture}}'  # 期望 arm64

# AMD64（实验版，附件上传后）
docker load -i meshcentral-readonly-dav-experimental-linux-amd64.tar.gz
docker inspect meshcentral-readonly-dav:experimental-amd64 --format '{{.Architecture}}'  # 期望 amd64
```

核验入口与卷：

```sh
docker inspect meshcentral-readonly-dav:experimental-amd64 \
  --format 'ENTRYPOINT={{.Config.Entrypoint}} WORKDIR={{.Config.WorkingDir}} VOLUMES={{json .Config.Volumes}}'
```

## 启动前配置（本任务不部署）

**不能直接 `docker run` 启动即用 DAV。** 须先完成以下配置：

1. 参考 `docker/readonly-dav-compose.yaml` 编排结构。
2. 配置**独立 DAV Basic 认证**（`username` + `passwordHash`，scrypt 哈希，见 `docs/readonly-webdav.md`），**不得复用 MeshCentral 管理员凭证**。
3. 配置设备 / 路径白名单：指定目标 Agent `nodeId`、`root` 远程根路径、`runAsUser` 低权限账号。
4. 生成自有 `config.json`（基于 `docker/config.json.template`），填入自有域名 / 证书 / DAV shares 配置。

```sh
# 示例（须替换为自有配置，仅供参考，本任务不执行）
docker run -d --name meshdav \
  -p 443:443 -p 80:80 \
  -v /path/to/your-config.json:/opt/meshcentral/meshcentral-data/config.json \
  -v meshcentral-data:/opt/meshcentral/meshcentral-data \
  -v meshcentral-files:/opt/meshcentral/meshcentral-files \
  -v meshcentral-backups:/opt/meshcentral/meshcentral-backups \
  -v meshcentral-web:/opt/meshcentral/meshcentral-web \
  meshcentral-readonly-dav:experimental-amd64
```

入口点为 `/opt/meshcentral/entrypoint.sh`，配置模板 `docker/config.json.template`。**本任务不启动服务。**

## 已知限制与未修复项

- **close 后迟到权限 refresh 复活 manager** — 未修复。
- **撤权测试缺断言** — 缺「已连接旧 WS 隧道立即关闭」断言。
- **未真实联调** — 153/161 模拟测试通过 ≠ 真实 Agent / AList / Docker 端到端验证。
- **未容器启动验证** — 镜像已 import/save/load 回验，但未实际 `docker run` 启动。
- **Range / seek** — 仅无 `Range` 与 `Range: bytes=0-` 返回 200 完整文件，其他 Range 返回 416，**绝不返回 206**。
- **符号链接** — 不提供 symlink / junction 物理隔离，`root` 不得含指向许可范围外的链接。
- **多服务器不支持** — Agent 须在本服务器在线。

详见 `docs/readonly-webdav.md` 与 `README-DAV-STATUS.md`。
