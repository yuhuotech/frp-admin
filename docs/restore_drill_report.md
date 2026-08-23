# 备份恢复演练记录

## 2026-07-28 本地隔离演练

环境：macOS Darwin，SQLite 3.51，OpenSSL，Go 工具链，Docker 内 MySQL 8.4/PostgreSQL 16 官方客户端与服务端；所有数据位于随机隔离目录/容器，演练结束后移入系统 Trash 并删除临时容器和网络。未读取或修改现有 Compose 数据卷。

### 已执行并通过

| 验证项 | 结果 | 证据范围 |
|---|---|---|
| SQLite WAL 一致性备份 | PASS | 使用真实 WAL 数据库和 `.backup`，恢复后 `integrity_check=ok`、`foreign_key_check` 无记录、探针数据行存在 |
| MySQL 8.4 备份恢复 | PASS | 真实 Server migration，官方 `mysqldump --single-transaction` 导出、`mysql` 导入空目标库，恢复后表存在且 Server readiness 通过 |
| PostgreSQL 16 备份恢复 | PASS | 真实 Server migration，官方 custom-format `pg_dump`、`pg_restore --single-transaction` 导入空目标库，恢复后表存在且 Server readiness 通过 |
| 统一恢复包 | PASS | 数据库、master key、CA/Server 证书与私钥同时归档；恢复前后 master key 哈希、CA DER 指纹一致 |
| PKI 有效性 | PASS | CA key/cert、Server key/cert 公钥匹配，恢复后 Server 证书通过 CA 验签 |
| 文件权限 | PASS | 恢复后 master key 与私钥为 `0600`，敏感目录为 `0700` |
| 防篡改 | PASS | 修改归档一个字节后，恢复在写目标前因 sidecar SHA-256 不匹配而拒绝 |
| 真实 Server 恢复启动 | PASS | 源实例完成 migration、管理员 bootstrap 和 Secret 创建；恢复实例 readiness 通过 |
| 恢复后认证 | PASS | 使用恢复前创建的管理员凭据登录成功，`/users/me` 可读 |
| Agent CA 连续性 | PASS | API 下载 CA 与恢复包 CA 指纹一致 |
| Secret 不回显 | PASS | 恢复后 Secret 元数据存在，API 响应无 `value` 字段 |
| 脚本静态检查 | PASS | `bash -n` 与 ShellCheck stable 对 `deploy/ops/*.sh` 无告警 |
| 悬空软链防护 | PASS | 自动回归覆盖 archive、sidecar、master key、PKI、keyring 和 SQLite target，均在写入前拒绝 |
| systemd unit 语法 | PASS | Ubuntu systemd 容器内 `systemd-analyze verify` 通过 |
| 历史 key ring 语义恢复 | PASS | old key 加密 Secret/升级 URL，new key 加密配置模板；归档并恢复 old/new key 后 Secret 可注入配置物化、升级 URL 可受控解密，缺 old key 时 Server 启动和读取均 fail-closed |

演练过程中首次发现并修复了 macOS Bash 3.2 在 `set -u` 下展开空 key ring 数组失败的问题。修复后重新执行完整恢复和最终归档类型回归，均通过。

### 尚未覆盖，仍是发布阻断项

| 未覆盖项 | 原因/下一步 |
|---|---|
| 三数据库业务数据逐表核对 | 已完成 schema/表数量和 Server readiness；仍需在预发布环境核对业务表行数、外键、审计链和 Secret 物化流程 |
| 配置 revision 发布 | 历史 Secret 与 revision 的恢复后物化已自动验证；真实 Agent 发布仍由 controlplane 恢复夹具验收 |
| 旧 Agent 重连/新 Agent 注册 | 需要隔离 Linux Agent 环境和可路由 gRPC 地址 |
| 恢复后配置发布/回滚 | 会改变节点状态，需在专用 Agent 上执行，不应由只读 smoke 自动触发 |
| Release 文件 SBOM 脚本实跑 | 本机未安装 Syft；镜像 SBOM 已由 CI workflow 定义，但仍需在 release job 生成并留存真实产物 |
| 备份加密、对象存储保留与跨故障域恢复 | 属于部署方 KMS/备份平台集成，仓库脚本只生成权限受限明文归档 |

因此，本记录不能作为整个项目“生产可用”的结论。虽然 PostgreSQL 16 与 SQLite 的 1000 Agent 短时重连基线及历史 key ring 语义恢复已通过，恢复后的 Agent 重连/配置发布与 7 天 soak 仍是发布阻断项。
