# frp-admin 生产运维 Runbook

## 1. 适用范围与硬约束

本 Runbook 适用于单组织、Linux/systemd 部署。SQLite 只用于单机小规模；接近 1000 Agent 时应使用 MySQL 8.4 或 PostgreSQL 16。一个 Server 实例只能连接一个主数据库，三种数据库“兼容”不等于同一实例同时写三套数据库。

当前代码处于 production candidate，尚未获得生产批准。完整实现尚未形成可追溯候选 commit/tag，168 小时 soak 也未完成；没有绑定同一候选版本的完整证据时，不得以短时压测或 CI 绿灯替代。

备份恢复单元必须同时包含：业务数据库、当前 master key、仍被 Secret 引用的历史 key ring、Agent CA 和 Server 证书私钥。缺少任一部分都不能算可恢复备份。归档包含私钥，离机前必须用组织的 KMS/备份平台加密；脚本不内置自创加密协议。

脚本在数据库快照前后校验 key/PKI 是否变化，但无法替代发布锁。master key、PKI 或数据库 migration 变更期间禁止备份；建议在发布窗口暂停控制面写操作后执行。SQLite Online Backup 不要求停止 Server，MySQL/PostgreSQL 业务写入由官方一致性快照处理。

## 2. systemd 部署

1. 创建系统用户 `frp-admin`，安装二进制到 `/usr/local/bin/frp-admin-server`。
2. 安装 [service 示例](../deploy/systemd/frp-admin-server.service) 和 [配置示例](../deploy/systemd/server.yaml)。将示例域名替换为 Agent 实际访问的稳定 DNS 名称。
3. `/etc/frp-admin/database-dsn` 必须为 root 所有、`0600`。SQLite 内容是 `/var/lib/frp-admin/frp-admin.db`；MySQL/PostgreSQL 内容是 Server 使用的 DSN。不要把 DSN 写进 unit 或命令行。
4. `/var/lib/frp-admin/master.key`、`pki/ca.key`、`pki/server.key` 必须为 `frp-admin` 所有、`0600`；目录为 `0700`。
5. 执行 `systemd-analyze security frp-admin-server.service`，再启动服务。反向代理负责浏览器 HTTPS；Agent gRPC 8443 直接使用 Server mTLS。

若使用外部 PKI 文件路径，应按实际路径增加 `ReadOnlyPaths`，并同时配置四个 PKI 文件；禁止只替换 CA 或只替换 Server 证书。

### Agent 与 root helper

生产 Agent 以专用 `frp-agent` 用户运行。frp 二进制应为 `root:root 0755` 或更严格的只读可执行模式，group/other 不得可写；frp 配置应匹配目标 `frpc.service`/`frps.service` 的 effective UID，并将 group/other 权限清零。不要机械地把非 root 服务的 `0600` 配置改为 root 所有，否则服务会失去读取权限。

需要服务启停或自动修复配置权限、frps Admin API loopback 时，安装 root-owned helper binary、root-owned `0600` helper allowlist 和 `0660 root:frp-agent` socket。helper 仅允许固定 `/etc/frp/{frpc,frps}.toml`、`/opt/frp/bin/{frpc,frps}` 与 role 对应的单一 systemd unit，使用 `SO_PEERCRED` 校验调用者。服务请求只有 start/stop/restart 三种类型，不接受 unit、路径、参数或 Shell；start/restart 的 reset-failed 是 helper 内部固定步骤。`/etc/frp` 与 `/opt/frp/bin` 默认必须为 `root:root 0755`，Agent 不得拥有 rename 替换权限。部署后必须执行 `make production-check-systemd`；当前候选已覆盖目录所有权、非特权替换拒绝、verify、restart 和失败回滚，正式 release 仍须绑定同一 commit/tag 的留存日志。

常规配置发布、回滚和升级只有在 frp 与 Agent 使用同一非 root effective UID，且目标文件和父目录通过安全可写 preflight 时才宣告 capability；其中需要的 restart/stop/start 统一经 helper，状态和健康检查仍由 Agent 本地只读查询。root-running frp 默认不宣告这些资源变更能力；不得通过把 root 服务资源目录 `chown frp-agent` 强行开启。

## 3. 一致性备份

所有示例都应由受限的本机运维账号执行，输出目录不得位于 Web 根目录或共享临时目录。

### SQLite

脚本使用 SQLite Online Backup API，包含已提交 WAL 页面；不允许直接 `cp frp-admin.db`。

```bash
deploy/ops/backup.sh --driver sqlite \
  --sqlite-path /var/lib/frp-admin/frp-admin.db \
  --master-key /var/lib/frp-admin/master.key \
  --pki-dir /var/lib/frp-admin/pki \
  --output /var/backups/frp-admin/backup.tar
```

### MySQL 8.4

创建 `0600` 的 `/root/.frp-admin-mysql.cnf`，使用只具备目标库备份所需权限的账号。文件格式为 MySQL 官方 `[client]` 配置，密码不出现在参数或日志。

生产连接必须启用 TLS 并验证数据库证书；不要使用演练环境中的 `ssl-mode=DISABLED` 或以 `get-server-public-key` 代替 TLS。

```bash
deploy/ops/backup.sh --driver mysql --database frpadmin \
  --mysql-defaults-file /root/.frp-admin-mysql.cnf \
  --master-key /var/lib/frp-admin/master.key \
  --pki-dir /var/lib/frp-admin/pki \
  --output /var/backups/frp-admin/backup.tar
```

备份使用 `mysqldump --single-transaction`，因此业务表必须保持 InnoDB。DDL 变更期间不要执行备份。

### PostgreSQL 16

使用 `PGHOST`、`PGPORT`、`PGUSER`、`PGDATABASE`、`PGSSLMODE` 和 `PGPASSFILE`；`.pgpass` 必须为 `0600`。脚本生成官方 custom-format dump。

```bash
PGHOST=db.internal PGUSER=frp_backup PGPASSFILE=/root/.pgpass PGSSLMODE=verify-full \
deploy/ops/backup.sh --driver postgres --database frpadmin \
  --master-key /var/lib/frp-admin/master.key \
  --pki-dir /var/lib/frp-admin/pki \
  --output /var/backups/frp-admin/backup.tar
```

master key 轮换后，对每个仍在数据库 `secrets.key_version` 或 `upgrade_plans.artifact_key_version` 中出现的版本增加 `--key-version VERSION=FILE`。备份完成后校验 `.sha256`，使用备份平台加密并复制到独立故障域。至少每日备份，保留周期由业务 RPO 决定；每月至少做一次隔离恢复演练。

输出父目录必须预先创建、不能是软链，且不能允许 group/other 写入；脚本会拒绝悬空软链和不安全父目录，避免归档路径被替换。

## 4. 恢复

恢复必须进入全新主机或全新空数据库。脚本拒绝覆盖现有 key、PKI、SQLite 文件或非空 MySQL/PostgreSQL schema。先停止目标 Server，禁止两个 Server 同时使用同一 SQLite 文件。

数据库和文件系统无法形成跨介质原子事务。恢复任一步失败时，应废弃该空目标库和目标目录并从头恢复，禁止在半恢复状态上手工补文件后启动 Server。

```bash
deploy/ops/restore.sh --archive /secure/backup.tar \
  --sqlite-target /var/lib/frp-admin/frp-admin.db \
  --master-key-target /var/lib/frp-admin/master.key \
  --keyring-target /var/lib/frp-admin/keyring \
  --pki-target /var/lib/frp-admin/pki
```

MySQL 恢复增加 `--database frpadmin --mysql-defaults-file FILE`；PostgreSQL 恢复增加 `--database frpadmin` 并设置同备份一致的 `PG*` 认证环境。数据库需预先创建且为空。恢复不会创建数据库账号、TLS 配置或外部 Webhook secret，这些由基础设施 secret 管理恢复。

恢复后以恢复出的 key ring 更新 `masterKey.currentVersion` 和 `masterKey.keyFiles`，启动 Server，再执行。Server 会扫描 Secret 与升级计划引用的 key version，缺任一历史 key 都会拒绝启动：

```bash
deploy/ops/smoke.sh --base-url https://admin.example.com \
  --username restore-auditor --password-file /run/secrets/restore-password \
  --expected-ca /var/lib/frp-admin/pki/ca.crt
```

Smoke 验证 live/ready、登录、数据库读取、CA 身份，并在存在配置 revision 时实际解密一次。完整演练还必须验证旧 Agent 重连、创建一次性新 Agent 注册 token、测试节点配置发布/回滚；后两项会改变生产状态，未自动放入 smoke 脚本。

## 5. 风险扫描与受控修复

风险中心的扫描是独立、只读的 `risk_scan` 任务（Agent 协议仍使用 InspectCommand），admin/operator 可对在线的 observe 或
managed 节点发起；viewer/auditor 只能查看。扫描只接收脱敏 Finding，不展示配置
原文、token、代理名或日志原文。平台按规则记录 completed/unknown：某项输入失败
只阻止依赖它的规则推进恢复，其他已完成规则可独立对账。不应手工用 unknown 结果
将既有 Finding 标为已解决；同一规则连续两次成功完成且未再发现后才自动 resolve。

自动修复只允许 managed 节点和平台声明的类型化 action：

| 风险 | Action | 执行前检查 | 影响/回滚 |
|---|---|---|---|
| 配置 token 权限过宽 | `restrict_config_permissions` | Linux/systemd、普通文件、无扩展 ACL、服务用户在 `0600` 下可读、Finding fingerprint 未变化 | 不重启服务；verify 或落盘失败恢复原 mode |
| frps Admin API 非 loopback | `bind_admin_api_loopback` | server role、admin、维护影响确认、TOML 配置、Finding fingerprint 未变化、Agent capability 可用、desired/observed revision 一致 | 重启 frps，客户端和代理短暂重连；控制面派生并原子关联新 revision，Agent 走 verify、备份、原子替换、健康检查和自动回滚 |
| 代理名称冲突 | 无 | 先确认所有 frpc 实例、代理业务归属和当前流量 | 人工合并/改名/停实例；平台不得猜测权威配置后自动停止 |

执行修复前先记录节点、Finding ID、任务 ID、当前配置 SHA-256、服务 PID/重启计数、
客户端与代理数量。修复后检查任务中的 backup ID 与 rollback 状态，重新扫描两次，
并验证代表性数据面。资源在审批后发生变化时 CAS 前检会拒绝执行，此时应重新扫描，
不得绕过 fingerprint 强制下发。

权限修复恢复原 mode 时，应使用任务记录对应的配置文件和原 mode，并再次运行目标
frp 二进制的 `verify`。Admin API 修复失败优先依赖 Agent 已执行的配置事务回滚；
若进入 `FAILED_MANUAL`，从该任务 backup ID 对应备份恢复，verify 后重启，并核对
控制连接、代理数和数据面。禁止通过直接开放公网 Admin API 来规避控制面采集失败。

## 6. 发布门禁

先运行可重复的仓库内门禁：

```bash
make production-check
```

该命令覆盖 generate、全量 Go test/race/vet、Web lint/test/build、二进制构建、Shell 语法和历史 key ring 备份恢复。以下门禁必须单独执行并留存报告，不能由上述命令假定通过：

```bash
# MySQL 与 PostgreSQL 分别执行一次
FRP_ADMIN_INTEGRATION_DB_DRIVER=postgres \
FRP_ADMIN_INTEGRATION_DB_DSN='postgres://...' make production-check-database

make production-check-systemd
make production-check-controlplane

# 必须指向明确的 Linux Server 进程或容器
SOAK_SERVER_CONTAINER=frp-admin-soak make production-check-soak
```

镜像 Trivy、SBOM、签名与 provenance 由 `.github/workflows/security.yml` 和 `.github/workflows/release.yml` 执行。正式发布必须关联具体 workflow run、镜像 digest、SBOM 和签名，而不是只确认 workflow 文件存在。完整状态见 [production_gate_report.md](./production_gate_report.md)。

## 7. 发布、SBOM 与回滚

发布产物先构建到独立目录，再用 Syft 生成逐文件 SPDX JSON 和 SHA-256：

```bash
deploy/ops/release-metadata.sh --output-dir dist/release bin/frp-admin-server bin/frp-agent
deploy/ops/verify-release.sh dist/release
```

Security workflow 生成镜像 SPDX SBOM，并用 Trivy 阻断有可修复 HIGH/CRITICAL 漏洞的镜像；release workflow 负责发布产物 SBOM 与签名。正式发布需记录 workflow run、镜像 digest、数据库 migration 版本、frp 兼容矩阵和回滚版本。升级前先完成备份；应用回滚不能自动回退破坏性数据库 migration，因此 migration 必须保持向后兼容或提供经演练的前向修复脚本。
