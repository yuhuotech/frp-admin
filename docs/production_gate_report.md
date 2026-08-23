# frp-admin 生产门禁报告

> 报告日期：2026-07-29  
> 结论：**BLOCKED，不得批准生产发布**  
> 当前硬阻断：完整实现尚未形成可追溯的候选 commit/tag；in-app Browser 视觉验收缺失；168 小时 soak 尚无完整通过报告

## 1. 判定规则

- `PASS`：本工作区在报告日期实际执行并得到成功结果，或存在可定位的留存报告。
- `REQUIRED`：门禁实现已存在，但当前 release 尚未关联具体环境结果、workflow run 或产物。
- `IN PROGRESS`：正在收口，不能作为通过证据。
- `BLOCKED`：生产批准的硬阻断项未满足。

`make production-check` 只串联可在开发机/普通 CI 中确定性执行的检查。它返回成功不等于生产批准，也不会把外部数据库、privileged systemd、Trivy、签名或 soak 标成通过。

## 2. 本次环境

| 项目 | 值 |
|---|---|
| 主机 | Apple Silicon arm64，Darwin 25.5.0 |
| Go | 1.26.5 darwin/arm64 |
| Node.js / npm | 26.0.0 / 11.12.1 |
| SQLite | 3.51.0 |
| OpenSSL | 3.6.3 |
| Docker | 29.2.1；数据库验证使用 MySQL 8.4、PostgreSQL 16 官方镜像 |
| 安全扫描 | Trivy 0.67.2；govulncheck；Web production audit |

本地结果只能证明代码和隔离容器行为，不能替代目标生产网络、数据库 TLS、KMS、对象存储、Linux 内核/cgroup、容量与故障域验证。

## 3. 证据表

| 门禁 | 状态 | 证据/命令 | 范围与限制 |
|---|---|---|---|
| 候选版本可追溯性 | **BLOCKED** | `HEAD=a9044bb` 仅包含 `LICENSE`，其余实现仍未被 Git 跟踪 | 必须先形成受审候选 commit/tag，再重跑并绑定全部门禁证据 |
| Protobuf 生成确定性 | PASS | `scripts/production-check.sh`：生成前临时快照，生成后 `diff -ru`；另执行 `git diff` | 不依赖文件是否已被 Git track |
| Go 全量测试 | PASS | `(cd contracts && go test ./...)`、`(cd agent && go test ./...)`、`(cd server && go test ./...)` | 本地工具链 |
| Go 全量 race | PASS | contracts、agent、server 分别执行 `go test -race ./...` | 不代表长期资源稳定性 |
| Go vet / 二进制构建 | PASS | 三模块 `go vet ./...`；Agent/Server `go build -trimpath` | 本地 arm64 构建；release 多架构仍需 workflow |
| Web lint/test/audit/build | PASS | `npm run lint`、`npm test -- --run`、`npm run audit:production`、`npm run build` | 浏览器 Playwright 另属环境门禁 |
| Shell 语法 | PASS | `bash -n` 覆盖 `deploy/`、`contracts/`、`scripts/` shell 文件 | ShellCheck 由 Linux CI 独立执行 |
| SQLite migration/repository | PASS | Server full/race suite；SQLite backup/restore `integrity_check`、`foreign_key_check` | 单机数据库 |
| MySQL 8.4 contract | PASS | `FRP_ADMIN_INTEGRATION_DB_DRIVER=mysql ... go test ./internal/store/sqlstore -run 'TestDatabase(Contract|MigrationReplay)' -count=1 -v` | 隔离 Docker，无生产 TLS/HA |
| PostgreSQL 16 contract | PASS | `FRP_ADMIN_INTEGRATION_DB_DRIVER=postgres ... go test ./internal/store/sqlstore -run TestDatabaseContract -count=1 -v` | 隔离 Docker，无生产 TLS/HA |
| PostgreSQL 16 短暂不可用故障注入 | PASS | `make production-check-db-fault`：DB 停止期间 readiness=503、runtime collection 写请求非 2xx 且恢复后无该幂等键，frp 代理持续可访问独立后端；同一 Server 容器恢复 ready，Agent 自动重连，离线排队的 `collect_runtime` 任务恰好成功一次并写入 Agent journal | 短暂单节点故障；不替代生产 HA failover、高延迟/丢包和长时 soak |
| Secret/配置/升级 URL 静态加密 | PASS | Server API/service tests覆盖 API/Task/Audit/DB 不泄密、AAD tamper、历史 key、缺 key fail-closed | master key/KMS 运维仍由部署方负责 |
| 出站网络与诊断脱敏 | PASS | Agent 升级与 Server Webhook 禁环境代理并固定已校验 IP；HTTPS、host allowlist、redirect 和 IANA special-use CIDR 测试通过；canary Secret 测试覆盖 Agent diagnostic/journal、Server task/task_step 与 API DTO | 私网 Webhook 仅允许 `allowPrivateAddresses` 与 `allowedHosts` 双重显式配置；生产出口仍应由防火墙二次限制 |
| RBAC、审计与管理模式 | PASS | HTTP/Store tests覆盖角色、事务审计、`observe/managed`、mode TOCTOU 与单节点变更互斥 | 单组织权限模型 |
| 任务取消/超时/迟到结果 | PASS | Server full/race；升级 timeout 后迟到结果不得覆盖终态 | 单 Server 进程模型 |
| Runtime snapshot | PASS | Gateway/Store/API tests；旧快照不覆盖、新快照可推进、Agent 未来时钟超限拒绝 | 当前只存最新快照，不是历史 TSDB |
| 备份恢复与历史 key ring | PASS | `deploy/ops/test.sh`；old-key Secret 注入配置、old-key 升级 URL 物化、缺 old key 启动/读取失败 | SQLite 自动语义 E2E；三库工具恢复证据见 `restore_drill_report.md` |
| Agent 证书注册/轮换 | PASS | PKI/Agent Gateway tests；返回 expiry 与 X.509 leaf `NotAfter` 精确一致 | 真实恢复后旧 Agent 重连见下方 control-plane 门禁 |
| 部署风险中心 | PASS | Finding/scan 三库 migration 与 repository contract；风险 API/Web 工作台；类型化修复协议和 Agent remediation；Agent/Server/Contracts full、vet、race 与 Web tests 覆盖；自动修复的真实 privileged E2E 证据限定为 Linux/systemd | 三条首期规则；逐规则 completed/unknown，连续两次规则 clean 才 resolve；代理重名无自动修复；Darwin 只读 inspect/risk scan 与条件性配置权限修复尚未使用最新 Agent 二进制完成真实 macOS 复验，不计入本项自动修复 PASS 证据 |
| Privileged Linux/systemd E2E | PASS（候选工作区） | `deploy/e2e/systemd/run-container.sh`：Test01-10 全通过；覆盖 root-owned 父目录、非特权 rename 拒绝、类型化 helper service probe/start/stop/restart、配置与升级回滚、风险扫描/权限修复/Admin loopback | helper 是唯一服务写权限通道，fixture 不安装 polkit；尚未绑定正式 commit/tag，release 必须留存对应 runner 日志 |
| 真实 control-plane 恢复 E2E | PASS | `make production-check-controlplane`：真实 `backup.sh` / `restore.sh` 恢复到全新 Server 命名卷；旧 Agent 原证书重连、CA SHA-256 指纹连续、old-key Secret 配置物化与回滚、新非 root Agent 注册/上线/runtime 采集均通过；25 Agent reconnect smoke 0 failures | 当前代码候选证据；正式 tag 仍必须关联运行日志 |
| Web Playwright E2E | PASS | Web Compose + Chromium Playwright 真实执行 7/7 | 当前代码候选证据；正式 tag/commit 仍需关联 run 与失败 artifact 策略 |
| 前端目标浏览器视觉验收 | **BLOCKED** | 本轮 in-app Browser 能力不可用，未能对当前页面执行桌面/移动视口截图与交互视觉复核 | Playwright 功能 E2E 不能替代布局、溢出、遮挡和响应式视觉验收；工具恢复后需重跑并留存截图 |
| 真实主机兼容、整改与数据面 | PASS（有限范围） | [real_host_validation_report.md](./real_host_validation_report.md)：m200 root ownership/loopback、machp 单实例；最终 4 个已列明 hostname/version 的 online clients、13 TCP proxies，代表数据面通过 | 公网证据只证明 Admin HTTP API 不可达，不声称所有 TCP 探测必然失败；WSL 仍为 `ubuntu:ubuntu`，所有权 hardening 未完成；不替代候选 release、systemd E2E 与 soak 门禁 |
| Go/Node 依赖漏洞扫描 | PASS | 本地 govuln 可达漏洞 0；`npm run audit:production` 仅保留 React Router `GHSA-qwww-vcr4-c8h2` scoped exception | 项目是 Vite/Nginx 纯静态 SPA，不包含 RSC/SSR/server action runtime；任何其他 high/critical 仍阻断，未来引入 RSC/SSR 必须撤销例外 |
| 镜像 Trivy | PASS | Trivy 0.67.2 扫描 Server/Web 的 amd64/arm64 四个候选镜像均 0 HIGH/CRITICAL；安全收口后本地 arm64 最终镜像再次扫描为 0/0 | 当前代码候选证据；正式 tag 仍需绑定 workflow、不可变 digest 和原始扫描日志 |
| SPDX SBOM artifact | REQUIRED | security/release workflow 定义 image/archive SBOM 生成与上传 | 需为正式 tag 留存 artifact；Trivy PASS 不能替代 SBOM 产物 |
| Release 签名/provenance | REQUIRED | `.github/workflows/release.yml`：多架构镜像、cosign、SBOM | 必须记录 tag、digest、签名与 workflow run |
| 1000 Agent 短时压力基线 | PASS（非发布充分条件） | `deploy/e2e/controlplane/README.md` 记录 SQLite/PostgreSQL/MySQL 8.4 本地基线；MySQL 2000 sessions 0 failures，welcome/reconnect p95=4.747/4.201 ms，Server peak=69.23% CPU/90.87 MiB | 6 秒连接窗口、采样有限，不能替代 soak |
| 100 Agent / 100 并发 task churn | PASS（非发布充分条件） | SQLite 实测 500/500 `inspect`/`collect_runtime` 任务成功，0 failed/timeout；p50/p95/p99=175.784/228.719/256.002 ms，Server peak=37.25% CPU/142.40 MiB | 短时 SQLite 候选基线；不代表生产数据库持续并发能力 |
| 168 小时 soak | **BLOCKED** | `make production-check-soak` / `deploy/soak/run.sh`；当前没有 `soak-results/.../report.md` 完整通过产物 | 至少 100 Agent；必须保留 samples、load JSON、资源趋势与最终报告 |

## 4. 发布决策

当前不能标记 production ready。完成以下动作后才能重新评审：

1. 将完整实现纳入版本控制，完成代码审查并冻结候选 commit/tag。
2. 为冻结候选版本重跑 privileged systemd E2E，留存所有权、非特权替换拒绝、verify、restart 和失败回滚证据。
3. in-app Browser 恢复后完成当前 Web 的桌面/移动视口关键工作流视觉验收并留存截图。
4. 在目标 Linux 与目标数据库环境完成 168 小时 soak，`SOAK_REQUIRE_168H=true`，报告无任务丢失且 goroutine、FD、RSS、连接池无持续增长。
5. 为候选 commit/tag 关联 control-plane、Web E2E、MySQL、PostgreSQL 的具体运行记录。
6. 为同一候选 tag 关联 security/release workflow run、Trivy 结果、SBOM、镜像 digest、cosign 签名与 provenance。
7. 在目标故障域执行恢复演练并记录 RPO/RTO、CA 指纹、历史 key、旧/新 Agent 与配置发布回滚结果。

任一证据缺失、过期或不对应同一候选版本，状态保持 `BLOCKED`。
