# frp-admin 生产就绪实施计划

> 基线日期：2026-07-28  
> 范围：单组织私有化部署，Linux systemd，最多 1000 Agent  
> 数据库：SQLite 用于单机小规模；MySQL/PostgreSQL 用于正式规模部署

> 执行状态：A-C 核心代码、风险中心与多数自动化门禁已落地，D 阶段同方言备份恢复、历史 key ring、systemd/release fixture 已实现；最新 root helper privileged systemd E2E 已通过，前端视觉验收尚未通过，跨方言业务数据迁移仍是后续能力。当前生产批准状态以 [production_gate_report.md](./production_gate_report.md) 为准；完整实现尚未形成可追溯候选 commit/tag，168 小时 soak 也尚未完成。

## 1. 生产定义

“生产可用”必须同时满足功能闭环、安全、可靠性、可观测、运维交付和容量六个门槛。代码合并、单元测试通过或 Docker Compose 能启动都不单独构成生产就绪。

最终发布门槛：

| 维度 | 验收标准 |
|---|---|
| 核心闭环 | 注册、在线、检查、启停、配置发布/回滚、升级、任务恢复均有真实 Linux E2E |
| 安全 | 无任意 Shell；Secret 不回显/不落日志；mTLS 证书可轮换；权限矩阵和依赖/镜像扫描通过 |
| 数据 | SQLite/MySQL/PostgreSQL migration、备份、恢复、升级重放通过；恢复后可登录、解密和发布 |
| 可靠性 | 故障注入无任务静默丢失；配置/升级失败自动恢复；控制面中断不影响 frp 数据面 |
| 容量 | 1000 Agent 心跳与重连压测达到 SLO；MySQL/PostgreSQL 无持续锁等待或连接泄漏 |
| 稳定性 | 100 个 Agent 连续运行 7 天，无任务丢失、goroutine/FD/内存持续增长 |
| 运维 | metrics、告警、结构化日志、runbook、升级/回滚、备份/恢复文档齐全 |

## 2. 分阶段计划

### 2.1 短期（0-3 月）：生产 P0

#### 阶段 A：安全与数据边界

- 字段级 Secret：只写不回显、配置引用、物化注入、key version 与轮换；
- 用户与 RBAC 管理、禁用用户撤销 Session、最后一个管理员保护；
- 审计查询及关键失败审计，禁止记录 token、配置正文和 Secret；
- 登录限流、CSRF、Cookie、CSP、mTLS、证书轮换的安全测试；
- SQLite/PostgreSQL migration 事务化，MySQL DDL 中断可重放。

退出条件：角色权限矩阵自动化测试通过；数据库、日志、API 响应中均无法检索到测试 Secret 明文。

#### 阶段 B：控制与恢复闭环

- start/stop/restart/status、任务取消语义、幂等和状态机；
- raw TOML validate/diff、reload/restart 判定、desired/observed、漂移检测；
- Agent 全局操作锁、磁盘/权限/路径前检、事务 journal 和启动恢复；
- frp 升级计划、checksum、架构/版本校验、健康窗口和自动回滚；
- 控制面重启、Agent 断网、数据库短暂不可用后的任务恢复。

退出条件：每个崩溃点均有故障注入测试；任务最终状态、节点 revision、文件和 systemd 状态一致。

#### 阶段 C：可观测与告警

- Prometheus `/metrics`：HTTP/gRPC、Agent session、任务、发布、升级、数据库与事件队列；
- 统一结构化日志字段和全链路 request/task/node/command ID；
- 节点失联、服务失败、配置漂移、任务超时、发布/升级失败告警；
- Webhook 签名、重试、退避、幂等和死信记录；
- Dashboard、告警确认/恢复和操作审计。
- 风险中心 Finding 持久化、显式只读扫描、逐规则 completed/unknown 语义、连续两次规则 clean 确认恢复；
- 类型化修复命令、资源 fingerprint CAS、RBAC/幂等/审计、Agent 本地备份和失败回滚；首批只自动处理配置权限与 Admin API loopback，代理重名保持人工维护。

退出条件：用故障注入触发每类告警，并验证指标、日志、Webhook 和 UI 指向同一资源。

#### 阶段 D：运维与交付

- SQLite 一致性备份；MySQL/PostgreSQL 官方工具备份编排；
- 数据库、master key、Agent CA 的统一备份/恢复 runbook；
- 同方言 SQLite/MySQL/PostgreSQL 一致性备份恢复已完成；跨方言版本化导出/导入作为后续迁移项目；
- Agent 安装/升级/卸载包、systemd hardening、最小 sudo/文件权限；
- root helper 固定资源 allowlist：二进制 root-owned，配置 owner 匹配 frp 服务 effective UID，Agent 通过 `SO_PEERCRED` socket 发送类型化请求；
- Agent 部署风险自检：Admin API 非 loopback、含 inline token 的配置权限宽于 `0600`、proxy duplicate/already-exists 日志形成持久 Finding；检查失败为 unknown，不得误恢复；
- 多架构镜像、SBOM、漏洞扫描、签名、校验和与 release notes。

退出条件：在全新环境完成一次备份恢复，旧 Agent 重连、新 Agent 注册、Secret 解密和配置发布均成功。

### 2.2 中期（3-12 月）：规模与企业能力

1. 1000 Agent 压测、100 并发操作、重连风暴和慢数据库测试；
2. 多副本控制面所需的 session ownership/lease；达不到 SLO 时再引入 NATS 通知层；
3. OIDC/LDAP、审批策略、批量灰度升级与暂停/继续；
4. frp 版本兼容矩阵、结构化代理表单、配置语义 diff；
5. 外部 Prometheus/Loki 集成和企业通知渠道。

### 2.3 长期（1 年以上）：产品化扩展

- Windows Service、launchd 与非 systemd Linux 的服务生命周期适配，以及依赖该生命周期的配置事务和 frp 升级；该缺口不包含已与 lifecycle 解耦的只读 inspect/risk scan；
- 跨 frps 容量和容灾编排；
- GitOps、策略即代码和稳定开放 API；
- 只有商业目标明确后才重新设计多租户、配额、计费和租户密钥边界。

## 3. 并行工作流

| 工作流 | 负责范围 | 不允许跨越的边界 |
|---|---|---|
| Server | Secret、用户/RBAC、审计、任务、告警、存储 | 不把明文配置写入 task/audit/log |
| Agent/Contracts | 证书、操作锁、journal、systemd、升级恢复 | 不增加 Shell 字符串命令面 |
| Web | 用户、Secret、审计、配置、告警、升级工作流 | 不持久化 Secret/配置正文，不只靠前端做权限控制 |
| Integration | 三数据库、Linux E2E、故障注入、压测、发布 | 不以 mock 结果替代真实数据库和 systemd |

每轮先冻结契约，再并行实现；主分支合并前执行生成代码 diff、权限矩阵、三数据库 migration、race、前端测试和生产镜像构建。

## 4. SLO 与容量基线

| 指标 | 初始目标 |
|---|---:|
| 控制面 API 可用性 | 月度 99.9% |
| Agent 在线识别延迟 | P95 小于 45 秒 |
| 单节点配置发布 | P95 小于 60 秒，不含人工确认 |
| 在线任务投递延迟 | P95 小于 5 秒 |
| 配置/升级失败自动恢复率 | 100%，无法恢复时必须明确告警 |
| 审计落库 | 与危险操作同请求可确认，不允许静默丢弃 |

## 5. 发布阻断项

存在下列任一情况不得标记生产就绪：

- Secret 明文出现在数据库非密文字段、日志、审计、SSE、任务 payload 或浏览器持久化存储；
- Linux/systemd 配置发布和二进制升级没有真实 E2E；
- 正式候选 commit/tag 尚未关联最新 root helper privileged systemd E2E 的留存日志；
- 前端关键工作流没有完成目标浏览器视觉验收；
- 数据库与 master key/CA 没有完成恢复演练；
- migration 中断后不能安全重放；
- 高危依赖或镜像漏洞没有修复、不可达证明或书面风险接受；
- 1000 Agent 压测或 168 小时 soak 未完成；
- 已知任务丢失、跨节点结果接受、并发发布覆盖或回滚失败问题未解决。
