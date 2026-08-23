# frp 集群管理平台完整技术实现方案

> 状态：production candidate implementation baseline v0.4（尚未生产批准）  
> 日期：2026-07-29  
> 产品定位：单组织私有化部署  
> 关联文档：[frp_admin_design.md](./frp_admin_design.md)

## 0. 当前实现状态

仓库已经完成单节点控制面的主要纵向闭环。本文同时包含当前实现和中长期目标，目标设计不能被当作已交付事实。当前实现包含：

- monorepo、Go workspace、CI、Docker Compose，以及 Server/Web/Agent/Contracts 四个独立子项目；
- SQLite 默认存储，同一 Server 发行物可在启动时选择 MySQL 8+ 或 PostgreSQL 15+；三种方言使用独立 migration；
- 管理员初始化与登录、Argon2id、Session/CSRF、基础 RBAC、登录失败限流；
- Agent 一次性注册、持久化 CA、TLS 1.3 mTLS 双向 gRPC、心跳、离线任务重连派发与命令幂等；
- 节点、代理、配置、升级、任务、告警、审计和用户管理页面，SSE 用于事实数据失效刷新；
- `observe/managed` 管理模式，Store 事务内重验和每节点单个活动变更任务；
- raw TOML 不可变修订、字段级 Secret reference、AES-256-GCM 静态加密、发布/回滚任务、Agent 本地 verify/原子替换/健康检查/自动恢复；
- 单节点 frp 升级：HTTPS URL、SHA-256、安全解压、新二进制 verify、失败恢复；带 query 的制品 URL 使用版本化 key ring 加密；
- runtime proxy/client 快照、全局代理查询、任务超时/取消、告警状态机、签名 Webhook outbox/dead-letter、独立 metrics listener；
- SQLite/MySQL/PostgreSQL migration 与 repository contract、备份恢复脚本、历史 key ring 恢复语义测试、Linux/systemd 和真实 control-plane E2E fixture；root helper 安全模型及最新 privileged systemd E2E 已通过候选工作区验证。

| 状态 | 能力 |
|---|---|
| 已实现并纳入自动门禁 | 单节点注册/观测/纳管、配置发布回滚、启停、单节点升级、runtime 查询、RBAC/审计、告警/Webhook、三数据库、备份恢复 |
| 已有独立环境证据 | MySQL/PostgreSQL contract、真实 Server/Agent control-plane E2E、Trivy；SBOM/签名 workflow 已定义 |
| 未完成，不得宣称生产可用 | 前端 in-app Browser 视觉验收；完整实现纳入可追溯候选 commit/tag；168 小时 soak；目标环境证据与具体 release 绑定 |
| 后续产品能力 | 结构化代理编辑、批量灰度升级、跨方言业务数据迁移、OIDC/LDAP、HA 控制面、多租户 SaaS |

当前是 production candidate，不是生产批准版本。raw TOML 在数据库中加密，但 admin/operator 查看时会受控解密整份内容，因此部署方必须把 master key、历史 key ring、数据库和 CA 私钥作为同等级 secret 管理。当前完整实现还未形成可追溯候选 commit/tag，168 小时 soak 也尚未完成；两者均为生产批准硬门禁，详见 [production_gate_report.md](./production_gate_report.md)。

## 1. 目标理解

本项目不是重新实现 frp，也不将 frp 作为 Go library 嵌入自有进程，而是建设一套管理官方 `frpc` / `frps` 二进制的控制面。系统需要在不要求 frpc 节点具备入站网络能力的前提下，实现：

1. 节点发现、安装、接管、在线状态和运行状态管理；
2. frpc / frps 配置的集中编辑、校验、发布、回滚和漂移检测；
3. 远程 reload、restart、stop、start 和版本升级；
4. 代理、客户端、流量和错误状态的统一展示；
5. 单组织内的用户鉴权、RBAC、操作审批预留和完整审计；
6. 可从单机 Docker Compose 起步，并能演进到高可用部署。

### 1.1 北极星指标

北极星指标定义为：**通过平台成功托管且配置一致的在线节点比例**。

```text
managed_healthy_ratio =
  online && process_healthy && desired_revision == observed_revision 的节点数
  / 已纳管节点数
```

辅助指标：

- 配置发布成功率、P95 发布时间、回滚成功率；
- Agent 7 日在线率、节点失联数量；
- 配置漂移节点数及平均恢复时间；
- frp 升级成功率和自动回滚率；
- 人工登录节点修改 frp 配置的次数，应持续下降。

### 1.2 首期非目标

- 不做公网 SaaS、多租户计费和租户级资源隔离；
- 不替代 Prometheus、Loki 等通用可观测平台；
- 不代理业务流量，控制面故障不得影响已运行的 frp 数据面；
- 不支持任意 Shell 远程执行；
- 首期不支持 Windows 服务接管和非 systemd Linux；
- 不承诺支持所有历史 frp 版本和 INI 配置；
- 不实现跨 frps 的自动流量调度和高可用数据面。

## 2. 关键假设与约束

| 项目 | 首期约束 |
|---|---|
| 部署模式 | 单组织私有化，一套控制面服务一个组织 |
| 目标规模 | 1000 个 Agent、10000 个代理、100 个并发操作 |
| 节点系统 | Linux amd64/arm64，systemd 作为服务管理器 |
| frp 版本 | 正式支持 `v0.60.0+`；更老版本仅允许导入后升级，不承诺可视化编辑 |
| 配置格式 | 新建配置统一生成 TOML；存量 TOML/YAML/JSON 可导入，INI 不做结构化管理 |
| 网络 | Agent 可通过 HTTPS/HTTP2 主动访问控制面；控制面不主动连接 Agent |
| 数据库 | 默认 SQLite 3.45+；可配置 MySQL 8.0+ 或 PostgreSQL 15+，单实例只选择一种 |
| 浏览器 | 最近两个稳定版 Chrome/Edge/Firefox/Safari |
| 一致性 | 控制面保存 desired state，Agent 上报 observed state，最终一致 |

1000 Agent 的目标规模以 MySQL/PostgreSQL 部署为验收环境；默认 SQLite 面向单机和小中规模。规模超过上述边界时，先基于压测结果定位数据库、长连接或时序写入瓶颈，不预先拆微服务。

## 3. 对原设计的关键修正

### 3.1 frps-agent 不能退化为纯轮询器

frps 同样需要接收配置、启停和升级命令，因此 `frpc-agent` 与 `frps-agent` 必须使用相同的主动长连接协议。两者实现为同一个 `frp-agent` 二进制，通过 `role: client|server` 区分能力。

### 3.2 配置发布必须是事务，而不是“写文件后重启”

任何配置变更都必须经历：生成候选文件、目标二进制 `verify`、备份、原子替换、reload/restart、健康确认、失败回滚。否则一次错误配置可能使 Agent 所在节点永久失联。

### 3.3 浏览器首期使用 SSE，不使用 WebSocket

浏览器的实时需求主要是节点、任务和告警的服务端单向推送。写操作仍通过 REST API，因此 SSE 更容易通过反向代理、鉴权和断线重连。只有出现终端双向交互等明确需求时再引入 WebSocket。

### 3.4 不在首期引入专用时序数据库

心跳只更新节点当前状态，不保存逐条历史。业务需要的流量历史先写入当前业务数据库并降采样、设置保留期。SQLite 默认缩短保留周期并限制采集规模；达到持续 5000 samples/s 或数据量 200 GB 后，应接入专用时序存储，而不是继续扩展通用业务库。

## 4. 总体架构

```text
 Browser
    | REST / SSE
    v
+-------------------------- Control Plane --------------------------+
| HTTP API | Auth/RBAC | Node | Config | Task | Upgrade | Audit     |
|                              |                                   |
|                 gRPC Stream Gateway / Task Dispatcher            |
|                              |                                   |
|                SQLite/MySQL/PostgreSQL + local event bus          |
+------------------------------|------------------------------------+
                               | outbound mTLS gRPC stream
                 +-------------+-------------+
                 |                           |
          +------v------+             +------v------+
          | frp-agent  |             | frp-agent   |
          | role=client|             | role=server |
          +------|------+             +------|------+
                 | systemd / local CLI       | systemd / Admin API
              frpc                         frps
                 \_____________ frp data plane _____________/
```

### 4.1 控制原则

- **数据面独立**：控制面、数据库或 Agent 不可用时，已运行的 frpc/frps 继续工作；
- **期望/观测分离**：数据库中的目标状态不能被一次不可靠 RPC 直接覆盖；
- **命令白名单**：Agent 只执行协议定义的强类型动作，不接受 Shell 字符串；
- **本地闭环**：配置发布和升级的备份、验证、健康检查、回滚由 Agent 本地完成；
- **默认安全**：Admin API 只监听 loopback，Agent 与控制面使用 mTLS，敏感值不进入日志；
- **可审计**：用户发起、控制面调度、Agent 执行三个阶段均可关联到同一 task ID。

## 5. 技术选型

| 层 | 选型 | 结论 |
|---|---|---|
| Agent | Go 1.26.5+ | 单文件、交叉编译、systemd 和进程管理成本低 |
| 控制面 | Go 1.26.5+、Chi、gRPC | 模块化单体；REST 与 gRPC 共用领域服务 |
| API 描述 | Protobuf + Buf；REST DTO/类型显式维护 | Agent 协议使用生成类型；REST OpenAPI 生成属于后续治理项 |
| 前端 | React 19、TypeScript、Vite、Ant Design | 面向运维后台，优先表格、表单、任务状态和审计 |
| 状态管理 | TanStack Query + React state | 服务端状态与少量本地交互状态分离 |
| 数据库 | SQLite/MySQL/PostgreSQL、`database/sql` | 领域 repository 隔离存储；公共查询和方言 migration 显式可审查 |
| 配置编码 | pelletier/go-toml/v2 | 当前解析/校验 raw TOML；最终以 frp `verify` 为准 |
| 密码 | Argon2id | 本地账号密码散列 |
| 前端实时 | SSE | 单向状态推送与自动重连 |
| 可观测 | Prometheus、slog | metrics 使用独立可选 listener，结构化日志关联 request/task/node；Trace 属于后续能力 |
| 测试 | Go test、Docker service、Vitest、Playwright | 覆盖事务状态机及端到端操作 |

不使用 Gin/Fiber 的核心原因不是性能，而是本系统 HTTP 路由不是瓶颈；优先采用标准库兼容性高、依赖更薄的 Chi。若团队已有统一 Gin 基建，可替换，领域设计不受影响。

## 6. Monorepo 目录设计

根目录按可独立构建和交付的子项目组织：

```text
frp-admin/
├── agent/                       # frp-agent，独立 Go module
│   ├── cmd/frp-agent/
│   ├── internal/bootstrap/      # 注册、证书轮换
│   ├── internal/channel/        # gRPC stream、重连、收发队列
│   ├── internal/configmgr/      # stage/verify/apply/rollback/drift
│   ├── internal/executor/       # 强类型任务执行器
│   ├── internal/frpadmin/       # frpc/frps Admin API 适配
│   ├── internal/inventory/      # OS、systemd、二进制和路径探测
│   ├── internal/service/        # systemd adapter
│   ├── internal/upgrader/       # 下载、校验、替换、回滚
│   └── packaging/systemd/
├── server/                      # 控制面，独立 Go module
│   ├── cmd/frp-admin-server/
│   ├── internal/app/            # 装配、生命周期
│   ├── internal/auth/
│   ├── internal/node/
│   ├── internal/configuration/
│   ├── internal/task/
│   ├── internal/upgrade/
│   ├── internal/alerting/
│   ├── internal/metrics/
│   ├── internal/secretmgr/
│   ├── internal/agentgateway/   # gRPC stream 与在线连接目录
│   ├── internal/httpapi/        # REST、SSE、middleware
│   ├── internal/store/          # repository、database/sql、方言 adapter
│   └── migrations/
│       ├── sqlite/              # 各方言独立、同 schema version
│       ├── mysql/
│       └── postgres/
├── web/                         # React 独立前端子项目
│   ├── src/api/
│   ├── src/app/
│   ├── src/components/
│   ├── src/pages/
│   └── e2e/
├── contracts/                   # 唯一跨进程契约源
│   ├── buf.yaml
│   ├── buf.gen.yaml
│   ├── proto/frpadmin/agent/v1/
│   └── gen/                     # CI 生成并校验无 diff
├── deploy/
│   ├── compose/
│   ├── e2e/
│   ├── ops/
│   ├── release/
│   ├── soak/
│   ├── systemd/
│   └── examples/
├── scripts/                     # 开发和发布脚本
├── docs/
├── go.work
├── Makefile
└── README.md
```

### 6.1 依赖规则

```text
web -> server HTTP API
agent <-> contracts <-> server/agentgateway
server domain modules -> server/store
agent executor -> frp/service/configmgr/upgrader
```

- `agent/internal` 与 `server/internal` 禁止互相 import；
- 跨进程只共享 `contracts`，不共享领域实体；
- 不建立泛化的 `common` / `utils` 包；只有稳定且确实跨模块的协议进入 `contracts`；
- 使用 `go.work` 改善本地开发，各子项目保留自己的 `go.mod` 和独立发布版本；
- 当前前端显式维护 REST DTO，并由 Web/Server 契约测试约束；引入 OpenAPI 后再切换为生成只读 client，不能在没有规范源时宣称已生成。

### 6.2 contracts 子项目的职责

`contracts/` 不是服务，也不保存数据库实体。它是跨进程/跨语言契约的唯一来源：

- `agent <-> server` 的 Protobuf service、message、error code；
- Buf breaking-change 规则和 Go 代码生成配置；
- 当前仅包含 Agent control-plane v1 协议；REST OpenAPI 属于后续治理项。

例如 `APPLY_CONFIG` 的字段、`VERIFY_FAILED` 错误码必须先在 contracts 定义，再由 Agent 和 Server 使用生成类型。`Node` 数据库表、repository entity、前端页面 model 不应放进 contracts，否则会把内部存储结构误变成公开协议。

## 7. 控制面详细设计

### 7.1 运行形态

当前 Server 为模块化单体进程，监听：

- `:8080`：REST API、SSE 和健康检查；Web 由独立子项目/容器提供；
- `:8443`：Agent mTLS gRPC/Connect；
- `:9090`：仅内网 Prometheus metrics，可通过配置关闭。

模块化单体不等于无边界：每个领域模块拥有 service、repository interface 和错误码，模块之间通过应用服务调用。数据库可以共用，但禁止跨模块随意拼 SQL。

### 7.2 核心模块

| 模块 | 责任 | 不承担 |
|---|---|---|
| auth | 登录、opaque session cookie、CSRF、RBAC、会话撤销 | Agent 身份 |
| node | 节点元数据、标签、期望/观测状态、注册 | 命令传输 |
| configuration | 配置草稿、修订、差异、发布计划 | 本机文件操作 |
| task | 任务、步骤、重试、取消、超时、幂等 | 业务配置解析 |
| upgrade | 单节点 frp 升级计划、加密制品 URL、任务关联 | 批量灰度和任意文件分发 |
| alerting/metrics | 当前运行快照、告警/Webhook、平台指标 | 历史 TSDB 与通用日志平台 |
| store/httpapi | 事务审计写入和按角色查询 | 业务状态回滚 |
| agentgateway | Agent 流会话、消息路由、在线判定 | 领域决策 |

### 7.3 长连接管理

每个 Agent 同一时刻只允许一个有效 session：

1. Agent 使用客户端证书建立 mTLS；
2. 首帧发送 `Hello`，包含 node ID、agent/frp 版本和 role；
3. 控制面验证证书 SAN 中的 node ID 与消息一致；
4. 更新节点 observation，在本实例内存 session 目录登记连接，并返回服务端时间和心跳间隔；
5. 同 node 新连接到来时，旧 session 标记 superseded 并关闭；
6. 心跳默认 15 秒，45 秒未收到心跳标记 offline；使用抖动避免同时重连；
7. 断线重连为指数退避 1s 到 60s，带 20% jitter；
8. session 恢复后 Agent 先上报运行中/已完成任务，再接收新命令。

服务端重启不会丢任务：任务事实保存在所选业务数据库，内存仅保存当前 stream。调度器扫描 `queued` 任务，并只向本实例持有 session 的节点发送。

### 7.4 调度与并发控制

- 每节点最多执行一个变更类任务；状态采集不占变更锁；
- `config_apply`、`frp_upgrade`、`service_restart` 互斥；
- 任务领取使用带 `version`/lease 的原子 compare-and-swap；MySQL/PostgreSQL adapter 可使用 `FOR UPDATE SKIP LOCKED` 优化，SQLite 使用单调度器和短事务；
- 每个命令带 `command_id` 和 `idempotency_key`；Agent 使用 bbolt journal 保存最近 1000 个执行结果；
- API 创建任务支持 `Idempotency-Key`，避免浏览器重试创建重复操作；
- `queued` 可取消，`dispatched/running` 只发送协作取消，进入原子替换阶段后不可强制取消；
- 默认超时：轻量命令 30 秒，配置发布 2 分钟，升级 10 分钟，可按策略配置。

## 8. Agent 详细设计

### 8.1 单二进制、双角色

```yaml
serverURL: https://admin.example.com:8443
role: client                 # client | server
nodeID: 01J...
stateDir: /var/lib/frp-agent
frp:
  serviceName: frpc.service
  binaryPath: /opt/frp/bin/frpc
  configPath: /etc/frp/frpc.toml
management:
  mode: adopt                # adopt | managed
```

角色只决定允许管理 `frpc` 还是 `frps`，不会生成两套进程。Agent 自身由 `frp-agent.service` 管理，并以专用 `frp-agent` 系统用户运行；Agent 不能直接改 root-owned frp 二进制或其他服务用户持有的配置。需要提权的风险修复和服务生命周期操作经 Unix socket 调用 root-owned、socket-activated helper；helper 用 `SO_PEERCRED` 校验 Agent UID，只接受固定 role/path/service allowlist 和类型化请求，不接受调用方提供的 unit、路径、参数或 Shell。资源 probe 与 service probe 相互独立，失败时分别关闭对应 capability。service helper 只接受 start、stop、restart，reset-failed 仅作为 start/restart 的内部固定步骤，并校验最终 active/inactive 状态。生产配置固定要求 client 对应 `frpc.service`、server 对应 `frps.service`，不支持通过 YAML 扩大权限面。

本机所有权不采用“一律 root:root”的简化规则：frp 二进制必须 `root:root` 且 group/other 不可写；配置必须由 `systemctl show` 得到的服务 effective UID 持有，且 group/other 不可写。这样既阻止非特权 Agent 替换可执行文件，也保证 `0600` 配置对实际 frp 服务可读。helper 配置自身必须是 `root:root 0600` 普通文件，资源路径固定为 `/etc/frp/{frpc,frps}.toml` 和 `/opt/frp/bin/{frpc,frps}`。

常规配置/回滚/升级采用 capability 降级：只有 frp 与 Agent 是同一非 root effective UID，且目标文件和父目录均由该身份安全持有时，才允许资源事务并在 Hello 中宣告能力；其中 restart/stop/start 统一通过 helper，状态与健康检查保持本地只读。默认 root-owned 模型不宣告这些能力；Server 对排队重连和当前在线 session 都在下发前校验 capability。helper 不扩展为任意配置或任意下载通道。

### 8.2 本地目录

```text
/etc/frp-agent/agent.yaml         # 非秘密配置，0600
/var/lib/frp-agent/
├── pki/                          # 客户端证书与私钥，0600
├── journal/                      # 命令幂等结果
├── staged/                       # 候选配置/二进制
├── backups/config/               # 最近 10 个配置版本
├── backups/bin/                  # 当前和上一个 frp 二进制
└── state.json                    # observed revision、boot ID 等
/var/log/frp-agent/               # 若不完全使用 journald
```

目录必须位于同一文件系统，保证 rename 原子性。候选文件以 `fsync(file) -> rename -> fsync(dir)` 提交。

### 8.3 探测与接管

探测顺序：

1. 显式配置路径；
2. `systemctl show <service>` 的 `ExecStart`；
3. `/proc/<pid>/exe` 与命令行；
4. 受支持的标准路径。

探测结果必须在 UI 由管理员确认后才进入 `adopt`，不能因为发现同名进程自动接管。确认项包括 service、binary、config、版本和文件权限。

| 模式 | 配置/二进制所有权 | 允许操作 |
|---|---|---|
| observe | 用户 | 仅状态采集，不修改 |
| adopt | 用户已有，平台接管后记录基线 | 配置发布、启停；升级需单独授权 |
| managed | 平台安装并维护 | 全能力 |

### 8.4 systemd 管理

Agent 不自行 fork 并守护 frp。所有生命周期操作通过 systemd D-Bus 或受限 `systemctl` 完成，使用：

- `systemctl start/stop/restart`；
- `systemctl show` 读取 `ActiveState`、`SubState`、`ExecMainPID`、`ExecMainStatus`；
- 安装 unit 后执行 `daemon-reload`；
- 禁止 Agent 修改非白名单 service name。

默认 frp unit 使用 `Restart=on-failure`、合理的 `StartLimit*` 和 `NoNewPrivileges=true`。如果目标配置需要读取私钥文件，需显式授予路径权限，不能为方便关闭所有 systemd sandbox。

## 9. Agent 通信协议

### 9.1 服务定义

```proto
service AgentControlService {
  rpc Enroll(EnrollRequest) returns (EnrollResponse);
  rpc Connect(stream AgentToServer) returns (stream ServerToAgent);
}

message AgentToServer {
  oneof payload {
    Hello hello = 1;
    Heartbeat heartbeat = 2;
    Inventory inventory = 3;
    CommandAck command_ack = 4;
    CommandProgress command_progress = 5;
    CommandResult command_result = 6;
    RuntimeSnapshot runtime_snapshot = 7;
    MetricBatch metric_batch = 8;
  }
}

message ServerToAgent {
  oneof payload {
    Welcome welcome = 1;
    Command command = 2;
    CancelCommand cancel_command = 3;
    RotateCertificate rotate_certificate = 4;
  }
}
```

### 9.2 Command 白名单

| 类型 | 关键参数 | 幂等语义 |
|---|---|---|
| `INSPECT` | 无 | 可重复 |
| `APPLY_CONFIG` | revision、sha256、content、strategy | 同 revision 重放返回原结果 |
| `START/STOP/RESTART` | service、precondition | 目标状态幂等 |
| `UPGRADE_FRP` | version、artifact URL、sha256 | 当前版本相同则成功 |
| `ROLLBACK_CONFIG` | target revision | 同 apply |
| `COLLECT_RUNTIME` | detail level | 可重复 |
| `ROTATE_AGENT_CERT` | cert chain | 按 serial 幂等 |

协议中不存在 `exec(command string)`。错误使用稳定枚举，例如 `VERIFY_FAILED`、`HEALTHCHECK_FAILED`、`CHECKSUM_MISMATCH`、`PRECONDITION_FAILED`，原始 stderr 经过脱敏和长度限制后作为诊断字段。

部署风险扫描在任务与 capability 层保持独立的 `risk_scan` / `risk.scan` 语义，不能因复用采集器而按普通 `inspect` 授权。v1 线协议为避免复制 inventory 结果结构，网关仅在编码时将 `risk_scan` 转换为 `InspectCommand`；任务首次创建、排队重连和当前 session 下发均必须校验 `risk.scan`。普通巡检独立校验 `inspect`，两项 capability 不互相替代。

### 9.3 版本兼容

- Protobuf 只追加字段，禁止复用 field number；
- `Hello` 携带 `protocol_version` 和 capability bitset；
- 服务端只下发 Agent 声明支持的 command；
- 支持当前和前两个 Agent minor 版本，超出范围在 UI 告警但不立即断开；
- breaking change 发布新 package `agent/v2`，不在 v1 中隐式改变语义。

## 10. 配置中心设计

### 10.1 配置源模型

配置中心不能只存渲染后的 TOML，也不应把所有 frp 字段拆成关系表。采用两层模型：

1. `config_revisions.document`：版本化 canonical JSON 文本，是可视化模式的事实源；
2. `rendered_template`：按目标 frp 版本生成、仍保留 secret 引用的 TOML 模板。

实际下发内容在任务派发时按权限短暂物化，不写普通数据库、不进入消息持久化和日志。服务端计算物化内容 hash，Agent 校验并回报；任务结束后相关内存和临时候选文件按生命周期清理。

提供两种互斥编辑模式：

| 模式 | 适用 | 行为 |
|---|---|---|
| structured | 常见字段与代理类型 | 表单编辑结构化 JSON，服务端确定性生成 TOML |
| raw | 未覆盖的新字段、复杂 includes | Monaco 编辑原始 TOML，只做语法和目标二进制校验 |

从 raw 切换到 structured 需要显式导入并展示丢失字段预览，不能自动无损承诺。首期 structured 支持 TCP、UDP、HTTP、HTTPS、STCP、SUDP、XTCP、TCPMUX 常用字段；插件、visitor 和 feature gates 可先走高级编辑。

### 10.2 Schema 与版本策略

- `contracts` 中维护平台支持的版本化配置 schema；
- 服务端完成基础类型、必填项、端口范围和跨字段校验；
- 最终校验必须在目标节点调用实际 `frpc/frps verify -c <staged>`；
- 不直接 import frp 内部 Go package 作为运行时依赖，避免 Agent 与某个 frp 版本硬绑定；
- 新 frp release 由兼容测试矩阵验证后加入支持列表；
- 未认证的新版本可运行和观测，但配置发布显示风险并要求管理员确认。

### 10.3 敏感字段

`auth.token`、OIDC client secret、webServer password 和私钥路径等字段不能以明文进入普通配置字段：

- 敏感值独立存入 `secrets`，使用 AES-256-GCM envelope encryption；
- master key 由文件、Docker secret、Kubernetes Secret 或 KMS 注入，不写数据库；
- 配置 document 只保存 `${secret:<id>}` 引用；
- 渲染时在服务端短暂解密，通过 mTLS 下发，日志与 diff 显示 `******`；
- Agent 候选配置和正式配置必然含运行所需秘密，文件权限强制 0600；
- 审计记录只保留 secret ID 和“已变更”，不保留旧值/新值。

### 10.4 发布状态机

```text
DRAFT -> VALIDATING -> READY -> DEPLOYING -> SUCCEEDED
                    \-> REJECTED       \-> ROLLING_BACK -> ROLLED_BACK
                                                   \-> FAILED_MANUAL
```

单节点发布流程：

1. 控制面校验 revision、权限和目标节点当前 revision；
2. 创建 task，将 desired revision 更新与任务创建放在同一数据库事务；
3. Agent 将内容写入 `staged/<revision>.toml` 并校验 sha256；
4. 调用目标 `frpc/frps verify`，失败则不触碰现有文件；
5. 备份当前配置并记录 hash；
6. 原子替换正式配置；
7. frpc 仅代理段变化时尝试 reload，其他变化或 frps 统一 restart；
8. 检查 systemd active、进程稳定窗口和本地 Admin API；
9. 上报 applied revision、最终 hash 和运行快照；
10. 任一步失败则恢复备份并再次 verify + restart；回滚也失败进入 `FAILED_MANUAL` 并触发严重告警；
11. 成功后确认 desired/observed revision 一致；取消或成功回滚时，控制面使用 compare-and-swap 将 desired revision 恢复到任务开始前的 revision，避免覆盖此后发起的新发布。

### 10.5 reload/restart 判定

服务端可以根据结构化 diff 给出建议，但 Agent 必须保守执行：

- `frpc` 且仅 `proxies` / `visitors` / `start` 变化：`reload`；
- frpc common section 变化：`restart`；
- `frps` 任意配置变化：`restart`；
- raw 模式无法可靠分类：默认 `restart`；
- 用户可选择“强制 restart”，不能强制把不支持的变更 reload。

健康确认不能只看 `systemctl active`。frpc 至少检查本地管理接口/status 或日志中的登录结果；frps 检查 Admin API 和监听端口。稳定窗口默认 15 秒。

### 10.6 漂移处理

Agent 使用 fsnotify 加每 60 秒 hash 兜底，检测正式配置变化：

1. 上报 `observed_hash != desired_hash`；
2. 控制面标记 `DRIFTED` 并告警；
3. 默认不自动覆盖，避免抹掉紧急人工修复；
4. 管理员选择“以平台配置覆盖”或“导入节点配置为新草稿”；
5. 所有选择进入审计。

## 11. frp 版本升级设计

### 11.1 制品来源

- 默认从 GitHub 官方 release 下载；私有网络可配置可信镜像；
- 控制面同步 release manifest 和官方 `frp_sha256_checksums.txt`；
- Agent 只接受 allowlist 域名或控制面制品代理地址；
- 必须校验 SHA-256，建议中期增加 Sigstore/组织签名；
- 记录来源 URL、checksum、下载时间和验证结果形成供应链审计。

### 11.2 升级事务

```text
preflight -> download -> checksum -> extract -> binary --version
-> config verify with new binary -> stop -> atomic swap -> start
-> health window -> success
                  \-> restore old binary/config -> restart -> rolled_back
```

升级前检查磁盘、架构、目标版本、配置兼容性和当前任务锁。新二进制先对现有配置执行 `verify`，通过后才停服务。保留上一个二进制和配置，健康窗口默认 60 秒。

### 11.3 批量与灰度

- 默认批次：1 台 canary -> 10% -> 25% -> 余量；
- 每批最大并发可配置，frps 默认一次只升级一台；
- 任一批失败率超过 10% 自动暂停；
- 批次间观察至少 5 分钟；
- 首期不自动升级 Agent 自身，Agent 升级使用包管理/安装脚本；中期再做双进程 self-update helper。

## 12. 数据模型

所有主键使用 UUIDv7 并以 `CHAR(36)` 保存；时间在应用层统一为 UTC，以微秒 Unix timestamp (`BIGINT`) 持久化，展示时再转换用户时区。避免依赖某一数据库的 UUID、时区和 JSON 原生类型。关键表如下：

| 表 | 关键字段 | 说明 |
|---|---|---|
| `users` | username、password_hash、status、role | 本地用户与 admin/operator/viewer/auditor 单角色 |
| `sessions` | token_hash、csrf_hash、expires_at、revoked_at | opaque session 与 CSRF 只存 hash |
| `enrollment_tokens` | token_hash、role、expires_at、used_at | 一次性 Agent 注册 |
| `nodes` | name、role、labels、management_mode、desired_revision_id | 节点事实与期望状态 |
| `node_observations` | online、agent/frp version、service state、observed hash/revision | 每节点仅一行当前观测 |
| `config_revisions` | node_id、version、encrypted_content、nonce、sha256、strategy | 不可变加密修订，不含已物化 Secret |
| `secrets` | ciphertext、nonce、key_version | 加密秘密 |
| `tasks` | type、state、node_id、idempotency_key、requested_by | 任务主表 |
| `task_steps` | task_id、name、state、attempt、error_code、output | 可诊断执行步骤 |
| `upgrade_plans` | version、artifact_ciphertext/nonce/key_version、sha256、state | 单节点升级历史，完整 URL 不明文落库 |
| `runtime_snapshots` | node_id、role、frp_version、collected_at、计数 | 节点当前运行快照 |
| `runtime_proxies/runtime_clients` | node_id、稳定键、状态/流量/地址 | 归一化当前代理与客户端状态 |
| `alerts` | rule、severity、state、fingerprint | 告警实例 |
| `webhook_deliveries` | alert_id、state、attempts、lease/next_attempt | 持久化通知 outbox/dead-letter |
| `audit_logs` | actor、action、resource、request_id、before/after redacted | 追加写审计 |

### 12.1 关键约束

- `config_revisions(node_id, version)` unique；revision 创建后禁止 update/delete；
- `tasks(node_id, idempotency_key)` unique，所有任务创建时都生成非空 idempotency key；
- 每节点只能有一个 queued/dispatched/running 的 service/config/upgrade 变更任务；Store 在同一事务内锁 node 行、重验 `managed` 并检查活动任务，避免 mode TOCTOU；inspect/runtime 不占变更锁；
- `nodes.desired_revision_id` 和 task 创建在同一事务；
- 当前只保存最新 runtime snapshot，不承诺历史 traffic 时序保留；历史聚合属于后续容量项目；
- `audit_logs` 不提供普通删除 API，运维保留策略由部署配置控制；
- 单租户首期不机械地在每张表加入 `tenant_id`。未来 SaaS 化应作为独立迁移项目，而不是依赖一个未生效字段获得虚假隔离感。

最后一点有意不同于“先预留 tenant_id”的直觉：只有字段没有 RLS、唯一键组合、查询约束和测试，不构成租户隔离，反而容易制造安全错觉。

### 12.2 多数据库兼容策略

“同时兼容”定义为同一个 Server 发行物可在启动时选择一种数据库后端，不支持一个实例同时读写多个主数据库，也不实现 SQLite/MySQL/PostgreSQL 之间的实时复制或自动故障切换。

```yaml
database:
  driver: sqlite              # sqlite | mysql | postgres
  dsn: /var/lib/frp-admin/frp-admin.db
```

| 能力 | SQLite 3.45+（默认） | MySQL 8.0+ | PostgreSQL 15+ |
|---|---|---|---|
| 适用场景 | 开箱即用、单机、小中规模 | 用户已有 MySQL 基础设施 | 较大规模、HA、首选生产库 |
| Server 副本 | 仅 1 个 | 多副本 | 多副本 |
| 建议规模 | <= 200 Agent、2000 proxy | 目标规模上限需压测 | 目标规模上限需压测 |
| 事务任务抢占 | 单调度器 + CAS | CAS / `SKIP LOCKED` | CAS / `SKIP LOCKED` |
| JSON | canonical JSON 存 `TEXT` | canonical JSON 存 `LONGTEXT` | canonical JSON 存 `TEXT` |
| 流量保留默认值 | 1 分钟 7 天、1 小时 90 天 | 1 分钟 30 天、1 小时 1 年 | 1 分钟 30 天、1 小时 1 年 |
| HA | 不支持共享文件/NFS | 由外部 MySQL HA 提供 | 由外部 PostgreSQL HA 提供 |

实现约束：

- 使用 `database/sql` 实现 repository，SQL row model 不能越过 repository 泄漏到领域层；
- 三种方言维护独立但 schema version 一致的 migration，必须经代码审查；不能依赖运行时 ORM 自动修改生产 schema；
- SQLite 使用纯 Go driver、WAL、`busy_timeout`、foreign keys，并限制一个写连接；数据库文件禁止放 NFS；
- MySQL 强制 `utf8mb4`、严格 SQL mode 和 UTC session timezone；连接 DSN 必须启用 `parseTime`；
- PostgreSQL session timezone 固定 UTC；
- 公共查询禁止依赖 JSON operator、array、enum、RETURNING、partial index、数据库函数和特定 upsert 语法；确需方言能力时通过显式 adapter 和三库测试实现；
- 公共功能以三库能力交集为准；不能在某个方言实现的新增能力必须在 API capability 中显式声明，不能静默降级成不同业务语义；
- 金额不存在于当前模型；计数和流量统一 `BIGINT`，布尔值和时间由 store adapter 归一；
- migrations、repository 集成测试和升级/回滚测试必须覆盖三种数据库，不能只在 SQLite 上通过就发布。

### 12.3 数据库迁移与切换

数据库切换不是修改 DSN 后直接启动。当前已提供 SQLite/MySQL/PostgreSQL 的同方言一致性备份恢复脚本，但尚未提供跨方言业务数据迁移命令。下列中立格式导入导出是后续目标，不是当前 CLI：

```text
frp-admin-server db export --output backup.tar.zst
frp-admin-server db import --input backup.tar.zst --target-dsn ...
```

导出包含 schema version、逐表 NDJSON、blob/checksum manifest，不包含 master key 和 CA 私钥；这些必须单独安全迁移。导入前要求目标库为空，完成后校验行数、外键、revision/hash 和审计链。首期可以先提供 SQLite 备份和相同方言恢复，跨方言迁移工具列为 M5 上线前交付项。

## 13. HTTP API 设计

统一前缀 `/api/v1`，错误响应遵循 RFC 9457 Problem Details，所有写接口返回/接受 `request_id`，分页使用 cursor。

### 13.1 主要资源

```text
POST   /auth/login
POST   /auth/logout
GET    /users/me

GET    /nodes
POST   /nodes/enrollment-tokens
GET    /nodes/{id}
PATCH  /nodes/{id}/management-mode
POST   /nodes/{id}/inspect
POST   /nodes/{id}/service-actions
GET    /nodes/{id}/runtime
POST   /nodes/{id}/runtime-collections

GET    /nodes/{id}/config-revisions
POST   /nodes/{id}/config-revisions
POST   /config-revisions/{id}/deploy
POST   /nodes/{id}/config-rollbacks

GET    /tasks
GET    /tasks/{id}
POST   /tasks/{id}/cancel
POST   /upgrade-plans
GET    /upgrade-plans
GET    /upgrade-plans/{id}
POST   /upgrade-plans/{id}/cancel

GET    /proxies
GET    /alerts
POST   /alerts/{id}/acknowledge
POST   /alerts/{id}/resolve
POST   /alerts/{id}/close
GET    /audit-logs
GET    /events                       # SSE
```

### 13.2 REST 语义

- action 使用名词化子资源，避免 `POST /node/restart` 到处扩散；
- 所有耗时操作返回 `202 Accepted` 和 task resource；
- 变更接口使用 `Idempotency-Key` 和 Store 事务约束防止重复/并发执行；
- Secret API 只返回元数据，永不回传 value、ciphertext 或 nonce；
- 当前升级计划为单节点即时执行；批量灰度 plan 属于后续能力；
- 当前不开放节点删除/远程卸载 API。

## 14. 身份、权限与安全

### 14.1 用户认证

- 当前使用本地账号密码，首次启动必须显式配置一次性 bootstrap token 创建 admin；空库缺 token 时 Server 拒绝启动且不记录 token；
- 登录创建数据库持久化的 opaque session，cookie 中只保存原始 token，数据库只存 token/CSRF hash；默认 7 天，可撤销；
- Web 使用 `HttpOnly + Secure + SameSite=Lax` cookie，写操作校验 CSRF token；
- 密码使用 Argon2id，参数按部署机器 benchmark 后固化；
- 连续失败登录限流和短期锁定；
- 中期接入 OIDC/LDAP，不自研 MFA。

### 14.2 RBAC

| 能力 | admin | operator | viewer | auditor |
|---|---:|---:|---:|---:|
| 用户与系统设置 | 是 | 否 | 否 | 否 |
| Agent 注册/删除 | 是 | 否 | 否 | 查看 |
| 配置编辑和发布 | 是 | 是 | 否 | 查看 |
| 启停与升级 | 是 | 是 | 否 | 查看 |
| 状态与监控 | 是 | 是 | 是 | 是 |
| 审计日志 | 是 | 否 | 否 | 是 |

危险操作（批量升级、frps restart、回滚失败后的强制覆盖）需要二次输入资源名。审批流只预留 task 字段，首期不实现。

### 14.3 Agent 注册与 mTLS

1. 管理员创建 10 分钟有效、一次性的 enrollment token；
2. 安装脚本通过 HTTPS 调用 `Enroll`，提交 token、公钥、role 和主机指纹；
3. 控制面签发 30 天客户端证书，SAN 为 node ID；
4. Agent 私钥在本机生成且不离开节点；
5. 到期前 7 天通过现有 mTLS session 轮换；
6. 节点解除纳管后吊销 serial，网关在握手和 session 层检查；
7. CA 私钥应以文件 secret 或 KMS/HSM 管理，不能存入普通数据库。

### 14.4 威胁控制

| 风险 | 控制 |
|---|---|
| Agent 被攻陷后横向控制其他节点 | 每节点独立证书，只能上报自身 node ID |
| 控制面被攻陷后远程任意执行 | 协议无 Shell，Agent 命令/路径/service allowlist |
| 恶意配置读取本机文件 | 限制配置可引用路径；高危字段告警；systemd 文件权限隔离 |
| 制品投毒 | HTTPS + 官方 checksum + 域名 allowlist + SBOM |
| 重放命令 | command ID、过期时间、幂等 journal、mTLS |
| 日志泄密 | 结构化字段脱敏，stderr 限长，secret diff 屏蔽 |
| SSRF | 制品 URL allowlist，Agent 不接受任意 URL/探测地址 |
| CSRF/XSS | SameSite、CSRF token、CSP、React 默认转义 |

## 15. 监控与告警

### 15.1 数据采集

- Agent heartbeat：15 秒，只维护当前在线状态；
- systemd/frp 运行快照：30 秒或状态变化立即上报；
- frps Admin API：15 秒抓取当前客户端和代理状态；
- frps `/metrics`：由 frps-agent 本地读取并按 1 分钟聚合需要的业务指标；
- 不将控制面直接暴露到 frps Admin API，也不把 Admin API 监听到公网。

Admin API 属于 frp 的实现接口，存在随版本变化的风险。`agent/internal/frp` 必须按版本适配，并把原始响应转换为平台稳定模型；解析失败只影响监控，不阻塞 frp 数据面。

### 15.2 风险中心与首期规则

部署风险不是普通瞬时告警。平台将每次 Agent 检查结果规范化为持久化
`Finding`，按 `node + kind` 归并，并保存脱敏 evidence、confidence、规则版本、
首次/最近发现时间和修复任务。操作员也可对在线节点发起独立的只读
`risk_scan` 任务；该任务在线协议编码复用 `InspectCommand`，但始终以
`risk.scan` capability 授权。扫描与修复均进入既有任务、幂等、审计和 RBAC
体系，而不是增加任意 Shell 入口。

首批规则及自动处置边界：

| Finding kind | 检测 | 自动修复 | 边界 |
|---|---|---|---|
| `admin_api_non_loopback` | frps Admin API 监听非 loopback | 控制面从当前 desired 派生不可变 revision，将 `webServer.addr` 定点改为 `127.0.0.1`，执行 verify、备份、原子替换、restart、健康确认和失败回滚 | 仅 server-role、managed、desired/observed revision 一致且 capability 可用的节点；首期只支持 TOML；必须 admin 确认维护影响 |
| `config_token_permissions` | 含 inline `auth.token` 的配置存在 group/other 权限位 | 收紧为 `0600`，verify 失败恢复原 mode | Linux 仅通过受限 root helper；Darwin 仅允许 Agent effective UID 持有的普通配置文件；均拒绝软链、inode 变化和扩展 ACL，并验证收紧后可读性 |
| `proxy_name_conflict` | 最近日志出现 duplicate/already-exists/name-in-use | 不提供 | 平台无法仅凭日志安全判断权威实例、业务流量和改名策略，必须人工维护 |

扫描结果按规则具有三值语义：发现为 active；某规则连续两次成功完成且未发现，
才从 `pending_confirmation` 进入 `resolved`；该规则所需输入读取/解析失败则为
`unknown`，只记录 scan error，绝不能据此推进该 Finding 的恢复。每次结果显式携带
`completed_kinds`，因此日志读取失败时，已成功完成的配置规则仍可独立对账，而
`proxy_name_conflict` 保持未知。这样可避免权限不足、日志轮转或解析器不兼容制造
“风险已消失”的假象。

自动修复使用 Finding 的资源 SHA-256 fingerprint 做 compare-and-swap 前检。
配置型修复同时将候选 revision、material SHA 和 expected desired revision 固化到任务；
Agent 回传 applied revision/SHA 后，Server 在同一事务内 CAS 推进 desired/observed、
完成任务步骤并写结果审计。派生 revision 与 repair task 也在同一数据库事务创建，
避免并发幂等重放留下孤儿 revision。
Server 在事务中锁定 open Finding、拒绝节点并发危险任务并保存审计，Agent 执行前
重新扫描；资源已变化、扫描不完整或 fingerprint 不一致即拒绝执行并要求重扫。
修复命令是 `kind + allowlisted action` 的强类型协议，不接受脚本、路径或任意命令。
修复结果记录 backup ID、changed、rollback attempted/succeeded，任务结果和审计日志
可关联查询。

RBAC 边界：admin/operator 可发起只读扫描和查看修复入口，viewer/auditor 只读；
修复仅允许 managed 节点。权限收紧可由 admin/operator 发起；会重启 frps 的
loopback 修复仅 admin 且必须显式确认维护影响。所有写请求要求 CSRF 和
`Idempotency-Key`。

首期通用告警规则：

- Agent 离线超过 2 分钟；
- frp service 非 active 超过 1 分钟；
- desired/observed revision 不一致超过 5 分钟；
- 配置漂移；
- 发布或升级回滚失败；
- frps 可用代理数异常下降；
- Agent 证书 3 天内到期且未轮换；
- 风险中心出现 `admin_api_non_loopback`、`config_token_permissions` 或
  `proxy_name_conflict` active Finding。

部署安全自检由 Agent 在连接成功后立即执行，之后每 5 分钟执行一次。Agent
只上报枚举化风险类型和有界脱敏 evidence，不上报配置内容、token、代理名称或
日志原文。配置解析失败或日志源不可用只影响依赖该输入的规则，不阻断 Agent 控制
通道和 frp 数据面，也不会自动 resolve 对应的既有 Finding。

通知首期支持签名 Webhook、持久化重试/outbox 和 dead-letter，后续按需求增加企业微信、钉钉、飞书适配。告警使用 active fingerprint 去重，状态为 open/acknowledged/resolved/closed。

### 15.3 平台自身设计目标

| 指标 | 首期设计目标 |
|---|---|
| 控制面 API 可用性 | 月度 99.9% |
| 在线 Agent 状态延迟 | P95 < 45 秒 |
| 单节点配置发布 | P95 < 60 秒，不含人为确认 |
| 任务状态不丢失 | 控制面重启后可恢复 |
| 数据面影响 | 控制面不可用不影响已运行代理 |

## 16. 前端信息架构

首屏直接进入运维工作台，不做营销首页：

```text
概览
节点
  ├─ 客户端节点
  └─ 服务端节点
代理
配置发布
升级计划
任务
风险中心
告警
审计日志
系统设置
```

关键交互：

- 节点列表以高密度表格展示在线、进程、版本、revision、漂移和最后心跳；
- 节点详情用 tabs 区分概览、代理、配置历史、任务、监控；
- 配置发布先展示语义 diff、影响判断（reload/restart）、目标节点与验证结果；
- 任务页展示明确的步骤时间线和错误码，不只显示“失败”；
- 危险操作使用 modal 二次确认，按钮在进行中不可重复触发；
- SSE 事件只用于让 Query cache 失效并重新拉取，不把事件流本身当作事实源。

## 17. 部署方案

### 17.1 当前单机形态：Docker Compose

```text
reverse-proxy (Caddy/Nginx)
  ├─ /api, /events -> frp-admin-server:8080
  └─ gRPC :8443   -> frp-admin-server:8443
frp-admin-server
database (默认使用 server 本地 SQLite；也可配置 mysql:8/postgres:16)
```

- Web 使用独立 Nginx 静态容器，反向代理 `/api` 和 `/events` 到 Server；
- SQLite 数据文件挂载持久化 volume；使用 MySQL/PostgreSQL 时数据库不暴露宿主公网；
- TLS 在反向代理终止用户流量，Agent mTLS 可由 server 直接终止或由支持透传客户端证书的网关处理；
- master key、CA key、数据库密码通过 secret 文件挂载；
- SQLite 使用在线 backup API/`VACUUM INTO` 生成一致备份，MySQL/PostgreSQL 分别使用其官方备份工具；同时备份 secret/CA。

### 17.2 中期：Kubernetes/HA

- server 多副本，Agent gRPC 连接任意实例；
- HA 部署只支持 MySQL/PostgreSQL；SQLite 部署升级前必须保持单副本；
- MySQL/PostgreSQL 使用托管高可用或成熟 operator；
- `agent_sessions` 保存 instance lease，任务调度只发送本地连接；
- 各实例短轮询自身 session 对应的 queued task；如轮询压力或事件延迟不达标，引入 NATS 作为通知层，数据库仍为事实源；
- SSE 经负载均衡可连接任意实例；多副本下使用 NATS 广播 cache invalidation/event hint；
- 不要求粘性会话；连接断开由 Agent 自动重连；
- NATS 消息不作为任务事实，不引入 Kafka。

### 17.3 备份与恢复

必须一起备份：所选业务数据库、master key、Agent CA 私钥/证书及部署配置。只恢复数据库而丢失 master key 会使所有 secret 永久不可读；丢失 CA key 则无法继续轮换 Agent 证书。

恢复演练至少每季度一次，验收包括：用户登录、secret 解密、已有 Agent 重连、新 Agent 注册、配置发布和审计查询。

## 18. 可观测性与运维

### 18.1 日志

统一 JSON 日志字段：`timestamp`、`level`、`service`、`version`、`request_id`、`task_id`、`node_id`、`command_id`、`error_code`。禁止记录配置全文、token、cookie 和私钥。

### 18.2 Metrics

控制面至少暴露：

- `agent_connections`、`agent_reconnects_total`；
- `tasks_total{type,state}`、`task_duration_seconds`；
- `config_apply_total{result}`、`config_rollback_total{result}`；
- `grpc_messages_total{type}`、发送队列深度；
- HTTP RED metrics、DB pool 和 query latency；
- traffic ingestion dropped/lag。

### 18.3 Trace

从 HTTP request -> task -> command -> Agent result 传播 W3C trace context。Agent 本地 systemd/CLI 步骤作为 spans，但不采集命令 stdout 全文。

## 19. 测试策略

### 19.1 测试金字塔

| 层 | 覆盖重点 |
|---|---|
| 单元 | 配置 diff、reload 判定、状态机、RBAC、错误映射、checksum |
| 属性/模糊 | TOML 解析渲染、协议消息、敏感值脱敏 |
| 集成 | SQLite/MySQL/PostgreSQL 事务、任务抢占、migration、证书注册/轮换 |
| Agent 集成 | 临时目录 + fake systemd/frp CLI，验证原子替换和失败回滚 |
| 兼容矩阵 | frp v0.60、受支持中间版本、最新版；amd64/arm64 |
| E2E | 两个 frpc + 一个 frps 容器/VM，完整发布、漂移、升级、回滚 |
| 前端 E2E | 登录、注册 token、配置 diff、任务进度、错误态 |
| 性能 | 1000 streams、心跳风暴、100 并发任务、10000 proxies |

systemd 行为不能只依赖单元测试。普通 PR 使用 fake adapter，nightly/release 使用 privileged Ubuntu fixture，并应在最终候选上追加非容器 VM 复验。当前 root helper 所有权与类型化服务生命周期模型已在 privileged Ubuntu systemd fixture 完整通过，但证据尚未绑定候选 commit/tag，因此只能标记为候选工作区 PASS。

### 19.2 必测故障注入

- Agent 在收到命令、写候选、替换配置、restart 后任一点崩溃；
- 控制面在 task dispatch 和结果入库之间重启；
- 数据库短暂不可用；
- 同一命令重复投递；
- checksum 错误、磁盘满、权限错误；
- 新二进制无法启动，旧二进制回滚；
- 配置发布后 frpc 无法登录 frps；
- Agent 证书过期/撤销和服务端时钟偏差。

验收不是“接口返回成功”，而是任务状态、文件、systemd、observed revision 和审计记录保持一致。

## 20. CI/CD 与供应链

CI 已定义 Go/Web test、race 关键路径、vet、协议生成 diff、MySQL/PostgreSQL contract、镜像构建、浏览器 E2E、privileged systemd/control-plane E2E。security workflow 执行 govulncheck、npm production audit、Trivy 与 SBOM；tag release workflow 执行多架构构建、SBOM、签名和 provenance。定义 workflow 不等于生产批准：当前工作区的 privileged systemd、control-plane 和数据库故障 E2E 已通过，但尚未绑定候选 commit/tag；in-app Browser 当前不可用导致视觉验收未完成。候选发布还必须关联独立环境证据；OpenAPI diff、frp 版本矩阵和 168h soak 不能假定已由普通 PR CI 覆盖。

发布产物：

- `frp-agent_<version>_<os>_<arch>.tar.gz`；
- `frp-admin-server` OCI image；
- Compose/systemd/release bundle；Helm chart 属于 HA 阶段目标；
- SHA-256 checksums、CycloneDX/SPDX SBOM；
- cosign 签名和 provenance；
- 数据库 migration 与升级说明。

版本规则：server/web 同版本发布，Agent 独立版本；协议遵循兼容窗口。数据库 migration 默认只向前，破坏性 schema 变更使用 expand -> migrate -> contract 三阶段。

## 21. 分阶段实施计划

### 21.1 已交付的首期基线（0-3 月）

| 优先级 | 里程碑 | 交付与验收 |
|---:|---|---|
| P0 | M0 工程骨架 | 已交付：monorepo、Go modules、前端、repository/三库 migration、CI、Compose |
| P0 | M1 注册与在线 | 已交付：enrollment、mTLS stream、证书轮换、心跳、inspect、节点列表 |
| P0 | M2 进程与配置闭环 | 已交付：observe/managed、启停、raw TOML、Secret reference、verify、发布、自动回滚 |
| P1 | M3 运行态与任务 | 已交付：proxy/client 快照、任务步骤/超时/取消、SSE、告警/Webhook |
| P1 | M4 单节点升级 | 已交付：HTTPS URL、加密凭据、checksum、安全解压、verify、失败恢复 |
| P1 | M5 生产工程 | 已交付代码与 fixture：备份恢复、历史 key ring、最新 root helper systemd/control-plane E2E、发布安全 workflow；视觉验收、候选版本证据绑定和 168h soak 未完成 |

生产批准门槛：

- 至少 100 个 Agent 连续运行 168 小时，无任务丢失和连接泄漏；当前尚无完整通过报告，是硬阻断项；
- 配置故障注入测试全部能自动回滚或明确进入人工处理态；
- 关键链路有审计和 metrics；
- 数据库 + CA + master key 完成一次恢复演练；
- 安全检查确认无任意命令执行、默认口令、明文 secret 日志。

### 21.2 中期（3-12 月）：规模与企业能力

按实际使用数据排序：

1. OIDC/LDAP、细粒度资源权限和可选审批；
2. 多副本控制面、任务压力测试和 NATS 引入评估；
3. 批量灰度升级、暂停/继续策略；
4. 更多 frp 配置 schema、兼容性自动测试；
5. Agent 自升级 helper 与更严格本机权限隔离；
6. 企业微信/钉钉/飞书告警；
7. 业务库时序容量达到阈值后评估 TimescaleDB 或外部 Prometheus-compatible storage。

### 21.3 长期（1 年+）：产品化演进

- Windows service / launchd 和非 systemd 适配；
- 跨 frps 的容量、调度和容灾编排；
- GitOps 配置源、策略即代码和开放 API；
- 如商业目标明确，再立项多租户 SaaS：重新设计 tenant boundary、RLS、配额、计费、独立 CA/密钥和合规，而不是简单增加 `tenant_id`；
- 评估 frp v2 的兼容策略，保持 adapter 边界，不承诺原地透明升级。

## 22. 主要风险与决策

| 优先级 | 风险 | 影响 | 应对 |
|---:|---|---|---|
| P0 | Agent 权限过大 | 控制面被攻陷可影响所有节点 | 无 Shell、命令/路径白名单、mTLS、最小权限、审计 |
| P0 | 发布后节点/服务失联 | 业务中断且无法远程修复 | 本地事务、verify、健康窗口、自动回滚、保留备份 |
| P0 | frp Admin API/配置变化 | 新版本监控或编辑失效 | version adapter、支持矩阵、实际二进制 verify |
| P1 | raw 与结构化配置无法无损往返 | 用户配置被覆盖 | 模式互斥、切换预览、raw 默认 restart |
| P1 | 单体长连接扩展 | 规模增长后实例内路由复杂 | DB lease + 本地 session，压测后再引入消息总线 |
| P1 | secret/CA 备份遗漏 | 灾难恢复失败 | 统一备份清单、启动检查、季度恢复演练 |
| P1 | 三数据库行为差异 | 锁、migration、时间和索引语义导致线上分叉 | 公共 SQL 子集、adapter、三库 CI；SQLite 明确单实例边界 |
| P2 | 监控数据膨胀 | 业务库成本增加，SQLite 尤其明显 | 聚合、分批清理、差异化保留策略、阈值触发时序库评估 |

## 23. 待落地的 ADR

实现前应在 `docs/adr/` 固化以下决策，避免开发过程中反复争论：

1. ADR-001：模块化单体而非微服务；
2. ADR-002：单 Agent 二进制双角色；
3. ADR-003：mTLS 双向流与注册证书模型；
4. ADR-004：desired/observed + 持久化 task 状态机；
5. ADR-005：canonical JSON + 渲染 TOML + raw 模式；
6. ADR-006：SQLite 默认、MySQL/PostgreSQL 可选的跨方言持久层；
7. ADR-007：浏览器使用 REST + SSE；
8. ADR-008：配置与升级的本地事务/回滚保证。

## 24. 开工顺序

第一条工程主链路应纵向打通，而不是分别堆完前端、后端和 Agent：

```text
创建注册 token
-> Agent enrollment/mTLS connect
-> 节点在线展示
-> 下发 INSPECT
-> task 进度与结果入库
-> SSE 驱动页面刷新
-> 审计可查询
```

这条链路稳定后，再将 `INSPECT` 替换为 `APPLY_CONFIG` 并实现本地事务。它能最早验证协议、身份、连接、调度、状态持久化和前端反馈六个最关键边界，降低三个月后才发现架构不能闭环的风险。

## 25. 结论

首期最合理的工程形态是：**根级子项目 monorepo + Go 模块化单体控制面 + 单一 Go Agent + React 管理台 + 默认 SQLite（可切换 MySQL/PostgreSQL）+ mTLS gRPC 双向流 + REST/SSE**。

项目成败不取决于页面数量，而取决于三个底层保证：配置/升级具备本地事务和自动回滚；命令投递具备持久化与幂等；控制面故障不影响 frp 数据面。任何为了赶功能而绕开这三点的实现，都会把远程管理平台变成新的单点风险。

## 26. 官方能力核验基线

本方案于 2026-07-28 按 frp `v0.70.1` 核验。实现时应把以下官方材料和对应 tag 源码作为兼容依据，不把第三方 API 汇总站或博客视为稳定契约：

- [Configuration File](https://gofrp.org/en/docs/features/common/configure/)：TOML/YAML/JSON、`frpc/frps verify`、includes；
- [Client](https://gofrp.org/en/docs/features/common/client/)：`frpc reload`、`frpc status` 及 common section 热加载限制；
- [Web Interface](https://gofrp.org/en/docs/features/common/ui/)：frps Dashboard、frpc Client Admin UI；
- [frp v0.70.1 release](https://github.com/fatedier/frp/releases/tag/v0.70.1)：官方二进制与 checksum；
- [ServerConfig source](https://github.com/fatedier/frp/blob/v0.70.1/pkg/config/v1/server.go) 与 [ClientConfig source](https://github.com/fatedier/frp/blob/v0.70.1/pkg/config/v1/client.go)：版本适配和 schema 测试基线。

Admin API 没有被本平台定义为跨版本稳定契约。每次扩大支持版本范围前，必须先通过配置校验、状态采集、reload、restart 和升级回滚兼容矩阵。
