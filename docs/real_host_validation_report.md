# frp-admin 真实主机验证报告

> 日期：2026-07-29  
> 主机：WSL2 Ubuntu 客户端、macOS 15.6 客户端、Ubuntu 24.04 正式 frps 服务器  
> 结论：真实主机的注册、mTLS、心跳、重连、只读检查、runtime 采集、旁路数据面和本轮部署风险整改通过；不构成生产发布批准

## 1. 安全边界

- 正式 frp 二进制均未替换。风险定位阶段保持正式进程只读；经用户确认维护影响后，m200 对 `webServer.addr` 变更执行两次受控 frps restart，machp 合并配置后重启用户级 frpc 并移除 root 遗留 LaunchDaemon。
- 隔离兼容验证阶段在 m200 创建的独立 Tailscale frps 0.70 transient unit 和只读 Server Agent 均有资源、运行时限，验证后已删除；它们与后续正式配置整改相互独立。
- WSL 控制面使用独立用户目录、SQLite、PKI、master key 和 user-systemd unit。
- 未对正式服务执行 frp 二进制升级或 frp-admin 的通用配置发布/回滚验收。本轮正式写操作只限已明确授权的三项部署整改，均先备份并在变更后验证控制连接、代理数和代表数据面。

## 2. 环境

| 节点 | 系统 | frp | 正式状态 |
|---|---|---:|---|
| PC01636 | WSL2 Ubuntu，Linux amd64，systemd | frpc 0.68.1 | active；自 2026-07-21 稳定运行 |
| machp.local | macOS 15.6 amd64，launchd | frpc 0.69.1 | 单一用户实例，最终 PID 87533，已建立到正式 frps 的连接 |
| VM-0-4-ubuntu | Ubuntu 24.04 amd64，systemd | frps 0.68.1 | active；最终 PID 3080004，`NRestarts=0` |

正式 frps 最终观测到 4 个唯一客户端，均为 `online=true`。不记录运行时 client ID：

| Hostname | frpc 版本 | 状态 |
|---|---:|---|
| `ubuntu` | 0.69.1 | online |
| `ubuntu-32-98` | 0.68.1 | online |
| `PC01636` | 0.68.1 | online |
| `machp.local` | 0.69.1 | online |

## 3. 控制面与 Agent

| 门禁 | 结果 | 证据摘要 |
|---|---|---|
| WSL 隔离控制面 | PASS | Tailscale `100.88.5.1` 上 HTTP/gRPC 可由本机和 macOS 访问；Server 无重启 |
| 100 Agent 注册和 mTLS | PASS | 100 Agents，200 sessions，0 provision/connect/reconnect/stream failure |
| 心跳与重连 | PASS | 1500 heartbeats；peak active 100；reconnect wave 227.450 ms |
| 100 并发任务 churn | PASS | 600/600 task succeeded，0 failed/timeout；p50/p95/p99 661.600/782.022/812.047 ms |
| Ubuntu 真实 Agent | PASS | enrollment、mTLS、heartbeat、只读 inspect 成功 |
| macOS 真实 Agent | PARTIAL | enrollment、mTLS、heartbeat、runtime 成功；历史验证中的 inspect 曾返回固定 `INTERNAL / command failed`。当前实现已将不可用的 systemd 状态降级为 `unknown/status_unavailable`，并将只读 `inspect`、`risk.scan` 与 launchd 生命周期解耦，但尚未使用包含这些变更的最新 Agent 二进制在真实 macOS 上复验，因此本行不构成这两项 capability 的实机通过证据 |
| 正式 frps Agent | PASS | server-role enrollment、inspect、runtime collection 成功；整改前采集 5 clients，整改后稳定为 4 个唯一 clients、13 running proxies |

## 4. 旁路 frp 数据面

在 m200 上使用 frps 0.70.0 创建独立实例，只监听 Tailscale `100.88.3.1:17000`，Admin API 只监听 loopback，并限制为 128 MiB、25% CPU、2 小时最长运行时间。

| 客户端 | 客户端版本 | 旁路代理 | 结果 |
|---|---:|---|---|
| Ubuntu | frpc 0.68.1 | `frp-admin-validation-ubuntu` | online；经 m200 读取独立 HTTP 后端成功 |
| macOS | frpc 0.69.1 | `frp-admin-validation-macos` | online；经 m200 读取独立 HTTP 后端成功 |

两个 Agent 均通过 loopback Admin API 成功采集 1 个运行中代理，证明 frpc 0.68/0.69 与 frps 0.70 的本次旁路场景兼容。

## 5. 发现的问题与整改状态

| 严重度 | 状态 | 问题 | 影响与建议 |
|---|---|---|---|
| HIGH | RESOLVED | 正式 frps Admin API 曾监听 `0.0.0.0:7500` | 已将 `webServer.addr` 改为 `127.0.0.1` 并受控重启；最终仅 `127.0.0.1:7500` 监听。此前仅匹配公网接口的临时 IPv4/IPv6 防火墙规则已精确删除，避免把临时网络规则当作长期配置 |
| HIGH | RESOLVED | 三台主机的 frp 配置包含 inline `auth.token` 且原权限为 `0644` | 三份配置权限均已收紧为 `0600`，原有 group/other 读取风险已消除；文件所有权 hardening 是下列独立风险，不能因 mode 已修复而一起关闭 |
| HIGH | RESOLVED | 正式 frps 日志中曾存在大量 proxy already-exists | `prod-7110` 已合入 machp 用户级规范配置，最终单一用户实例承载 8 个代理；root 遗留 LaunchDaemon 已移除。整改后 frps 为 4 个唯一 client、13 个运行代理，观察窗口无新增 duplicate/already-exists |
| MEDIUM | OPEN | WSL `frpc.service` 历史 `NRestarts=27694` | 当前已稳定一周且近 30 分钟无 warning，但需结合历史 journal 确认曾经的重启原因 |
| MEDIUM | OPEN | WSL frpc 二进制/配置所有权尚未完成 root hardening | 尝试提权时用户提供的 sudo 凭据未通过，未继续修改；二进制和配置仍为 `ubuntu:ubuntu`，配置 mode 为 `0600`。这不影响现有运行，但 ubuntu 账号仍可替换二进制/配置，需取得有效 root 运维通道后按服务身份重新验收 |
| MEDIUM | ACCEPTED | 正式 frps/frpc 为 0.68.1/0.69.1，项目验证基线为 0.70.0 | 本次只读 runtime 与数据面兼容，但正式升级前仍需版本矩阵和回滚窗口 |
| SCOPE | ACCEPTED | macOS launchd 生命周期未实现 | 当前生产范围明确为 Linux/systemd。代码边界允许 macOS 连接、runtime、只读 inspect/risk scan，以及通过 owner/普通文件/无扩展 ACL 前检后的配置权限修复；最新二进制尚未完成真实 macOS 复验。macOS 仍不得批准 service status/start/stop/restart、配置发布/回滚、frp 升级或 Admin API loopback 自动修复能力 |

## 6. 整改与回滚证据

- 三台正式配置在同目录创建 `*.bak.frp-admin-20260729-permissions` 备份；权限整改时原文件和备份均为 `0600`，正文 SHA-256 一致。后续 loopback 和代理合并属于经授权的配置正文变更，不沿用“哈希未变”结论。
- m200 frps 二进制和配置最终为 `root:root 0755/0600`；所有权加固未重启服务，PID 3080004、`NRestarts=0` 保持不变。WSL 的 root ownership 尝试因 sudo 认证失败而停止，没有用绕过方式提权或修改文件，仍为 `ubuntu:ubuntu`。machp frpc 由用户级 launchd 以 `hongmw` 运行，因此 `hongmw:admin 0600` 配置配合 `root:admin 0555` 二进制是合理边界，无需强改配置为 root 后导致服务不可读。
- m200 loopback 变更前备份为 `/opt/frp/frps.toml.bak.frp-admin-20260729-loopback`。首次受控 restart 用于生效 Admin API loopback，第二次用于清理 machp 重复会话竞态遗留的 `23306` 监听异常。最终 frps 为 PID 3080004、`NRestarts=0`、active，`7500` 只监听 `127.0.0.1`，控制连接与代理均已恢复。
- m200 防火墙变更前规则保存为 `/opt/frp/iptables.before-frp-admin-20260729.rules`，权限 `0600`。临时规则曾只匹配 `eth0` 的 TCP/7500，未修改默认策略；loopback 配置生效后已按原精确规则从 IPv4/IPv6 INPUT 删除，最终规则集中不再存在该临时项。
- 公网复测中，m200 `tcpdump` 观测到发往公网 `7500` 的 SYN 到达主机 `10.0.0.4` 后由主机返回 RST，连续 HTTP 请求均超时；loopback 请求稳定返回未认证 401。偶发 `nc` TCP 成功与主机抓包不一致，判断为云侧 TCP 前置行为，因此证据结论限定为“公网 Admin HTTP API 不可达”，不扩大为“公网 TCP 在所有探测下完全不可连接”。
- machp 合并前配置备份为 `/usr/local/etc/frp/frpc.toml.bak.frp-admin-20260729-consolidate`；用户 LaunchAgent 和 root LaunchDaemon 分别在 `/Users/hongmw/Library/LaunchAgents/homebrew.mxcl.frpc.plist.bak.frp-admin-20260729-consolidate`、`/Library/LaunchDaemons/homebrew.mxcl.frpc.plist.bak.frp-admin-20260729-consolidate` 留存同目录备份。最终用户级 frpc PID 87533，配置包含 8 个代理，system launchd job 不存在。
- 定位阶段对 `prod-7110:23406` 仅建立一次无认证 TCP 连接并读取 MySQL 握手，随后在 macOS 观测到当时的遗留 frpc 连接 `192.168.71.10:3306`；未发送认证信息或业务查询。该阶段 PID 20585/99395 均保持不变，确认归属后才进入受控合并。
- 整改完成后为 4 个唯一 client、13 个 TCP 运行代理。代表数据面 TCP `60023`、`23406`、`23306` 均连通；其中 `23406`、`23306` 仅验证 MySQL 握手/连通，没有认证或业务查询。未因去重减少有效代理。

回滚时，m200 可从 loopback 备份恢复原配置并经 `frps verify` 后 restart；这会重新暴露 Admin API，必须先恢复公网接口的精确 7500 阻断规则。machp 可从 consolidate 配置和对应 plist 备份恢复，但会重新引入双实例与名称争抢，仅用于故障止血，恢复后必须重新规划单实例合并。任何回滚均需再次核对 4 个 client、13 个代理及代表数据面。

## 7. 未通过的生产门禁

- 尚未在目标 Linux + PostgreSQL/MySQL 环境完成 100 Agent、168 小时 soak。
- 本轮正式写操作仅覆盖已备份的部署风险整改，不等价于用 frp-admin 对正式节点验收通用配置发布、升级或失败回滚；最新 root helper privileged systemd fixture 已在候选工作区通过，但正式 tag 仍须绑定 Linux runner 日志，目标环境演练仍待完成。
- WSL 二进制/配置仍为 `ubuntu:ubuntu`，本机所有权 hardening 未完成；不能用 m200 和 machp 的结果替代该节点整改。
- in-app Browser 当前不可用，Web 的目标浏览器视觉验收尚未完成。
- 未对正式部署绑定 release tag、SBOM、签名和 provenance 证据。
- 当前完整实现尚未纳入可追溯的候选 commit/tag。

因此项目仍是 production candidate，不能标记为 production ready。
