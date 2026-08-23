# frp集群管理平台技术设计文档

> 本文用于记录产品背景和初始技术判断。可执行的系统边界、协议、数据模型、目录、发布事务、安全和实施计划见 [frp_admin_implementation.md](./frp_admin_implementation.md)。如两份文档存在差异，以实施方案及后续 ADR 为准。

## 1. 背景与目标

frp官方原生提供了frps端的Dashboard/Admin API（`/api/proxies`、`/api/clients`、`/api/traffic/:name`等），可以在不改动frpc的情况下只读收集节点、代理、流量信息。但官方架构中配置变更只能由frpc主动发起（例如`frpc reload`热加载代理），frps无法反向推送配置给frpc，因此若要实现"完全管理"（集中下发配置、远程重启、版本升级），必须在frpc/frps两侧各部署一个轻量agent，由agent负责本机的配置文件读写、进程生命周期管理和状态上报，管理面板则作为中心控制平面统一调度所有agent。[^1][^2][^3][^4][^5]

本设计的核心原则是**零侵入官方二进制**：不fork或重新编译frp源码（区别于VaalaCat/frp-panel将frp作为库嵌入自定义二进制的做法），而是让agent作为独立进程"托管"官方原生frpc/frps可执行文件，两者通过进程管理和本地API交互，从而保证frp本身可以独立于agent单独升级版本。[^6][^7][^8]

## 2. 总体架构

系统由三个核心组件构成：

| 组件 | 部署位置 | 职责 |
|---|---|---|
| frpc-agent | 每个frpc节点所在主机 | 探测/安装/托管frpc进程，监控状态，接收面板指令改配置、重启、升级 |
| frps-agent | frps服务器 | 托管frps进程，轮询frps本地Admin API，汇总上报给面板 |
| 管理面板 | 独立部署（可与frps同机） | 中心化配置下发、集群拓扑展示、用户鉴权、历史记录、告警 |

frpc节点通常位于NAT内网、无公网IP，因此通信模型采用**agent主动向面板建立长连接**（而非面板主动连接agent），面板通过下行推送指令完成配置变更和重启操作，这与Tailscale、Prometheus等fleet management系统的通用做法一致。frps-agent由于与面板同机或同网段部署，可以退化为本地轮询frps Admin API后上报，无需维护长连接。

## 3. 技术栈选型

### 3.1 Agent（frpc-agent / frps-agent）

推荐语言：**Go**。

选型理由：

- frp官方本身即为Go编写，agent与被托管进程同技术栈，便于团队统一维护、复用交叉编译与分发流程。[^9][^10][^11]
- agent的核心工作负载是文件I/O、进程管理（fork/exec、信号处理）、HTTP轮询与长连接维持，属于I/O密集型任务，Go的goroutine并发模型和标准库（`os/exec`、`os/signal`）天然适配，Rust的所有权模型在此类场景下收益有限而开发成本更高。
- Go支持单文件静态二进制、一条命令交叉编译多平台，与frp官方release的分发方式一致，非常适合"一键安装agent"的分发场景。[^12]
- gRPC/Protobuf生态在Go中最成熟，可与面板端共享同一套接口定义。

两个agent（frpc-agent、frps-agent）建议共享同一套代码基座，通过启动参数或配置区分角色模式，减少重复开发。

### 3.2 管理面板

| 层 | 推荐技术 | 理由 |
|---|---|---|
| 后端 | Go（Gin/Fiber + gRPC Server） | 与agent同语言，Protobuf定义一次两端复用，团队Go/K8s背景可直接复用 |
| 前端 | React + TypeScript（或Vue3 + TS，搭配Ant Design Pro/Element Plus） | 中后台管理系统生态成熟，CRUD和拓扑可视化组件丰富 |
| Agent通信协议 | gRPC双向流（bidirectional streaming） | 强类型接口、内置心跳与背压机制，比裸WebSocket更适合"指令下发+状态上报"双工场景 |
| 前端实时推送 | WebSocket（由面板后端转发） | agent-面板用gRPC，面板-浏览器用WebSocket，两段解耦，各自选用最合适协议 |
| 结构化数据存储 | PostgreSQL | 存储节点信息、代理配置、配置版本历史等强关系数据，团队已有PostgreSQL运维经验可直接复用 |
| 时序数据存储 | InfluxDB/TimescaleDB（可选） | 存储流量、心跳等高频时序指标，避免关系型库承载写密集型监控数据 |

如团队更偏好TypeScript全栈统一，也可用NestJS替代Go作为面板后端，优势是前后端可共享DTO类型定义，但gRPC在Node生态的成熟度不及Go，且面板后续可能涉及批量配置下发、批量升级等并发密集型批处理逻辑，Go的goroutine模型在这类场景下运维成本更低。综合团队现有Go/Python/K8s基础设施背景，统一采用Go承担agent与面板后端是整体成本最低的选择。

## 4. Agent核心能力设计

### 4.1 服务探测与接管模式

agent需支持"复用已装服务"与"一键安装"两种模式：

- **探测阶段**：启动时检测系统是否存在对应的systemd服务单元、进程是否已在运行，识别可执行文件路径、配置文件路径与版本号。
- **接管阶段**：若检测到已有安装，agent仅记录路径信息，后续操作统一通过`systemctl`或进程管理接口执行；若用户选择一键安装，agent自行下载指定版本官方二进制、生成systemd unit、并托管其生命周期。

两种模式下，agent对上层面板暴露的管理接口保持一致，面板无需感知底层安装方式的差异。

### 4.2 配置变更与重启策略

frp官方对配置热更新的支持存在粒度差异，agent需按字段类型分级处理：

| 操作类型 | 官方机制 | 处理方式 |
|---|---|---|
| frpc代理列表增删改（`[[proxies]]`） | 开启`webServer`后执行`frpc reload -c frpc.toml`[^5][^13] | agent调用本地`127.0.0.1:7400`的reload接口，数秒内生效，无需重启进程 |
| frpc顶层公共参数（`serverAddr`、`auth.token`等） | reload机制不支持此类变更[^5][^14] | agent写入新配置文件后，通过systemd重启frpc进程 |
| frps顶层参数（`bindPort`、`webServer`账号等） | 无热加载机制 | agent写入新配置后重启frps进程 |

面板下发配置变更指令时，应自动判断改动字段归属类别并选择对应链路（reload或重启），而非依赖用户手动判断，这是实现"完全管理"体验的关键环节。

### 4.3 配置文件格式适配

frp自v0.52.0起采用TOML/YAML/JSON替代旧版INI格式，agent在生成和校验配置时需按目标frp版本选择对应的字段schema，避免新旧版本字段命名（如驼峰式`serverAddr`）不一致导致解析失败。[^15][^16][^17]

### 4.4 进程守护与版本管理

- **进程守护**：建议将frpc/frps进程托管给systemd而非agent自行实现supervisor逻辑，降低agent自身异常导致连带故障的风险，agent仅负责监听状态并上报。
- **版本管理**：agent需支持下载指定版本官方release二进制、校验checksum、原子替换（停止旧进程→替换文件→用新配置拉起），实现独立于agent版本的frp版本升级能力。[^12]
- **配置漂移检测**：agent应能检测配置文件的mtime或hash变化并上报面板，避免用户绕过面板手动改动配置导致状态不一致。

## 5. 管理面板核心功能模块

- **节点管理**：展示所有frpc/frps节点的在线状态、版本、安装模式（复用/一键装），支持批量操作。
- **配置中心**：可视化编辑代理配置，自动判断reload/restart链路并下发，保留配置版本历史支持回滚。
- **监控与告警**：汇总frps Admin API的流量、连接数数据与agent上报的进程健康状态，异常时触发告警。[^2][^3]
- **版本升级管理**：远程触发指定节点的frp二进制升级，支持灰度批次升级。
- **鉴权与多租户**：结合frps原生`user`字段或httpPlugin鉴权插件思路，实现多用户/多团队的节点隔离。[^18][^19]

## 6. 与已有社区方案的差异化定位

| 维度 | 本方案 | frps-panel插件方案[^18][^19] | frp-panel嵌入式方案[^6][^7][^8] |
|---|---|---|---|
| 是否修改/重编译frp | 否，agent托管原生二进制 | 否，以httpPlugin方式挂载 | 是，将frp作为库嵌入自定义二进制 |
| frp版本独立升级 | 支持，agent与frp解耦 | 支持，但功能受限于插件接口 | 受限，需随自定义二进制一起升级 |
| 已有安装复用 | 支持探测接管模式 | 不支持 | 不支持，需替换为其打包版本 |
| 主动配置下发/重启 | 支持（agent本地执行） | 不支持（仅鉴权与展示） | 支持（但依赖其自有协议） |

该差异化设计使本方案在保留官方frp二进制完整性和独立升级能力的同时，仍能实现与frp-panel同等级别的集中式配置管理能力，是在"零侵入"与"完全管理"两个目标之间的折中优化。

---

## References

1. [Web Interface - frp](https://gofrp.org/en/docs/features/common/ui/) - The server Dashboard allows users to view frp status and proxy statistics through a browser. You can...

2. [Frp | APIs.io Providers](https://apis.io/providers/frp/) - frp publishes 2 APIs on the APIs.io network: Server Admin API and Client Admin API. Tagged areas inc...

3. [frp Server Admin API — Documentation, OpenAPI](https://apis.io/apis/frp/server-admin-api/) - It returns version and traffic information for the server, lists connected clients, lists and inspec...

4. [Client - frp](https://gofrp.org/en/docs/features/common/client/) - Dynamic Configuration Updates When you need to modify frpc proxy configuration, you can use the frpc...

5. [客户端 - frp](https://gofrp.org/zh-cn/docs/features/common/client/) - 当你需要修改frpc 的代理配置时，你可以使用 frpc reload 命令来实现动态加载配置文件，通常在数秒内完成代理的更新。 要启用此功能，需要在frpc 中启用webServer，以提供API ...

6. [FRP-Panel](https://github.com/VaalaCat/frp-panel) - FRP-Panel is a visualization management dashboard for FRP, offering centralized configuration, unifi...

7. [frp-panel/README_zh.md at main](https://github.com/VaalaCat/frp-panel/blob/main/README_zh.md) - FRP-Panel 是一款基于FRP 的可视化管理面板，提供中心化配置、统一凭证、动态调度和边缘Worker 支持，让内网穿透和服务暴露更简单、更安全、更高效。

8. [frp-panel 项目亮点解析](https://blog.gitcode.com/9c0254c7ed8daeed0e4be5650ff9f648.html) - frp-panel 是一个基于frp 内网穿透工具的Web 管理面板，旨在为用户提供一个直观、便捷的方式来配置和管理frp 服务。该项目通过Web 界面简化了配置过程，使得 ...

9. [fatedier/frp](https://github.hot/repo/fatedier/frp) - 高性能反向代理工具，将 NAT 或防火墙后的本地服务暴露到公网

10. [#每天一开源# frpfrp 是一种用 Go 开发的快速反向代理，可帮助我们将 NAT 或防火墙后面的本地服务器暴露给 Internet。 目前，它支持 TCP 和 UDP，以及 HTTP 和 HTTPS 协议，可以通过域名将请求转发到内部服务。frp 还有一个 P2P 连接模式。repo：github.com/fatedier/frp⭐️ ：60.5k语言：Go](https://www.sina.cn/news/detail/4826555647264871.html) - #每天一开源# frpfrp 是一种用 Go 开发的快速反向代理，可帮助我们将 NAT 或防火墙后面的本地服务器暴露给 Internet。 目前，它支持 TCP 和 UDP，以及 HTTP 和 HTT...

11. [推荐一款很好用的内网穿透工具FRP - Junkman](https://panlw.github.io/15514075339420.html)

12. [Releases · fatedier/frp](https://github.com/fatedier/frp/releases) - A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet. - f...

13. [FRPC不同场景下的重启方法与配置指南_文心快码](https://comate.baidu.com/zh/page/bhppjdpetny) - 动态重载配置(无需重启) 适用于启用webServer 的场景: bash 复制 1frpc reload -c /path/to/frpc.ini 注意:此方式仅更新代理配置,不重启进程。

14. [功能说明- 客户端热加载配置文件- 《frp v0.27 中文文档》](https://www.bookstack.cn/read/frp/spilt.7.spilt.4.README_zh.md) - 当修改了frpc 中的代理配置，可以通过 frpc reload 命令来动态加载配置文件，通常会在10 秒内完成代理的更新。 ... 等待一段时间后客户端会根据新的配置文件 ...

15. [FRP项目中TOML配置格式的常见问题解析 - GitCode博客](https://blog.gitcode.com/73143bdf62cb3471c4b8e3cd5aa0bcd9.html) - FRP作为一款优秀的内网穿透工具，其配置文件格式从INI过渡到TOML后，许多用户在迁移过程中遇到了各种配置问题。本文将深入分析FRP项目中TOML配置文件的正确写法，特别是针对Windows环境下常...

16. [frp新版toml配置原创 - CSDN博客](https://blog.csdn.net/qq233325332/article/details/136065890) - 文章浏览阅读9.6k次，点赞12次，收藏35次。从frpv0.52.0版本开始，frp 将TOML作为配置文件格式。INI 格式已被弃用，并将在未来的发布中移除。因此，frp v0.52.0 及更高版...

17. [配置文件 - frp](https://gofrp.org/zh-cn/docs/features/common/configure/) - 从 v0.52.0 版本开始，frp 开始支持 TOML、YAML 和 JSON 作为配置文件格式。 请注意，INI 已被弃用，并将在未来的发布中移除。新功能只能在TOML、YAML 或 JSON 中...

18. [frps-panel/README_zh.md at main · yhl452493373/frps-panel](https://github.com/yhl452493373/frps-panel/blob/main/README_zh.md) - frps-panel 是 https://github.com/fatedier/frp 的一个服务端插件，用于支持多用户鉴权，同时用于展示服务器信息。 - yhl452493373/frps-pan...

19. [frps-panel(Support FRP >= 0.52.0)](https://github.com/yhl452493373/frps-panel) - frps-panel 是 https://github.com/fatedier/frp 的一个服务端插件，用于支持多用户鉴权，同时用于展示服务器信息。 - yhl452493373/frps-pan...
