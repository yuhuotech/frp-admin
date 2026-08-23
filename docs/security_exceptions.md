# 安全例外登记

## React Router GHSA-qwww-vcr4-c8h2（唯一启用例外）

| 字段 | 内容 |
|---|---|
| npm advisory | `1124282` |
| 严重级别 | High |
| 受影响能力 | React Server Components action 请求处理 |
| 当前适用性 | 不可达：入口使用 `BrowserRouter`，Web 由 Vite 构建为纯静态 SPA，生产镜像仅用 Nginx 提供静态资源，不包含 RSC、SSR、server action 或 React Router server runtime |
| 临时控制 | CI 仅对白名单 advisory ID 放行；任何其他 high/critical 依赖漏洞仍阻断 |
| 解除条件 | 上游发布修复版本后升级依赖并删除 `web/scripts/audit-production.mjs` 中的例外 |
| 复核频率 | 每周自动审计及每次依赖升级 |

这是当前唯一允许的 npm high advisory 例外，不是通用包名或严重度豁免。该例外不覆盖未来引入 SSR/RSC 的变更；若前端架构切换到服务端渲染或 server actions，必须在合并前撤销例外并重新完成威胁建模。
