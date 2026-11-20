# NextConnect Core Wiki

欢迎查阅 **NextConnect Core** 技术文档。本 Wiki 覆盖了独立内核 `nextconnect-core` 的本地控制接口、WebSocket 实时遥测流、CLI 命令行用法与诊断排错流程。

---

## 文档导航

| 文档 | 内容说明 |
| :--- | :--- |
| [Controller REST API](./Controller-REST-API.md) | 全部本地 HTTP 接口、请求/响应 JSON 结构、状态码与 `curl` 示例 |
| [WebSocket Streams](./WebSocket-Streams.md) | 实时流量/状态推送（`/api/v1/ws/traffic`）与日志流（`/api/v1/ws/logs`） |
| [CLI and Diagnostics](./CLI-and-Diagnostics.md) | 命令行启动模式、参数表、交互式密码输入、全量日志与故障诊断流程 |

---

## 架构与安全模型

- **默认监听地址**：
  - 本地控制 API：`http://127.0.0.1:9090`（可通过 `-controller` 修改）
  - 本地 SOCKS5 代理：`127.0.0.1:10808`（可通过 `-socks` 修改）
  - 本地 HTTP / PAC 代理：`127.0.0.1:10809`（可通过 `-http` 修改）
- **访问控制与 Origin 校验**：
  - API 默认仅绑定 `127.0.0.1` 回环地址，并设置本地调试所需的 CORS 响应头（允许 `GET, POST, PATCH, DELETE, OPTIONS` 与 `Content-Type`）。
  - WebSocket 握手严格校验 `Origin`，仅放行空 Origin、`"null"`、`file://`、`app://` 以及 `http(s)://127.0.0.1*` / `http(s)://localhost*`。
- **敏感凭据保护**：
  - 所有响应体不会返回明文密码、`TWFID` 或 `TunnelToken`（`SessionTicket` 对应字段标签为 `json:"-"`）。
  - 所有内核日志经 `Engine.Log` 自动对当前活动 `TWFID` 做掩码脱敏处理。
