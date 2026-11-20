# WebSocket Streams

`nextconnect-core` 在控制端口（默认 `127.0.0.1:9090`）提供两个单向服务端推送 WebSocket 通道，用于免轮询渲染实时网速波形、状态变更和控制台日志。

---

## 握手要求

- `Origin` 请求头必须满足本地白名单校验（否则返回握手拒绝）：
  - 空 `Origin`（如 CLI/Node.js 客户端）
  - `"null"`
  - `file://...`、`app://...`
  - `http://127.0.0.1...`、`http://localhost...`
  - `https://127.0.0.1...`、`https://localhost...`
- 单帧写入超时为 `3s`；客户端主动关闭或断连后，服务端清理订阅通道并退出推送协程。

---

## 1. 实时状态与速率流：`GET /api/v1/ws/traffic`

连接成功后立即推送一条当前 [`TrafficSnapshot`](./Controller-REST-API.md#trafficsnapshot)，此后：
- 每 `1s` 定时推送最新上下行速率（`uploadRateBps`、`downloadRateBps`）、累计字节数、活跃连接数与运行时长。
- 当连接状态发生切换（`setState`）时即时触发额外推送。

**消息帧格式（JSON）**：
```json
{
  "state": "connected",
  "routingMode": "rule",
  "systemProxyOn": true,
  "tunModeOn": false,
  "virtualIp": "10.100.80.15",
  "uploadRateBps": 4096,
  "downloadRateBps": 65536,
  "totalUpload": 182400,
  "totalDownload": 3910400,
  "activeCount": 3,
  "uptimeSeconds": 420
}
```

---

## 2. 实时脱敏日志流：`GET /api/v1/ws/logs`

连接成功后：
1. 先按顺序回放最近最多 **100** 条历史日志（`Engine.RecentLogs(100)`）。
2. 之后每当内核任意模块（`cli` / `router` / `auth` / `svpn` / `proxy` / `socks5` / `http-proxy` / `tun` / `api`）记录新日志时实时推送。

**消息帧格式（JSON `LogEntry`）**：
```json
{
  "timestamp": "2026-11-20T14:23:55.120411+08:00",
  "level": "info",
  "component": "proxy",
  "message": "SOCKS5(TCP) portal.example.edu:443 -> [GATEWAY-DOMAIN:*.example.edu]"
}
```

> [!NOTE]
> WebSocket `/api/v1/ws/logs` 会推送内核记录的全量消息（不受 CLI `-log-level` 或 `-quiet` 终端输出过滤影响），且所有消息已对 `TWFID` 自动脱敏。
