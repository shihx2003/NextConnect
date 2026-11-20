# Controller REST API

`nextconnect-core` 启动后会暴露兼容本地控制器（Clash Party 风格）的 HTTP REST 接口，默认基础地址为 `http://127.0.0.1:9090`。

所有 JSON 响应均使用 `Content-Type: application/json; charset=utf-8`（`/api/v1/proxy.pac` 除外）。

---

## 接口总览

| 方法与路径 | 用途 | 成功状态码 |
| :--- | :--- | :--- |
| `GET /api/v1/status` | 查询内核状态、代理开关与实时流量快照 | `200 OK` |
| `POST /api/v1/connect` | 使用账密或 CAS Cookie 登录并建立 SVPN 隧道 | `200 OK` |
| `POST /api/v1/disconnect` | 注销会话、停止本地代理并还原虚拟路由 | `200 OK` |
| `PATCH /api/v1/mode` | 切换分流模式（`rule`/`global`）、系统代理或 Wintun 模式 | `200 OK` |
| `GET /api/v1/rules` | 查询当前生效的分流规则列表（网关下发 + 预置规则） | `200 OK` |
| `GET /api/v1/connections` | 查询当前活跃转发连接及实时速率 | `200 OK` |
| `DELETE /api/v1/connections/{id}` | 主动断开指定 ID 的活跃连接 | `200 OK` |
| `GET /api/v1/logs` | 拉取历史脱敏日志（支持 `?limit=N`） | `200 OK` |
| `GET /api/v1/tun/capabilities` | 检测当前主机 `Wintun` 可用性与管理员权限状态 | `200 OK` |
| `GET /api/v1/proxy.pac` | 获取动态生成的校园网分流 PAC 脚本 | `200 OK` |

---

## 核心枚举与公共对象

### `ConnectionState`
- `"disconnected"` — 未连接
- `"authenticating"` — 正在向网关执行身份认证
- `"establishing_tunnel"` — 认证完成，正在握手建立 SVPN L3 隧道
- `"connected"` — 隧道与本地代理已就绪
- `"faulted"` — 连接/隧道发生不可恢复故障

### `TrafficSnapshot`
```json
{
  "state": "connected",
  "routingMode": "rule",
  "systemProxyOn": true,
  "tunModeOn": false,
  "virtualIp": "10.100.80.15",
  "uploadRateBps": 1280,
  "downloadRateBps": 24576,
  "totalUpload": 102400,
  "totalDownload": 2048576,
  "activeCount": 2,
  "uptimeSeconds": 185
}
```

> [!NOTE]
> `virtualIp` 在未分配或未连接状态下可能省略（`omitempty`）或为空值。

---

## 接口详情

### 1. `GET /api/v1/status`
获取当前运行快照。

**示例**：
```bash
curl -s http://127.0.0.1:9090/api/v1/status
```

**响应（`200 OK`）**：返回 [`TrafficSnapshot`](#trafficsnapshot) JSON 对象。

---

### 2. `POST /api/v1/connect`
发起网关认证、建立 Port 443 SVPN 隧道并启动本地 `SOCKS5`/`HTTP` 代理（服务端超时上限 `45s`）。

**请求体（`ConnectParams`）**：

| 字段 | 类型 | 必填 | 说明 |
| :--- | :--- | :--- | :--- |
| `gatewayUrl` | `string` | 是（若未预配置） | 目标 SSL VPN 网关地址，如 `https://vpn.example.edu` |
| `username` | `string` | 条件 | 账密登录必填；使用 `casCookie` 时可留空 |
| `password` | `string` | 条件 | 账密登录必填；使用 `casCookie` 时可留空 |
| `captchaCode` | `string` | 否 | 二次图形验证码内容 |
| `preTwfId` | `string` | 否 | 验证码挑战返回的 `challengeId` |
| `casCookie` | `string` | 否 | WebView CAS 登录提取的 `TWFID` Cookie |
| `routingMode` | `string` | 否 | `"rule"` 或 `"global"` |

**正常响应（`200 OK`）**：
```json
{
  "status": {
    "state": "connected",
    "routingMode": "rule",
    "systemProxyOn": true,
    "tunModeOn": false,
    "virtualIp": "10.100.80.15",
    "uploadRateBps": 0,
    "downloadRateBps": 0,
    "totalUpload": 0,
    "totalDownload": 0,
    "activeCount": 0,
    "uptimeSeconds": 0
  },
  "ticket": {
    "gatewayHost": "vpn.example.edu",
    "gatewayPort": 443,
    "virtualIp": "10.100.80.15",
    "dnsServers": ["10.84.1.1", "8.8.8.8"],
    "intranetSubnets": ["10.0.0.0/8"],
    "intranetDomains": ["*.example.edu"],
    "l3Eigenvalue": "L3IP",
    "l3CipherSuite": "RC4-SHA",
    "tunnelMtu": 1400,
    "expiresAtUtc": "2026-11-20T12:53:06Z"
  }
}
```
*注：`TwfID` 与 `TunnelToken` 在服务端 JSON 序列化中标记为 `json:"-"`，绝不会暴露到响应中。*

**需要二次验证响应（`409 Conflict`）**：
```json
{
  "requiresSecondaryAuth": true,
  "challenge": {
    "authType": "captcha",
    "nextAuth": "rand_code",
    "message": "请输入图形验证码",
    "challengeId": "...",
    "captchaImageBase64": "iVBORw0KGgo..."
  }
}
```

**错误响应**：
- `400 Bad Request`：`{"error": "invalid connect json payload"}`
- `401 Unauthorized`：`{"error": "..."}`

---

### 3. `POST /api/v1/disconnect`
断开 SVPN 隧道、关闭本地代理、清理 TUN 路由并向网关发送注销请求。

**示例**：
```bash
curl -s -X POST http://127.0.0.1:9090/api/v1/disconnect
```

**响应**：
- `200 OK`：返回更新后的 `TrafficSnapshot`。
- `500 Internal Server Error`：`{"error": "..."}`

---

### 4. `PATCH /api/v1/mode`
动态更新分流模式与代理/虚拟网卡状态；若模式切换（例如开启 Wintun 权限不足）失败，核心会自动回滚状态并在错误响应中返回当前快照。

**请求体（均为可选指针字段）**：
```json
{
  "systemProxyOn": true,
  "tunModeOn": false,
  "routingMode": "rule"
}
```

**响应**：
- `200 OK`：更新后的 `TrafficSnapshot`。
- `400 Bad Request`：
  - 若 `routingMode` 非法：`{"error": "invalid routingMode: must be rule or global"}`
  - 若切换开关失败：`{"error": "...", "status": { ...当前快照... }}`

---

### 5. `GET /api/v1/rules`
获取当前分流路由表与模式。

**响应（`200 OK`）**：
```json
{
  "routingMode": "rule",
  "rules": [
    {
      "type": "DOMAIN-SUFFIX",
      "pattern": "*.example.edu",
      "action": "TUNNEL",
      "source": "gateway-autorule"
    },
    {
      "type": "IP-CIDR",
      "pattern": "10.0.0.0/8",
      "action": "TUNNEL",
      "source": "builtin-intranet"
    }
  ]
}
```

---

### 6. `GET /api/v1/connections`
查询当前正在进行中的连接列表。

**响应（`200 OK`）**：
```json
{
  "connections": [
    {
      "id": "conn-1",
      "source": "127.0.0.1:53210",
      "destination": "portal.example.edu:443",
      "network": "SOCKS5(TCP)",
      "rule": "GATEWAY-DOMAIN:*.example.edu",
      "uploadBytes": 782,
      "downloadBytes": 5466,
      "uploadRateBps": 0,
      "downloadRateBps": 0,
      "startedAt": "2026-11-20T12:54:34.538Z"
    }
  ]
}
```

---

### 7. `DELETE /api/v1/connections/{id}`
强制关闭指定连接 ID。

**示例**：
```bash
curl -s -X DELETE http://127.0.0.1:9090/api/v1/connections/conn-1
```

**响应**：
- `200 OK`：`{"closed": "conn-1"}`
- `400 Bad Request`：`{"error": "connection id is required"}`
- `404 Not Found`：`{"error": "..."}`

---

### 8. `GET /api/v1/logs`
拉取内核内存中保留的历史脱敏日志（环形缓冲上限 500 条）。

**查询参数**：
- `limit`（可选整数，正数有效；未指定或 `<= 0` 返回全部保留日志）。

**示例**：
```bash
curl -s "http://127.0.0.1:9090/api/v1/logs?limit=20"
```

**响应（`200 OK`）**：
```json
{
  "logs": [
    {
      "timestamp": "2026-11-20T12:53:06.121Z",
      "level": "info",
      "component": "auth",
      "message": "authenticated (twfid=43f0****0502, dns=2, subnets=54, domains=211)"
    }
  ]
}
```

---

### 9. `GET /api/v1/tun/capabilities`
检查宿主机启用 `Wintun` 虚拟网卡模式的前置条件。

**响应（`200 OK`）**：
```json
{
  "platform": "windows",
  "wintunAvailable": true,
  "elevated": false,
  "adapterName": "NextConnect",
  "wintunPath": "C:\\Windows\\System32\\wintun.dll"
}
```

---

### 10. `GET /api/v1/proxy.pac`
返回可供浏览器或系统代理使用的 PAC 自动配置脚本。

- **响应头**：`Content-Type: application/x-ns-proxy-autoconfig; charset=utf-8`
- **状态码**：`200 OK`
