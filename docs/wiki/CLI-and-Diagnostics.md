# CLI and Diagnostics

`nextconnect-core` 既可以作为界面宿主的后台控制器（Sidecar）运行，也可以直接在 Windows/Linux 终端下作为纯命令行 VPN 客户端与协议诊断工具运行。

---

## 运行动作（Actions）

同时最多只能指定以下一个动作参数；若均不指定，则默认进入**无头控制 API Sidecar 模式**：

| 参数 | 行为 |
| :--- | :--- |
| *（默认不传动作参数）* | 启动本地 HTTP/WS 控制服务器（`127.0.0.1:9090`），等待外部调用 `POST /api/v1/connect` |
| `-connect` | 执行认证、建立 Port 443 SVPN 隧道，同时启动 SOCKS5/HTTP/PAC 与控制 API 直至收到中断信号 |
| `-probe` | 仅探测目标网关认证能力与预认证参数，打印结果后退出 |
| `-auth-test` | 执行 Phase 1 认证、会话保活检查与注销清理后退出 |
| `-tunnel-probe` | 执行认证并测试 Port 443 SVPN L3VPN 三通道握手与虚拟 IP 分配，结束后注销退出 |
| `-version` | 打印内核版本、Go 工具链、操作系统架构及目标协议版本后退出 |

---

## 完整参数说明

### 网络与代理参数

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `-controller` | `127.0.0.1:9090` | 本地 REST + WebSocket 控制 API 监听地址 |
| `-socks` | `127.0.0.1:10808` | 本地 SOCKS5 代理监听地址 |
| `-http` | `127.0.0.1:10809` | 本地 HTTP 代理与 PAC（`/proxy.pac`）监听地址 |
| `-mode` | `rule` | 分流模式：`rule`（仅校园网内网与白名单域名走隧道）或 `global`（全局） |
| `-tun` | `false` | 在 `-connect` 成功后自动启用 Windows `Wintun` 虚拟网卡模式（需管理员权限及 `wintun.dll`） |

### 认证参数与环境变量

| 参数 / 环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `-gateway` | `""` | 目标 Sangfor SSL VPN 网关地址（由用户显式指定，执行连接/探测动作时必填） |
| `-user` | `""` | 登录账号；在交互式终端中省略时将提示输入 |
| `-cas-cookie` | `""` | 可选 CAS WebView 登录得到的 `TWFID` Cookie |
| `NEXTCONNECT_GATEWAY` | *未设置* | 当未显式传入 `-gateway` 时自动读取该环境变量 |
| `NEXTCONNECT_TEST_PASS` | *未设置* | 非交互场景可提前注入密码；未设置且运行在交互终端时 CLI 自动以无回显方式提示输入密码 |
| `NEXTCONNECT_CAS_COOKIE` | *未设置* | 当未显式传入 `-cas-cookie` 时自动读取该环境变量 |

### 日志参数

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `-log-level` | `info` | 终端与 `-log-file` 同步输出的最低日志级别：`debug`、`info`、`warn`、`error` |
| `-log-file` | `""` | 可选日志文件路径；若指定则按追加模式写入并自动创建父目录（权限 `0600`） |
| `-quiet` | `false` | 在常驻模式/控制器模式下屏蔽终端 `stdout` 日志输出（不影响 `-log-file` 与 `/api/v1/logs`） |

---

## 终端日志格式说明

开启终端或文件日志后，每条记录采用固定对齐格式并自动对 `TWFID` 做掩码脱敏：

```text
2026/11/20 14:23:55 [INFO ] [router    ] routing mode switched to rule
2026/11/20 14:23:55 [INFO ] [cli       ] nextconnect-core 0.2.0 starting (controller=http://127.0.0.1:9090, mode=rule, logLevel=info, target=EasyConnect 7.6.7.0)
2026/11/20 14:23:55 [INFO ] [api       ] controller HTTP/WS server listening on http://127.0.0.1:9090
```

设为 `-log-level debug` 时，还会输出每条连接关闭时的字节统计/耗时，以及每 20 秒控制心跳、L3 DNS 保活和每 40 秒会话保活的详细信息。

---

## 故障排查建议顺序

以下示例中的 `https://vpn.example.edu` 请替换为你的实际 SSL VPN 网关地址：

1. **先做无密码网关探测**：
   ```bash
   nextconnect-core -probe -gateway https://vpn.example.edu
   ```
2. **再验证账密与图形验证码链路**：
   ```bash
   nextconnect-core -auth-test -gateway https://vpn.example.edu -user <account>
   ```
   *若触发图形验证码，CLI 会将图片保存至可执行文件同目录并提示输入验证码。*
3. **测试 Port 443 L3 隧道握手**：
   ```bash
   nextconnect-core -tunnel-probe -gateway https://vpn.example.edu -user <account>
   ```
   *若主机握手异常，会自动运行候选 Query-IP / TX-RX 布局探测并打印十六进制诊断行。*
4. **正式启动并开启 `debug` 日志留档**：
   ```bash
   nextconnect-core -connect -gateway https://vpn.example.edu -user <account> -log-level debug -log-file nextconnect.log
   ```

## 退出码

- `0`：正常执行完成或收到 `SIGINT` / `SIGTERM` 后完成清理与退出
- `1`：运行时异常（连接失败、认证失败、日志文件无法打开或监听端口被占用等）
- `2`：命令行参数校验错误（如同时传多个互斥动作参数或非法 `-mode`/`-log-level`）
