# NextConnect Core (`src/core`)

`nextconnect-core` 是 NextConnect 的纯 Go 无头 VPN 内核，负责 Sangfor SSL VPN（参考 `EasyConnect 7.6.7.0`）身份认证、Port 443 SVPN L3VPN 加密隧道收发、`gvisor/netstack` 免驱动本地代理、Windows `Wintun` 虚拟网卡分流，以及面向前端/外部控制器的本地 HTTP REST + WebSocket API。

---

## 模块依赖规范

内核严格保持自上而下的**单向依赖**，禁止反向引用或循环依赖：

```text
cmd/nextconnect-core
        │
        ▼
  internal/api          (HTTP REST + WebSocket 控制接口)
        │
        ▼
  internal/tunnel       (Engine 调度、RouteTable 分流、proxy Netstack/SOCKS5/HTTP/PAC、tun Wintun)
        │
        ▼
  internal/protocol     (SangforAuthenticator 认证、Underlay 网卡旁路、SvpnClient L3 隧道)
        │
        ▼
    pkg/model           (ConnectionState、SessionTicket、ActiveConnection、TrafficSnapshot、LogEntry)
```

---

## 工作原理概要

### 1. 认证与配置拉取 (`internal/protocol/auth.go`)
1. **预认证探测**：`GET /por/login_auth.csp?apiversion=1` 获取网关能力 XML、`PreTwfID`、`CSRF_RAND_CODE` 以及 RSA 公钥（`rsa_encrypt_key` / `rsa_encrypt_exp`）。
2. **身份认证**：
   - **账密登录**：使用 RSA PKCS#1 v1.5 加密凭据后 `POST /por/login_psw.csp`，支持图形验证码挑战（`/por/rand_code.csp`，提交小写 MD5）与二次认证识别。
   - **CAS Cookie 登录**：支持通过 WebView 获取到的有效 `TWFID` 直接拉取配置（CLI `-cas-cookie` 或 API `casCookie`）。
3. **虚拟网络与分流下发**：拉取 `/por/conf.csp` 与 `/por/rclist.csp`，提取 `TWFID`、`DNSServers`、`IntranetSubnets`（自动展开 `StartIP~EndIP` 区间为规范 CIDR 前缀）、`IntranetDomains`（`<Autorule domain="..."/>` 与 RC 域名列表）、`SSLEigenvalue`（`L3IP`）及加密套件（如 `RC4-SHA`）。
4. **底层网卡直连旁路 (`underlay.go`)**：自动过滤 TUN/虚拟适配器，在 Windows 下通过 `IP_UNICAST_IF` 将拨号套接字绑定到真实物理出口网卡，防止认证或隧道 TLS 握手回环进入本机代理。

### 2. Port 443 SVPN L3VPN 三通道隧道 (`internal/protocol/svpn.go`)
- 基于 `refraction-networking/utls` 建立 `L3IP` 隧道连接：
  1. **Control 控制流**：发送 64 字节 `Query-IP` 控制帧获取校园网虚拟 IP（`VirtualIP`）与隧道 MTU（默认 `1400`），并维持每 20 秒 `0x03` 隧道心跳。
  2. **TX 上行数据流 (`0x05`)** 与 **RX 下行数据流 (`0x06`)**：复用 `ServerHello.SessionId` 衍生的 48 字节隧道令牌建立全双工 IPv4 包转发。
- **自动断流恢复 (`engine.go` + `proxy/netstack.go`)**：
  - `runStatsAndKeepAliveLoop` 每 20 秒触发控制心跳 + 通过 `NetstackTunnel.KeepAlive` 经隧道发送轻量私有 DNS A 记录查询包，防止网关在 60 秒无业务 IP 包时主动断开空闲 `rxConn`。
  - 每 40 秒调用 `/por/update_session.csp` 刷新网关 HTTP 会话；遇瞬时 RX `EOF` 时由 `svpnPacketHub.tryRecoverRX` 自动重连数据流最多 3 次。

### 3. 双模式分流与本地代理 (`internal/tunnel`)
- **`RouteTable` (`route_table.go`)**：
  - 始终对回环地址及网关自身主机/IP 强制 `DIRECT` 防回环。
  - `rule` 模式（默认）：仅校内私有网段、网关下发 `IntranetSubnets` 与校园网域名列表走 `TUNNEL`，其余公网流量 `DIRECT`。
  - `global` 模式：除本地回环及网关自身地址外全部走 `TUNNEL`。
- **用户态协议栈 (`proxy/netstack.go`, `socks5.go`, `http_proxy.go`, `pac.go`)**：
  - 校园网 DNS 解析优先通过隧道内下发私有 DNS 查询，不可达时回退宿主机解析器。
  - 实时统计每秒上/下行速率、累计流量及活跃连接表。
- **Windows Wintun (`tun/tun_windows.go`)**：
  - 通过系统 `wintun.dll` 动态加载（零 CGo），需管理员权限；仅向系统路由表注入网关旁路路由和校园网分流路由，`Stop()` 时逆序还原清理。

---

## 本地测试与静态检查

```powershell
cd src/core

# 代码格式化检查
gofmt -l .

# 静态检查（Windows 与 Linux 跨平台条件编译文件）
go vet ./...
$env:GOOS='linux'; $env:GOARCH='amd64'; go vet ./...
Remove-Item Env:GOOS, Env:GOARCH

# 运行全量单元测试（无缓存）
go test -count=1 ./...
```

---

## 凭据脱敏与安全约定

- `model.SessionTicket` 中的 `TwfID` 与 `TunnelToken` 字段均标记为 `json:"-"`，控制 API 永不序列化返回明文令牌。
- `Engine.Log` 在写入内存缓冲、终端 stdout、`-log-file` 及推送 WebSocket 前统一经过 `redactSensitive` 替换敏感 `TWFID`。
- 测试及示例严禁硬编码真实学号、密码、Cookie 或私密服务器信息。
