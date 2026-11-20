# NextConnect

一个轻量、纯净、跨平台的开源 SSL VPN 客户端内核，采用 **“独立 Go 无头内核 + 受控本地 API + 界面解耦”** 架构（借鉴 Clash Party / Mihomo Party 设计思想），旨在替代后台常驻服务繁杂的原厂客户端（目标参考协议版本：`EasyConnect 7.6.7.0`）。

> [!NOTE]
> 当前仓库优先开源并稳定交付 **Core 无头内核部分（`src/core/`）**。桌面端与移动端界面仍在方案打磨中，暂未包含在当前分支。

---

## 适用场景与设计定位

本内核不内置或绑定任何特定高校/机构的域名或地址，**所有网关地址均由用户通过 CLI 参数、环境变量或控制 API 自行指定**，适用于以下使用场景：

- **高校 / 科研机构校外安全接入**：校外访问采用 Sangfor SSL VPN（`EasyConnect 7.6.7.0` 协议族）的教务、图书馆、学术文献资源或内网服务器，需要轻量化客户端且不希望安装系统常驻后台服务（如各类守护进程）的场景。
- **企业 / 实验室按需分流访问**：仅需将网关下发的内网 CIDR 网段、内网域名走加密隧道，公网流量保持直连，避免全局 VPN 拖慢日常上网体验。
- **无头环境 / 命令行 / 容器及旁路代理环境**：Linux 终端、Windows 无头脚本或与本机既有代理软件并存的环境（内置物理网卡底层直连旁路，降低与本机 TUN/系统代理的冲突）。
- **支持多种网关认证流**：覆盖预认证探测、RSA 账密登录、图形验证码交互输入及统一身份认证（CAS）WebView 获取的 `TWFID` Cookie 导入。

---

## 核心特性

- **零后台流氓驻留**：不安装任何系统级常驻守护服务，进程退出即自动注销 `TWFID` 会话、停止本地代理并清理系统/虚拟路由。
- **零系统入侵**：不注入系统根证书、不强行全局劫持公网流量。
- **免驱动 + 虚拟网卡双模式分流**：
  - **免驱动本地代理（默认）**：基于 `gvisor.dev/gvisor/pkg/tcpip` 用户态协议栈提供本地 `SOCKS5`（默认 `127.0.0.1:10808`）、`HTTP` 代理与 `PAC`（默认 `127.0.0.1:10809/proxy.pac`）。
  - **Wintun 虚拟网卡（Windows）**：通过 `golang.org/x/sys/windows` 动态加载 `wintun.dll`（零 CGo），按网关推送的网段注入精准静态路由及防回环网关旁路路由。
- **物理底层网卡旁路**：Windows 支持通过 `IP_UNICAST_IF` 绑定物理网卡并绕过环境变量代理与 FakeIP DNS（`198.18.0.0/15`）。
- **高可靠性隧道保活与自愈**：控制通道 20 秒心跳、L3 数据通道 20 秒 DNS A 记录保活、`/por/update_session.csp` 会话保活，并在网关断开空闲 RX 流时自动重连恢复。
- **完整受控 REST + WebSocket API**：通过 `127.0.0.1:9090` 对外提供状态快照、认证连接、分流规则、实时流量波形流、活动连接管理与脱敏实时日志流。

---

## 整体架构

```text
+-----------------------------------------------------------------------+
|          External Controller / Desktop UI / CLI Consumer              |
|     (curl, browser PAC, Clash-style UI, scripts, custom clients)      |
+-----------------------------------+-----------------------------------+
                                    | Local HTTP REST + WebSocket
                                    | http://127.0.0.1:9090
                                    ▼
+-----------------------------------------------------------------------+
|                      NextConnect Core (src/core)                      |
|  - cmd/nextconnect-core : CLI 交互入口 / 无头守护 / 诊断工具            |
|  - internal/api         : REST API + WS 实时遥测 & 日志推送             |
|  - internal/tunnel      : 引擎调度、CIDR/域名分流、gVisor/Netstack、TUN  |
|  - internal/protocol    : Sangfor 认证、配置拉取与 Port 443 SVPN       |
|  - pkg/model            : 共享领域模型（严格脱敏）                       |
+-------------------+-------------------------------+-------------------+
                    |                               |
     Port 10808/10809 (Rule/Global)          Port 443 TLS / L3VPN
        SOCKS5 / HTTP / PAC               Control + TX + RX Streams
                    ▼                               ▼
          Local Applications               Target SSL VPN Gateway
```

---

## 仓库目录结构

```text
NextConnect/
├── LICENSE                         # MIT 开源许可证
├── README.md                       # 项目说明、适用场景与快速上手
├── .gitignore                      # Go/Node/产物与敏感日志忽略规则
├── build.ps1                       # 构建脚本（支持 -SkipUi 仅构建内核）
├── scripts/
│   ├── test_auth.ps1               # 网关探测与 Phase 1 认证调试脚本
│   └── test_tunnel.ps1             # Port 443 隧道握手与无头运行调试脚本
├── docs/
│   └── wiki/                       # 本地控制 API 与 CLI Wiki 文档
│       ├── Home.md
│       ├── Controller-REST-API.md
│       ├── WebSocket-Streams.md
│       └── CLI-and-Diagnostics.md
└── src/
    └── core/                       # Go 语言独立无头内核源码
        ├── go.mod
        ├── go.sum
        ├── README.md               # 内核架构、协议流程与开发测试说明
        ├── cmd/nextconnect-core/   # CLI 与无回显交互式口令读取
        ├── internal/
        │   ├── api/                # 本地 HTTP REST + WebSocket 服务器
        │   ├── protocol/           # Sangfor 认证与 SVPN 三通道协议实现
        │   └── tunnel/             # Tunnel Engine、RouteTable、proxy、tun
        └── pkg/model/              # 领域数据结构与 JSON 契约
```

---

## 快速开始

### 环境要求

- **Go SDK 1.24+**（纯 Go 实现，**无需 CGo / Visual Studio / CMake**）
- **Windows / Linux**（支持 `windows/amd64` 与交叉编译 `linux/amd64`）

### 编译二进制

```powershell
# 进入 Go 内核目录
cd src/core

# 运行单元测试与静态检查
go vet ./...
go test -count=1 ./...

# 编译 Windows 可执行文件
go build -trimpath -ldflags "-s -w -X main.version=0.2.0" -o ../../dist/nextconnect-core.exe ./cmd/nextconnect-core

# 可选：交叉编译 Linux 服务端/无头版
$env:GOOS='linux'; $env:GOARCH='amd64'
go build -trimpath -ldflags "-s -w -X main.version=0.2.0" -o ../../dist/nextconnect-core-linux-amd64 ./cmd/nextconnect-core
```

或者使用仓库根目录脚本仅构建内核：

```powershell
.\build.ps1 -SkipUi
```

### 常用运行方式

通过 `-gateway` 参数（或环境变量 `NEXTCONNECT_GATEWAY`）传入所在机构/学校的 SSL VPN 网关地址：

```powershell
# 1. 查看版本与全部 CLI 参数说明
.\dist\nextconnect-core.exe -version
.\dist\nextconnect-core.exe -h

# 2. 探测网关认证能力（无需账号密码）
.\dist\nextconnect-core.exe -probe -gateway https://vpn.example.edu

# 3. 交互式登录并开启代理 + 本地控制 API（终端安全输入密码，输出完整实时日志）
.\dist\nextconnect-core.exe -connect -gateway https://vpn.example.edu -user <account> -mode rule -log-level info

# 4. 开启 debug 详细日志并同时写入日志文件
.\dist\nextconnect-core.exe -connect -gateway https://vpn.example.edu -user <account> -log-level debug -log-file nextconnect.log

# 5. 仅作为无头控制器 Sidecar 启动（等待外部通过 REST API 下发 gatewayUrl 与凭据）
.\dist\nextconnect-core.exe -controller 127.0.0.1:9090
```

代理接入示例（启动 `-connect` 后）：

```bash
# 通过 SOCKS5 代理访问内网服务（启用远程域名解析）
curl -I --socks5-hostname 127.0.0.1:10808 https://portal.example.edu

# 获取动态生成的内网分流 PAC 脚本
curl -s http://127.0.0.1:10809/proxy.pac
```

---

## 文档与 API Wiki

更多内核设计、控制接口、WebSocket 推送协议及诊断参数请查阅：

- **内核开发文档**：[`src/core/README.md`](./src/core/README.md)
- **Wiki 首页与安全模型**：[`docs/wiki/Home.md`](./docs/wiki/Home.md)
- **REST 控制 API 规范**：[`docs/wiki/Controller-REST-API.md`](./docs/wiki/Controller-REST-API.md)
- **WebSocket 实时流规范**：[`docs/wiki/WebSocket-Streams.md`](./docs/wiki/WebSocket-Streams.md)
- **CLI 参数与诊断手册**：[`docs/wiki/CLI-and-Diagnostics.md`](./docs/wiki/CLI-and-Diagnostics.md)

> [!TIP]
> `docs/wiki/` 目录的 Markdown 文件可直接同步至 GitHub 仓库的 **Wiki** 标签页。

---

## 开源与免责声明

本项目基于公开网络协议分析与互操作性研究从零独立编写，**不包含任何原厂专有二进制文件、签名证书或反编译源码**。代码仅用于学术交流及改善合法授权用户的校园内网访问体验，请严格遵守所在高校网络管理规定与相关法律法规。

## License

[MIT License](./LICENSE)
