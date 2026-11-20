package model

import (
	"net/netip"
	"time"
)

// ConnectionState 表示 NextConnect 内核的当前运行状态。
type ConnectionState string

const (
	StateDisconnected       ConnectionState = "disconnected"
	StateAuthenticating     ConnectionState = "authenticating"
	StateEstablishingTunnel ConnectionState = "establishing_tunnel"
	StateConnected          ConnectionState = "connected"
	StateFaulted            ConnectionState = "faulted"
)

// RoutingMode 表示流量分流模式（默认规则分流，按需切换全局）。
type RoutingMode string

const (
	// RoutingModeRule 仅将校园网内网网段与校方学术域名路由进 SVPN 隧道，公网流量直连。
	RoutingModeRule RoutingMode = "rule"
	// RoutingModeGlobal 将除本地回环及 VPN 网关本身外的流量全部路由进 SVPN 隧道。
	RoutingModeGlobal RoutingMode = "global"
)

// RuleAction 表示单条分流规则的转发动作。
type RuleAction string

const (
	RuleActionTunnel RuleAction = "TUNNEL"
	RuleActionDirect RuleAction = "DIRECT"
)

// ConnectionProfile 描述单个校园网 VPN 连接配置。
type ConnectionProfile struct {
	ProfileName    string      `json:"profileName"`
	GatewayURL     string      `json:"gatewayUrl"`
	RoutingMode    RoutingMode `json:"routingMode"`
	SystemProxyOn  bool        `json:"systemProxyOn"`
	TunModeOn      bool        `json:"tunModeOn"`
	LocalSocksPort int         `json:"localSocksPort"`
	LocalHTTPPort  int         `json:"localHttpPort"`
	ControllerAddr string      `json:"controllerAddr"`
}

// SessionTicket 保存网关认证成功后的会话令牌及分配的虚拟网络参数。
// 注意：TwfID 与 TunnelToken 属于敏感凭据，禁止在日志中明文打印或序列化暴露。
type SessionTicket struct {
	TwfID           string         `json:"-"`
	TunnelToken     []byte         `json:"-"`
	GatewayHost     string         `json:"gatewayHost,omitempty"`
	GatewayPort     int            `json:"gatewayPort,omitempty"`
	VirtualIP       netip.Addr     `json:"virtualIp"`
	DNSServers      []netip.Addr   `json:"dnsServers"`
	IntranetSubnets []netip.Prefix `json:"intranetSubnets"`
	IntranetDomains []string       `json:"intranetDomains,omitempty"`
	L3Eigenvalue    string         `json:"l3Eigenvalue,omitempty"`
	TCPEigenvalue   string         `json:"tcpEigenvalue,omitempty"`
	L3CipherSuite   string         `json:"l3CipherSuite,omitempty"`
	TunnelMTU       int            `json:"tunnelMtu,omitempty"`
	ExpiresAtUTC    time.Time      `json:"expiresAtUtc"`
}

// RuleEntry 描述一条可读的校园网分流规则（用于 UI 与控制 API 展示）。
type RuleEntry struct {
	Type    string     `json:"type"`
	Pattern string     `json:"pattern"`
	Action  RuleAction `json:"action"`
	Source  string     `json:"source"`
}

// ActiveConnection 表示当前经过分流器转发的一条实时连接记录（用于前端连接列表展示）。
type ActiveConnection struct {
	ID              string    `json:"id"`
	Source          string    `json:"source"`
	Destination     string    `json:"destination"`
	Network         string    `json:"network"`
	Rule            string    `json:"rule"`
	UploadBytes     uint64    `json:"uploadBytes"`
	DownloadBytes   uint64    `json:"downloadBytes"`
	UploadRateBps   uint64    `json:"uploadRateBps"`
	DownloadRateBps uint64    `json:"downloadRateBps"`
	StartedAt       time.Time `json:"startedAt"`
}

// TrafficSnapshot 表示每秒推送给 UI 的实时流量速率与状态快照。
type TrafficSnapshot struct {
	State           ConnectionState `json:"state"`
	RoutingMode     RoutingMode     `json:"routingMode"`
	SystemProxyOn   bool            `json:"systemProxyOn"`
	TunModeOn       bool            `json:"tunModeOn"`
	VirtualIP       netip.Addr      `json:"virtualIp,omitempty"`
	UploadRateBps   uint64          `json:"uploadRateBps"`
	DownloadRateBps uint64          `json:"downloadRateBps"`
	TotalUpload     uint64          `json:"totalUpload"`
	TotalDownload   uint64          `json:"totalDownload"`
	ActiveCount     int             `json:"activeCount"`
	UptimeSeconds   int64           `json:"uptimeSeconds"`
}

// LogEntry 表示一条通过控制 API / WebSocket 推送的脱敏内核日志。
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	Message   string    `json:"message"`
}
