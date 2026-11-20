package proxy

import (
	"context"
	"net"

	"github.com/nextconnect/core/pkg/model"
)

// PacketTransport 抽象 SVPN 三层原始 IP 数据包传输通道（如 SVPN 443 隧道或内存环回通道）。
type PacketTransport interface {
	ReadPacket() ([]byte, error)
	WritePacket(pkt []byte) error
	MTU() int
	Close() error
}

// RouteDecider 抽象分流路由器，用于决定目标主机走隧道还是直连。
type RouteDecider interface {
	Match(host string) (action model.RuleAction, rule string)
	Rules() []model.RuleEntry
	Mode() model.RoutingMode
}

// ConnObserver 抽象连接统计与日志观察器，避免 proxy 子包反向依赖 tunnel 包。
type ConnObserver interface {
	WrapAndTrack(conn net.Conn, source string, destination string, network string, rule string) net.Conn
	Log(level string, component string, message string)
}

// TargetDialer 抽象按网络和地址建立连接的拨号器（如 gVisor Netstack 隧道拨号）。
type TargetDialer interface {
	DialContext(ctx context.Context, network string, address string) (net.Conn, error)
}
