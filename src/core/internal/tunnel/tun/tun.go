package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
)

const (
	// DefaultAdapterName 定义 Windows Wintun 虚拟网卡的默认适配器名称。
	DefaultAdapterName = "NextConnect"
	// DefaultTunnelType 定义 Windows 注册虚拟网卡时使用的驱动分类名称。
	DefaultTunnelType = "NextConnect-Wintun"
	// DefaultTunMTU 定义 Wintun 虚拟网卡默认 MTU（与 EasyConnect L3IP 隧道一致）。
	DefaultTunMTU = 1400
)

var (
	// ErrTunUnsupportedPlatform 表示当前构建目标平台暂未实现系统级 TUN 驱动接入。
	ErrTunUnsupportedPlatform = errors.New("tun virtual adapter is only supported on windows in this build")
	// ErrWintunNotFound 表示未在运行目录或系统目录找到 wintun.dll。
	ErrWintunNotFound = errors.New("wintun.dll not found beside nextconnect-core.exe or in system directory")
	// ErrAdminRequired 表示创建 Wintun 虚拟网卡与写入系统分流路由需要管理员权限。
	ErrAdminRequired = errors.New("administrator privileges are required for virtual nic (wintun) mode")
)

// PacketBridge 定义 Wintun 与上层 L3 SVPN 通道之间传输原始 IP 包的抽象接口。
type PacketBridge interface {
	WritePacket(pkt []byte) error
	ReadPacket() ([]byte, error)
}

// Config 描述启动 Wintun 虚拟网卡所需的地址、路由与防环回参数。
type Config struct {
	AdapterName string
	VirtualIP   netip.Addr
	PrefixLen   int
	MTU         int
	Routes      []netip.Prefix
	BypassIPs   []netip.Addr
}

// Capabilities 描述当前宿主机环境是否具备开启虚拟网卡模式的条件。
type Capabilities struct {
	Platform        string `json:"platform"`
	WintunAvailable bool   `json:"wintunAvailable"`
	Elevated        bool   `json:"elevated"`
	AdapterName     string `json:"adapterName"`
	WintunPath      string `json:"wintunPath,omitempty"`
}

// Device 抽象跨平台 TUN 虚拟网卡句柄。
type Device interface {
	Name() string
	LUID() uint64
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) error
	Close() error
}

// FilterCampusRoutes 过滤并规范化需要注入虚拟网卡的校园网 CIDR 路由（禁止注入 0.0.0.0/0 全局劫持默认路由）。
func FilterCampusRoutes(prefixes []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, raw := range prefixes {
		p := raw.Masked()
		if !p.IsValid() || !p.Addr().Is4() || p.Bits() == 0 {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// Manager 负责管理 Wintun 虚拟网卡与 SVPN 通道之间的数据包转发与退出清理。
type Manager struct {
	device Device
	bridge PacketBridge
	onLog  func(level, component, msg string)

	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// StartBridgeWithDevice 使用给定 TUN 设备启动与 SVPN 隧道的数据面双向转发。
func StartBridgeWithDevice(
	parentCtx context.Context,
	device Device,
	bridge PacketBridge,
	onLog func(level, component, msg string),
) (*Manager, error) {
	if device == nil {
		return nil, errors.New("tun device is nil")
	}
	if bridge == nil {
		_ = device.Close()
		return nil, errors.New("packet bridge is nil")
	}

	ctx, cancel := context.WithCancel(parentCtx)
	m := &Manager{
		device: device,
		bridge: bridge,
		onLog:  onLog,
		cancel: cancel,
	}

	m.wg.Add(2)
	go m.pumpTunToTunnel(ctx)
	go m.pumpTunnelToTun(ctx)
	return m, nil
}

// Device 返回底层正在运行的 TUN 设备实例。
func (m *Manager) Device() Device {
	return m.device
}

// Close 停止转发协程并确定性关闭 TUN 网卡及自动回收注入的系统路由。
func (m *Manager) Close() error {
	var closeErr error
	m.closeOnce.Do(func() {
		m.cancel()
		closeErr = m.device.Close()
		if closer, ok := m.bridge.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		m.wg.Wait()
	})
	return closeErr
}

func (m *Manager) pumpTunToTunnel(ctx context.Context) {
	defer m.wg.Done()
	buf := make([]byte, 65535)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := m.device.ReadPacket(buf)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, io.EOF) {
				m.log("warn", "tun", fmt.Sprintf("read from tun stopped: %v", err))
			}
			return
		}
		if n < 20 {
			continue
		}
		// 仅转发 IPv4 数据包进入 EasyConnect L3IP 隧道。
		if buf[0]>>4 != 4 {
			continue
		}
		if err := m.bridge.WritePacket(buf[:n]); err != nil {
			if ctx.Err() == nil {
				m.log("warn", "tun", fmt.Sprintf("write packet to svpn failed: %v", err))
			}
			return
		}
	}
}

func (m *Manager) pumpTunnelToTun(ctx context.Context) {
	defer m.wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		pkt, err := m.bridge.ReadPacket()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, io.EOF) {
				m.log("warn", "tun", fmt.Sprintf("read packet from svpn failed: %v", err))
			}
			return
		}
		if len(pkt) < 20 || pkt[0]>>4 != 4 {
			continue
		}
		if err := m.device.WritePacket(pkt); err != nil {
			if ctx.Err() == nil {
				m.log("warn", "tun", fmt.Sprintf("write packet to tun failed: %v", err))
			}
			return
		}
	}
}

func (m *Manager) log(level, component, msg string) {
	if m.onLog != nil {
		m.onLog(level, component, msg)
	}
}
