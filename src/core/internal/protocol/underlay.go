package protocol

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var virtualInterfaceKeywords = []string{
	"mihomo",
	"meta",
	"clash",
	"sing-box",
	"singbox",
	"wintun",
	"nextconnect",
	"utun",
	"wireguard",
	"tailscale",
	"zerotier",
	"vethernet",
	"vmware",
	"virtualbox",
	"vbox",
	"hyper-v",
	"bluetooth",
	"蓝牙",
	"loopback",
	"pseudo",
}

var cgnatBenchPrefix = netip.MustParsePrefix("198.18.0.0/15")

// UnderlayDialer 用于探测物理底层网卡并通过接口绑定绕过本地 Clash/Mihomo/Wintun 等虚拟网卡。
type UnderlayDialer struct {
	mu          sync.RWMutex
	excludedIPs []netip.Addr
	timeout     time.Duration
}

// NewUnderlayDialer 创建支持物理网卡自动探测与旁路绑定的底层拨号器。
func NewUnderlayDialer(timeout time.Duration) *UnderlayDialer {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &UnderlayDialer{
		timeout: timeout,
	}
}

// ExcludeIP 将指定 IP（例如本机分配的隧道虚拟 IP）加入排除列表，防止回环选中虚拟网卡。
func (d *UnderlayDialer) ExcludeIP(ip netip.Addr) {
	if d == nil || !ip.IsValid() {
		return
	}
	d.mu.Lock()
	d.excludedIPs = append(d.excludedIPs, ip.Unmap())
	d.mu.Unlock()
}

// DialContext 优先通过物理网卡直连目标地址（绕过 TUN 劫持），失败时自动回退标准拨号器。
func (d *UnderlayDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	timeout := 10 * time.Second
	if d != nil && d.timeout > 0 {
		timeout = d.timeout
	}

	candidates := d.candidateInterfaces()
	if len(candidates) == 0 {
		return (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
	}

	resolvedAddr := d.resolveTargetAddress(ctx, address, candidates[0])

	var lastErr error
	for _, iface := range candidates {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		dialer := &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}
		if err := bindDialerToInterface(dialer, iface); err != nil {
			continue
		}
		conn, err := dialer.DialContext(ctx, network, resolvedAddr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	// 若物理网卡绑定拨号不可用，则回退默认系统路由拨号（限定短超时避免阻塞探针）。
	fbCtx, fbCancel := context.WithTimeout(ctx, timeout)
	defer fbCancel()
	conn, fallbackErr := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext(fbCtx, network, address)
	if fallbackErr == nil {
		return conn, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fallbackErr
}

func (d *UnderlayDialer) resolveTargetAddress(ctx context.Context, address string, iface net.Interface) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return address
	}
	if _, parseErr := netip.ParseAddr(strings.Trim(host, "[]")); parseErr == nil {
		return address
	}

	ips, lookupErr := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if lookupErr == nil {
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				addr := netip.AddrFrom4([4]byte(ip4))
				// 若系统 DNS 被虚拟网卡劫持返回 FakeIP (198.18.0.0/15)，改用物理网卡直连公共 DNS 解析。
				if !cgnatBenchPrefix.Contains(addr) {
					return net.JoinHostPort(addr.String(), port)
				}
			}
		}
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(rCtx context.Context, network, _ string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			_ = bindDialerToInterface(dialer, iface)
			return dialer.DialContext(rCtx, network, "114.114.114.114:53")
		},
	}
	if fallbackIPs, fErr := resolver.LookupIP(ctx, "ip4", host); fErr == nil {
		for _, ip := range fallbackIPs {
			if ip4 := ip.To4(); ip4 != nil {
				addr := netip.AddrFrom4([4]byte(ip4))
				if !cgnatBenchPrefix.Contains(addr) {
					return net.JoinHostPort(addr.String(), port)
				}
			}
		}
	}
	return address
}

func (d *UnderlayDialer) candidateInterfaces() []net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var excluded []netip.Addr
	if d != nil {
		d.mu.RLock()
		excluded = append(excluded, d.excludedIPs...)
		d.mu.RUnlock()
	}

	var out []net.Interface
	for _, iface := range ifaces {
		if isUsablePhysicalInterface(iface, excluded) {
			out = append(out, iface)
		}
	}
	return out
}

func isUsablePhysicalInterface(iface net.Interface, excluded []netip.Addr) bool {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	lowerName := strings.ToLower(iface.Name)
	for _, kw := range virtualInterfaceKeywords {
		if strings.Contains(lowerName, kw) {
			return false
		}
	}
	// 排除名为 tunX / tapX 等标准虚拟网卡命名。
	if strings.HasPrefix(lowerName, "tun") || strings.HasPrefix(lowerName, "tap") {
		return false
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	hasValidIPv4 := false
	for _, raw := range addrs {
		var ip net.IP
		switch v := raw.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		addr := netip.AddrFrom4([4]byte(ip4))
		if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || cgnatBenchPrefix.Contains(addr) {
			continue
		}
		for _, ex := range excluded {
			if addr == ex {
				return false
			}
		}
		hasValidIPv4 = true
	}
	return hasValidIPv4
}
