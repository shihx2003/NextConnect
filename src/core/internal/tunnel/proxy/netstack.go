package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	defaultNetstackNICID     tcpip.NICID = 1
	defaultChannelQueueDepth             = 512
	defaultStackVirtualIP                = "10.255.0.2"
)

// NetstackTunnel 使用 gVisor 纯 Go 用户态 TCP/IP 协议栈将三层 IP 包通道转换为免驱动 TCP/UDP 拨号器。
type NetstackTunnel struct {
	stack      *stack.Stack
	endpoint   *channel.Endpoint
	transport  PacketTransport
	virtualIP  netip.Addr
	dnsServers []netip.Addr
	resolver   *net.Resolver

	cancel context.CancelFunc
	wg     sync.WaitGroup

	closeOnce sync.Once
}

// NewNetstackTunnel 初始化并启动用户态 Netstack 协议栈，桥接给定的三层数据包通道。
func NewNetstackTunnel(
	parentCtx context.Context,
	transport PacketTransport,
	virtualIP netip.Addr,
	dnsServers []netip.Addr,
) (*NetstackTunnel, error) {
	if transport == nil {
		return nil, errors.New("packet transport is required for netstack tunnel")
	}

	if !virtualIP.IsValid() || !virtualIP.Is4() || virtualIP.IsUnspecified() {
		virtualIP = netip.MustParseAddr(defaultStackVirtualIP)
	}

	mtu := transport.MTU()
	if mtu < 576 {
		mtu = 1400
	}

	ipStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
		HandleLocal: true,
	})

	ep := channel.New(defaultChannelQueueDepth, uint32(mtu), "")
	if tcErr := ipStack.CreateNIC(defaultNetstackNICID, ep); tcErr != nil {
		ep.Close()
		ipStack.Close()
		return nil, fmt.Errorf("create gvisor nic failed: %s", tcErr)
	}

	sackOpt := tcpip.TCPSACKEnabled(true)
	_ = ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	ip4 := virtualIP.As4()
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(ip4),
			PrefixLen: 32,
		},
	}
	if tcErr := ipStack.AddProtocolAddress(defaultNetstackNICID, protoAddr, stack.AddressProperties{}); tcErr != nil {
		ep.Close()
		ipStack.Close()
		return nil, fmt.Errorf("assign virtual ip %s failed: %s", virtualIP, tcErr)
	}

	ipStack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         defaultNetstackNICID,
		},
	})

	ctx, cancel := context.WithCancel(parentCtx)
	nt := &NetstackTunnel{
		stack:      ipStack,
		endpoint:   ep,
		transport:  transport,
		virtualIP:  virtualIP,
		dnsServers: append([]netip.Addr(nil), dnsServers...),
		resolver:   net.DefaultResolver,
		cancel:     cancel,
	}

	nt.wg.Add(2)
	go nt.pumpOutbound(ctx)
	go nt.pumpInbound(ctx)

	return nt, nil
}

// VirtualIP 返回用户态协议栈当前绑定的虚拟网卡 IPv4 地址。
func (n *NetstackTunnel) VirtualIP() netip.Addr {
	return n.virtualIP
}

// DialContext 通过 gVisor 用户态协议栈向目标校园网地址（IP 或域名）建立 TCP/UDP 连接。
func (n *NetstackTunnel) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid target address %q: %w", address, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portStr)
	}

	targetAddr, err := n.resolveIPv4(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q failed: %w", host, err)
	}

	ip4 := targetAddr.As4()
	fullAddr := tcpip.FullAddress{
		NIC:  defaultNetstackNICID,
		Addr: tcpip.AddrFrom4(ip4),
		Port: uint16(port),
	}

	switch strings.ToLower(strings.TrimSpace(network)) {
	case "tcp", "tcp4":
		return gonet.DialContextTCP(ctx, n.stack, fullAddr, ipv4.ProtocolNumber)
	case "udp", "udp4":
		return gonet.DialUDP(n.stack, nil, &fullAddr, ipv4.ProtocolNumber)
	default:
		return nil, fmt.Errorf("unsupported netstack network %q", network)
	}
}

// KeepAlive 通过隧道内校园网私有 DNS 发起轻量 A 记录保活探测，防止长时间无数据包导致网关主动断开空闲 RX 流。
func (n *NetstackTunnel) KeepAlive(ctx context.Context) error {
	for _, dnsAddr := range n.dnsServers {
		if !dnsAddr.IsValid() || !dnsAddr.Is4() || !dnsAddr.IsPrivate() {
			continue
		}
		_, err := n.queryARecordViaTunnel(ctx, dnsAddr, "keepalive.internal")
		return err
	}
	return nil
}

// Close 停止收发协程并释放 gVisor 协议栈与底层通道资源。
func (n *NetstackTunnel) Close() error {
	var closeErr error
	n.closeOnce.Do(func() {
		n.cancel()
		closeErr = n.transport.Close()
		n.endpoint.Close()
		n.stack.Close()
		n.wg.Wait()
	})
	return closeErr
}

func (n *NetstackTunnel) pumpOutbound(ctx context.Context) {
	defer n.wg.Done()
	for {
		pkt := n.endpoint.ReadContext(ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		raw := view.AsSlice()
		err := n.transport.WritePacket(raw)
		view.Release()
		pkt.DecRef()
		if err != nil && ctx.Err() == nil {
			return
		}
	}
}

func (n *NetstackTunnel) pumpInbound(ctx context.Context) {
	defer n.wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		raw, err := n.transport.ReadPacket()
		if err != nil {
			return
		}
		if len(raw) < header.IPv4MinimumSize {
			continue
		}
		if header.IPVersion(raw) != header.IPv4Version {
			continue
		}

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(raw),
		})
		n.endpoint.InjectInbound(ipv4.ProtocolNumber, pkt)
		pkt.DecRef()
	}
}

func (n *NetstackTunnel) resolveIPv4(ctx context.Context, host string) (netip.Addr, error) {
	trimmed := strings.Trim(strings.TrimSpace(host), "[]")
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		if addr.Is4() {
			return addr, nil
		}
		if addr.Is4In6() {
			return addr.Unmap(), nil
		}
		return netip.Addr{}, fmt.Errorf("ipv6 target %s is not supported over ipv4 svpn tunnel", trimmed)
	}

	// 优先使用隧道内的私有校园网 DNS 解析校内域名，不可达时再回退宿主机解析器。
	for _, dnsAddr := range n.dnsServers {
		if !dnsAddr.IsValid() || !dnsAddr.Is4() || !dnsAddr.IsPrivate() {
			continue
		}
		if resolved, err := n.queryARecordViaTunnel(ctx, dnsAddr, trimmed); err == nil {
			return resolved, nil
		}
	}

	ips, err := n.resolver.LookupIP(ctx, "ip4", trimmed)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return netip.AddrFrom4([4]byte(ip4)), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no ipv4 address found for %q", trimmed)
}

func (n *NetstackTunnel) queryARecordViaTunnel(ctx context.Context, dnsServer netip.Addr, domain string) (netip.Addr, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	remote := tcpip.FullAddress{
		NIC:  defaultNetstackNICID,
		Addr: tcpip.AddrFrom4(dnsServer.As4()),
		Port: 53,
	}
	udpConn, err := gonet.DialUDP(n.stack, nil, &remote, ipv4.ProtocolNumber)
	if err != nil {
		return netip.Addr{}, err
	}
	defer udpConn.Close()

	if deadline, ok := queryCtx.Deadline(); ok {
		_ = udpConn.SetDeadline(deadline)
	}

	queryPkt := buildDNSAQuery(0x4E43, domain)
	if _, err := udpConn.Write(queryPkt); err != nil {
		return netip.Addr{}, err
	}

	resp := make([]byte, 512)
	readN, err := udpConn.Read(resp)
	if err != nil {
		return netip.Addr{}, err
	}
	return parseDNSAResponse(0x4E43, resp[:readN])
}

func buildDNSAQuery(txID uint16, domain string) []byte {
	clean := strings.TrimSuffix(strings.TrimSpace(domain), ".")
	buf := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(buf[0:2], txID)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // Standard query, Recursion Desired
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT = 1

	for _, label := range strings.Split(clean, ".") {
		if label == "" || len(label) > 63 {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00)       // Root label
	buf = append(buf, 0x00, 0x01) // QTYPE = A
	buf = append(buf, 0x00, 0x01) // QCLASS = IN
	return buf
}

func parseDNSAResponse(txID uint16, pkt []byte) (netip.Addr, error) {
	if len(pkt) < 12 {
		return netip.Addr{}, errors.New("dns response too short")
	}
	if binary.BigEndian.Uint16(pkt[0:2]) != txID {
		return netip.Addr{}, errors.New("dns transaction id mismatch")
	}
	qdCount := int(binary.BigEndian.Uint16(pkt[4:6]))
	anCount := int(binary.BigEndian.Uint16(pkt[6:8]))
	offset := 12

	skipName := func() bool {
		for offset < len(pkt) {
			length := int(pkt[offset])
			if length == 0 {
				offset++
				return true
			}
			if length&0xC0 == 0xC0 {
				if offset+1 >= len(pkt) {
					return false
				}
				offset += 2
				return true
			}
			offset += 1 + length
		}
		return false
	}

	for i := 0; i < qdCount; i++ {
		if !skipName() || offset+4 > len(pkt) {
			return netip.Addr{}, errors.New("malformed dns question")
		}
		offset += 4
	}

	for i := 0; i < anCount; i++ {
		if !skipName() || offset+10 > len(pkt) {
			return netip.Addr{}, errors.New("malformed dns answer")
		}
		rType := binary.BigEndian.Uint16(pkt[offset : offset+2])
		rdLen := int(binary.BigEndian.Uint16(pkt[offset+8 : offset+10]))
		offset += 10
		if offset+rdLen > len(pkt) {
			return netip.Addr{}, errors.New("truncated dns rdata")
		}
		if rType == 1 && rdLen == 4 {
			return netip.AddrFrom4([4]byte(pkt[offset : offset+4])), nil
		}
		offset += rdLen
	}
	return netip.Addr{}, errors.New("no dns A record in response")
}
