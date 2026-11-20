package protocol

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nextconnect/core/pkg/model"
	utls "github.com/refraction-networking/utls"
)

const (
	// DefaultGatewayPort 是 SVPN 控制与数据隧道的默认 TLS 端口。
	DefaultGatewayPort = 443

	// TargetProtocolVersion 记录当前适配的目标官方客户端版本。
	TargetProtocolVersion = "7.6.7.0"

	// HeaderSizeBytes 表示通用 SVPN 辅助帧头的固定字节长度（5 字节）。
	HeaderSizeBytes = 5

	// DefaultTunnelMTU 表示 L3VPN 虚拟通道默认 MTU（与网关 conf.csp <Htp mtu="1400"/> 一致）。
	DefaultTunnelMTU = 1400

	// SvpnMagicNumber 是辅助帧头魔数（ASCII "SV"）。
	SvpnMagicNumber uint16 = 0x5356

	// TunnelTokenSize 是 Sangfor L3VPN 二进制控制握手中的 48 字节令牌长度（31B token + 0x00 + 16B TWFID）。
	TunnelTokenSize = 48

	// ControlMessageSize 是 Sangfor Query-IP / RX / TX / 心跳控制请求帧的固定字节长度（64 字节 = 48B 令牌 + 16B 控制尾）。
	ControlMessageSize = 64

	// ControlReplySize 是实测抓包中网关对 64 字节控制请求的响应长度（56B TLS 记录 = 36B 明文 + 20B SHA1 MAC）。
	ControlReplySize = 36

	// EigenvalueL3IP 与 EigenvalueTCPP 是网关用于分流端口 443 TLS 握手的特征字。
	EigenvalueL3IP = "L3IP"
	EigenvalueTCPP = "TCPP"
)

const (
	// SvpnFlagData 标识普通 L3 IP 数据载荷帧。
	SvpnFlagData uint8 = 0x00
	// SvpnFlagKeepAlive 标识隧道链路层保活帧。
	SvpnFlagKeepAlive uint8 = 0x01
	// SvpnFlagControl 标识隧道控制信令帧。
	SvpnFlagControl uint8 = 0x02
)

const (
	// ControlOpQueryIP 向网关查询并申请分配虚拟网卡 IP。
	ControlOpQueryIP uint8 = 0x00
	// ControlOpRecvSuccess 表示 RX 数据流握手确认响应（reply[0] == 0x01）。
	ControlOpRecvSuccess uint8 = 0x01
	// ControlOpSuccess 表示 Query-IP 与 TX 数据流握手确认响应（reply[0] == 0x02）。
	ControlOpSuccess uint8 = 0x02
	// ControlOpHeartbeat 表示长连接控制流命令心跳（op=0x03）。
	ControlOpHeartbeat uint8 = 0x03
	// ControlOpDataTX 表示客户端发送至网关的 TX 隧道流握手（op=0x05）。
	ControlOpDataTX uint8 = 0x05
	// ControlOpDataRX 表示客户端从网关接收数据的 RX 隧道流握手（op=0x06）。
	ControlOpDataRX uint8 = 0x06
	// ControlOpShutdown 表示网关拒绝或主动关闭隧道连接。
	ControlOpShutdown uint8 = 0x08
)

const (
	maxSvpnPayloadBytes  = 65535
	minIPv4HeaderBytes   = 20
	controlFrameAABBSize = 40
)

var (
	// ErrSvpnShutdown 表示网关在控制握手或数据流中返回关闭状态（0x08）。
	ErrSvpnShutdown = errors.New("svpn gateway signaled tunnel shutdown")
)

// SvpnHeader 描述通用 5 字节扩展数据帧头（Magic 2B + PayloadLength 2B + Flags 1B）。
// 注意：实测 Wireshark 抓包确认 Sangfor L3IP TX/RX 数据通道在 TLS 应用数据记录内直接传输原始 IPv4 报文，不附加该 5 字节头。
type SvpnHeader struct {
	MagicNumber   uint16
	PayloadLength uint16
	Flags         uint8
}

// EncodeHeader 将 SvpnHeader 序列化为 5 字节大端序帧头。
func EncodeHeader(hdr SvpnHeader) [HeaderSizeBytes]byte {
	var buf [HeaderSizeBytes]byte
	magic := hdr.MagicNumber
	if magic == 0 {
		magic = SvpnMagicNumber
	}
	binary.BigEndian.PutUint16(buf[0:2], magic)
	binary.BigEndian.PutUint16(buf[2:4], hdr.PayloadLength)
	buf[4] = hdr.Flags
	return buf
}

// DecodeHeader 解析 5 字节 SVPN 帧头并校验魔数。
func DecodeHeader(raw []byte) (SvpnHeader, error) {
	if len(raw) < HeaderSizeBytes {
		return SvpnHeader{}, fmt.Errorf("svpn header too short: got %d bytes, want %d", len(raw), HeaderSizeBytes)
	}
	hdr := SvpnHeader{
		MagicNumber:   binary.BigEndian.Uint16(raw[0:2]),
		PayloadLength: binary.BigEndian.Uint16(raw[2:4]),
		Flags:         raw[4],
	}
	if hdr.MagicNumber != SvpnMagicNumber {
		return SvpnHeader{}, fmt.Errorf("invalid svpn header magic: 0x%04x", hdr.MagicNumber)
	}
	return hdr, nil
}

// WriteSvpnFrame 将带 5 字节 SvpnHeader 的数据帧写入流。
func WriteSvpnFrame(w io.Writer, flags uint8, payload []byte) error {
	if len(payload) > maxSvpnPayloadBytes {
		return fmt.Errorf("svpn payload exceeds max length (%d > %d)", len(payload), maxSvpnPayloadBytes)
	}
	hdr := EncodeHeader(SvpnHeader{
		MagicNumber:   SvpnMagicNumber,
		PayloadLength: uint16(len(payload)),
		Flags:         flags,
	})
	frame := make([]byte, HeaderSizeBytes+len(payload))
	copy(frame[:HeaderSizeBytes], hdr[:])
	copy(frame[HeaderSizeBytes:], payload)

	for written := 0; written < len(frame); {
		n, err := w.Write(frame[written:])
		if err != nil {
			return fmt.Errorf("write svpn frame: %w", err)
		}
		written += n
	}
	return nil
}

// ReadSvpnFrame 从流中读取一帧完整的 5 字节头 SVPN 报文并返回帧头与载荷副本。
func ReadSvpnFrame(r io.Reader) (SvpnHeader, []byte, error) {
	var hdrBuf [HeaderSizeBytes]byte
	if _, err := io.ReadFull(r, hdrBuf[:]); err != nil {
		return SvpnHeader{}, nil, fmt.Errorf("read svpn header: %w", err)
	}
	hdr, err := DecodeHeader(hdrBuf[:])
	if err != nil {
		return SvpnHeader{}, nil, err
	}
	payload := make([]byte, hdr.PayloadLength)
	if hdr.PayloadLength > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return SvpnHeader{}, nil, fmt.Errorf("read svpn payload (%d bytes): %w", hdr.PayloadLength, err)
		}
	}
	return hdr, payload, nil
}

// ControlFrame 表示 Sangfor L3VPN 64 字节二进制控制握手报文：
//   - [0..3]   : 操作码/状态字（小端 uint32，[0] 为 0x00=QueryIP, 0x01=RecvAck, 0x02=SendAck, 0x03=Heartbeat, 0x05=TX, 0x06=RX, 0x08=Shutdown）
//   - [4..51]  : 48 字节隧道会话令牌（sslctx / ServerHello.SessionID[:31] + 0x00 + 16B TWFID）
//   - [52..59] : 8 字节保留字段（全 0）
//   - [60..63] : 4 字节 IPv4 地址（反序/小端字节序：QueryIP 未指定 IP 时填 0xffffffff；TX/RX 填 ipReverse）
type ControlFrame struct {
	Op        uint8
	Flags     [3]byte
	Token     [TunnelTokenSize]byte
	VirtualIP netip.Addr
	Reserved  [8]byte
}

// BuildTunnelToken 根据认证阶段取得的 TWFID 构造 48 字节后备令牌（优先使用 conf.csp <Other sslctx> 的完整 48 字节）。
func BuildTunnelToken(twfID string) ([TunnelTokenSize]byte, error) {
	var token [TunnelTokenSize]byte
	trimmed := strings.TrimSpace(twfID)
	if trimmed == "" {
		return token, errors.New("cannot build svpn tunnel token from empty TWFID")
	}
	raw := []byte(trimmed)
	if len(raw) >= TunnelTokenSize {
		copy(token[:], raw[:TunnelTokenSize])
	} else {
		copy(token[:], raw)
	}
	return token, nil
}

// Encode 将 ControlFrame 序列化为 64 字节 Sangfor L3IP 线格式报文（[52..59]=Reserved/0，[60..63]=ipReverse 或 0xffffffff）。
func (cf ControlFrame) Encode() [ControlMessageSize]byte {
	var out [ControlMessageSize]byte
	out[0] = cf.Op
	copy(out[1:4], cf.Flags[:])
	copy(out[4:52], cf.Token[:])
	copy(out[52:60], cf.Reserved[:])
	if cf.VirtualIP.Is4() {
		ip4 := cf.VirtualIP.As4()
		out[60] = ip4[3]
		out[61] = ip4[2]
		out[62] = ip4[1]
		out[63] = ip4[0]
	} else if cf.Op == ControlOpQueryIP {
		out[60], out[61], out[62], out[63] = 0xff, 0xff, 0xff, 0xff
	}
	return out
}

func (cf ControlFrame) encodeNetworkOrderIPAtTail() [ControlMessageSize]byte {
	out := cf.Encode()
	if cf.VirtualIP.Is4() {
		ip4 := cf.VirtualIP.As4()
		out[60] = ip4[0]
		out[61] = ip4[1]
		out[62] = ip4[2]
		out[63] = ip4[3]
	}
	return out
}

// ParseControlFrame 解析 36 字节或 64 字节 Sangfor L3VPN 控制握手响应。
func ParseControlFrame(raw []byte) (ControlFrame, error) {
	if len(raw) >= ControlReplySize && len(raw) < ControlMessageSize {
		// 36 字节网关响应：前 4 字节为小端状态字（[0]），[4..7] 为分配的 4 字节网络序 IPv4（如 0a64500e = 10.100.80.14）。
		var cf ControlFrame
		cf.Op = raw[0]
		if cf.Op == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] != 0 {
			cf.Op = raw[3]
		}
		copy(cf.Flags[:], raw[1:4])
		if ip := netip.AddrFrom4([4]byte{raw[4], raw[5], raw[6], raw[7]}); ip.IsPrivate() {
			cf.VirtualIP = ip
		} else if ip := extractFirstPrivateIPv4(raw[4:]); ip.IsValid() {
			cf.VirtualIP = ip
		}
		return cf, nil
	}
	if len(raw) < ControlMessageSize {
		return ControlFrame{}, fmt.Errorf("svpn control frame too short: got %d bytes (hex=%s)", len(raw), hex.EncodeToString(raw))
	}
	var cf ControlFrame
	cf.Op = raw[0]
	copy(cf.Flags[:], raw[1:4])
	copy(cf.Token[:], raw[4:52])
	copy(cf.Reserved[:], raw[52:60])

	tail := [4]byte{raw[60], raw[61], raw[62], raw[63]}
	if tail != ([4]byte{}) && tail != ([4]byte{0xff, 0xff, 0xff, 0xff}) {
		cf.VirtualIP = netip.AddrFrom4([4]byte{raw[63], raw[62], raw[61], raw[60]})
	} else if ipBytes := ([4]byte{raw[52], raw[53], raw[54], raw[55]}); ipBytes != ([4]byte{}) {
		cf.VirtualIP = netip.AddrFrom4(ipBytes)
	}
	return cf, nil
}

func extractFirstPrivateIPv4(buf []byte) netip.Addr {
	// 优先扫描常见对齐偏移（4B 步长）查找反序或正序私网虚拟 IP（10.x / 172.16-31.x / 192.168.x）。
	for off := 0; off+4 <= len(buf); off += 4 {
		rev := netip.AddrFrom4([4]byte{buf[off+3], buf[off+2], buf[off+1], buf[off]})
		if rev.IsPrivate() {
			return rev
		}
		fwd := netip.AddrFrom4([4]byte{buf[off], buf[off+1], buf[off+2], buf[off+3]})
		if fwd.IsPrivate() {
			return fwd
		}
	}
	return netip.Addr{}
}

// BuildL3IPSessionID 构造注入到 TLS ClientHello SessionId 中的 32 字节纯特征标识（"L3IP\x00..."）。
func BuildL3IPSessionID(eigenvalue string) []byte {
	ev := strings.TrimSpace(eigenvalue)
	if ev == "" {
		ev = EigenvalueL3IP
	}
	sessionID := make([]byte, 32)
	copy(sessionID, []byte(ev))
	return sessionID
}

// TunnelDialer 定义建立端口 443 SVPN TLS 通道的拨号抽象，便于单元测试替换或适配不同校方网关。
type TunnelDialer interface {
	DialTunnel(ctx context.Context, host string, port int, eigenvalue string, cipherHint string) (net.Conn, error)
}

// UtlsL3Dialer 使用 refraction-networking/utls 精确复刻实机抓包的 L3IP TLS 1.1 ClientHello，
// 并通过 UnderlayDialer 绑定物理网卡绕过本地虚拟网卡劫持。
type UtlsL3Dialer struct {
	InsecureSkipVerify bool
	DialTimeout        time.Duration
	Underlay           *UnderlayDialer
}

// DialTunnel 连接到目标网关端口 443 并发送与官方 EasyConnect 完全一致的 L3IP TLS ClientHello。
func (d *UtlsL3Dialer) DialTunnel(
	ctx context.Context,
	host string,
	port int,
	eigenvalue string,
	cipherHint string,
) (net.Conn, error) {
	if strings.TrimSpace(host) == "" {
		return nil, errors.New("gateway host is required for svpn dial")
	}
	if port <= 0 || port > 65535 {
		port = DefaultGatewayPort
	}

	timeout := d.DialTimeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}

	underlay := d.Underlay
	if underlay == nil {
		underlay = NewUnderlayDialer(timeout)
	}
	rawConn, err := underlay.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("svpn tcp dial failed: %w", err)
	}

	uConn, err := wrapWithL3TLS(ctx, rawConn, host, eigenvalue, cipherHint, d.InsecureSkipVerify)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return uConn, nil
}

// ServerSessionIDProvider 允许底层 TLS 连接暴露握手返回的 ServerHello.SessionId。
type ServerSessionIDProvider interface {
	ServerSessionID() []byte
}

type utlsSessionConn struct {
	*utls.UConn
}

func (c *utlsSessionConn) ServerSessionID() []byte {
	if c == nil || c.UConn == nil || c.HandshakeState.ServerHello == nil {
		return nil
	}
	sid := c.HandshakeState.ServerHello.SessionId
	out := make([]byte, len(sid))
	copy(out, sid)
	return out
}

func wrapWithL3TLS(
	ctx context.Context,
	rawConn net.Conn,
	serverName string,
	eigenvalue string,
	cipherHint string,
	insecureSkipVerify bool,
) (net.Conn, error) {
	cfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         utls.VersionTLS10,
		MaxVersion:         utls.VersionTLS12,
	}

	uConn := utls.UClient(rawConn, cfg, utls.HelloCustom)
	ciphers := selectL3CipherSuites(cipherHint)

	// 完全对齐 Wireshark 抓包 pkt#570 / pkt#700：TLS 1.1 (0x0302)，仅携带 RC4-SHA + SCSV 与 Heartbeat(0x000f=1) 扩展。
	spec := &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS11,
		TLSVersMax:         utls.VersionTLS11,
		CipherSuites:       ciphers,
		CompressionMethods: []uint8{0x00},
		Extensions: []utls.TLSExtension{
			&utls.GenericExtension{Id: 0x000f, Data: []byte{0x01}},
		},
	}
	if err := uConn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("apply svpn tls preset failed: %w", err)
	}
	uConn.HandshakeState.Hello.SessionId = BuildL3IPSessionID(eigenvalue)

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("svpn l3ip tls handshake failed: %w", err)
	}
	return &utlsSessionConn{UConn: uConn}, nil
}

func selectL3CipherSuites(cipherHint string) []uint16 {
	upper := strings.ToUpper(strings.TrimSpace(cipherHint))
	switch {
	case strings.Contains(upper, "AES") && !strings.Contains(upper, "RC4"):
		return []uint16{
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
		}
	default:
		return []uint16{
			utls.TLS_RSA_WITH_RC4_128_SHA,
			utls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
		}
	}
}

// SvpnClient 管理端口 443 L3VPN 三通道生命周期：Query-IP 控制通道、RX 接收通道与 TX 发送通道。
type SvpnClient struct {
	dialer TunnelDialer

	mu          sync.Mutex
	ctrlConn    net.Conn
	rxConn      net.Conn
	txConn      net.Conn
	ticket      model.SessionTicket
	token       [TunnelTokenSize]byte
	virtualIP   netip.Addr
	mtu         int
	closed      bool
	ctrlMu      sync.Mutex
	reconnectMu sync.Mutex

	writeMu sync.Mutex
	readMu  sync.Mutex
}

// NewSvpnClient 创建 SVPN 隧道客户端；若 dialer 为 nil 则使用默认 UtlsL3Dialer。
func NewSvpnClient(dialer TunnelDialer) *SvpnClient {
	if dialer == nil {
		dialer = &UtlsL3Dialer{
			InsecureSkipVerify: true,
			DialTimeout:        12 * time.Second,
		}
	}
	return &SvpnClient{
		dialer: dialer,
		mtu:    DefaultTunnelMTU,
	}
}

// Connect 依次建立 Query-IP 控制连接、RX 接收连接与 TX 发送连接，完成虚拟 IP 协商。
func (c *SvpnClient) Connect(ctx context.Context, ticket model.SessionTicket) (model.SessionTicket, error) {
	var token [TunnelTokenSize]byte
	if len(ticket.TunnelToken) == TunnelTokenSize {
		copy(token[:], ticket.TunnelToken)
	} else {
		var err error
		token, err = BuildTunnelToken(ticket.TwfID)
		if err != nil {
			return model.SessionTicket{}, err
		}
	}

	host := strings.TrimSpace(ticket.GatewayHost)
	if host == "" {
		return model.SessionTicket{}, errors.New("session ticket missing gateway host")
	}
	port := ticket.GatewayPort
	if port <= 0 {
		port = DefaultGatewayPort
	}
	eigenvalue := strings.TrimSpace(ticket.L3Eigenvalue)
	if eigenvalue == "" {
		eigenvalue = EigenvalueL3IP
	}

	// 1. 建立控制通道并发送 64 字节 Query-IP 握手请求。
	ctrlConn, err := c.dialer.DialTunnel(ctx, host, port, eigenvalue, ticket.L3CipherSuite)
	if err != nil {
		return model.SessionTicket{}, err
	}

	queryReq := ControlFrame{
		Token:     token,
		Op:        ControlOpQueryIP,
		VirtualIP: ticket.VirtualIP,
	}.Encode()

	if err := writeControlWithDeadline(ctrlConn, queryReq[:]); err != nil {
		_ = ctrlConn.Close()
		return model.SessionTicket{}, fmt.Errorf("send Query-IP frame failed: %w", err)
	}

	rawResp, err := readControlWithDeadline(ctrlConn)
	if err != nil {
		_ = ctrlConn.Close()
		return model.SessionTicket{}, fmt.Errorf("read Query-IP response failed: %w", err)
	}

	respFrame, err := ParseControlFrame(rawResp)
	if err != nil {
		_ = ctrlConn.Close()
		return model.SessionTicket{}, err
	}
	if respFrame.Op == ControlOpShutdown {
		_ = ctrlConn.Close()
		return model.SessionTicket{}, fmt.Errorf("%w (reply=%s)", ErrSvpnShutdown, hex.EncodeToString(rawResp))
	}
	if respFrame.Op != ControlOpSuccess && respFrame.Op != ControlOpQueryIP {
		_ = ctrlConn.Close()
		return model.SessionTicket{}, fmt.Errorf("unexpected Query-IP response op: 0x%02x (reply=%s)",
			respFrame.Op, hex.EncodeToString(rawResp))
	}

	updated := ticket
	if respFrame.VirtualIP.IsValid() && !respFrame.VirtualIP.IsUnspecified() {
		updated.VirtualIP = respFrame.VirtualIP
	}
	if updated.TunnelMTU <= 0 {
		updated.TunnelMTU = DefaultTunnelMTU
	}

	// 2. 在保持控制通道打开的条件下，先建立 TX（0x05 -> ack 0x02）再建立 RX（0x06 -> ack 0x01）L3IP 数据流。
	txConn, err := c.openDataStream(ctx, host, port, eigenvalue, ticket.L3CipherSuite, ControlOpDataTX, token, updated.VirtualIP)
	if err != nil {
		_ = ctrlConn.Close()
		return model.SessionTicket{}, fmt.Errorf("open TX stream failed: %w", err)
	}

	rxConn, err := c.openDataStream(ctx, host, port, eigenvalue, ticket.L3CipherSuite, ControlOpDataRX, token, updated.VirtualIP)
	if err != nil {
		_ = txConn.Close()
		_ = ctrlConn.Close()
		return model.SessionTicket{}, fmt.Errorf("open RX stream failed: %w", err)
	}

	c.mu.Lock()
	c.ctrlConn = ctrlConn
	c.rxConn = rxConn
	c.txConn = txConn
	c.ticket = updated
	c.token = token
	c.virtualIP = updated.VirtualIP
	c.mtu = updated.TunnelMTU
	c.closed = false
	c.mu.Unlock()

	return updated, nil
}

// ReconnectDataStreams 在 RX/TX 流遭遇意外 EOF 时重建 L3VPN 数据通道（必要时连带重建控制通道）。
func (c *SvpnClient) ReconnectDataStreams(ctx context.Context) error {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("svpn client is closed")
	}
	ticket := c.ticket
	token := c.token
	vip := c.virtualIP
	oldTX := c.txConn
	oldRX := c.rxConn
	c.mu.Unlock()

	host := strings.TrimSpace(ticket.GatewayHost)
	if host == "" {
		return errors.New("cannot reconnect svpn streams without gateway host")
	}
	port := ticket.GatewayPort
	if port <= 0 {
		port = DefaultGatewayPort
	}
	eigenvalue := strings.TrimSpace(ticket.L3Eigenvalue)
	if eigenvalue == "" {
		eigenvalue = EigenvalueL3IP
	}

	// 先尝试复用现有 Query-IP 控制流重建 TX 与 RX 数据流。
	if oldTX != nil {
		_ = oldTX.Close()
	}
	if oldRX != nil {
		_ = oldRX.Close()
	}

	txConn, txErr := c.openDataStream(ctx, host, port, eigenvalue, ticket.L3CipherSuite, ControlOpDataTX, token, vip)
	if txErr == nil {
		rxConn, rxErr := c.openDataStream(ctx, host, port, eigenvalue, ticket.L3CipherSuite, ControlOpDataRX, token, vip)
		if rxErr == nil {
			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				_ = txConn.Close()
				_ = rxConn.Close()
				return errors.New("svpn client is closed")
			}
			c.txConn = txConn
			c.rxConn = rxConn
			c.mu.Unlock()
			return nil
		}
		_ = txConn.Close()
		if errors.Is(rxErr, ErrSvpnShutdown) {
			return rxErr
		}
	} else if errors.Is(txErr, ErrSvpnShutdown) {
		return txErr
	}

	// 若控制流也已失效，则重建完整的三通道（Query-IP + TX + RX）。
	c.mu.Lock()
	oldCtrl := c.ctrlConn
	c.ctrlConn = nil
	c.txConn = nil
	c.rxConn = nil
	c.mu.Unlock()
	if oldCtrl != nil {
		_ = oldCtrl.Close()
	}

	_, err := c.Connect(ctx, ticket)
	return err
}

func (c *SvpnClient) openDataStream(
	ctx context.Context,
	host string,
	port int,
	eigenvalue string,
	cipherSuite string,
	op uint8,
	token [TunnelTokenSize]byte,
	vip netip.Addr,
) (net.Conn, error) {
	frame := ControlFrame{
		Op:        op,
		Token:     token,
		VirtualIP: vip,
	}
	payloads := [][ControlMessageSize]byte{
		frame.Encode(),
		frame.encodeNetworkOrderIPAtTail(),
	}

	var lastErr error
	for idx, rawReq := range payloads {
		if idx == 1 && rawReq == payloads[0] {
			continue
		}
		conn, err := c.dialer.DialTunnel(ctx, host, port, eigenvalue, cipherSuite)
		if err != nil {
			return nil, err
		}
		if err := writeControlWithDeadline(conn, rawReq[:]); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("send stream handshake (op=0x%02x) failed: %w", op, err)
		}
		rawResp, err := readControlWithDeadline(conn)
		if err != nil {
			_ = conn.Close()
			lastErr = fmt.Errorf("read stream handshake reply (op=0x%02x) failed: %w", op, err)
			continue
		}
		parsed, pErr := ParseControlFrame(rawResp)
		if pErr != nil {
			_ = conn.Close()
			lastErr = pErr
			continue
		}
		if parsed.Op == ControlOpShutdown {
			_ = conn.Close()
			lastErr = fmt.Errorf("%w (op=0x%02x, reply=%s)", ErrSvpnShutdown, op, hex.EncodeToString(rawResp))
			continue
		}
		if op == ControlOpDataTX && parsed.Op != ControlOpSuccess {
			_ = conn.Close()
			lastErr = fmt.Errorf("unexpected TX stream handshake reply op=0x%02x (reply=%s)", parsed.Op, hex.EncodeToString(rawResp))
			continue
		}
		if op == ControlOpDataRX && parsed.Op != ControlOpRecvSuccess && parsed.Op != ControlOpSuccess {
			_ = conn.Close()
			lastErr = fmt.Errorf("unexpected RX stream handshake reply op=0x%02x (reply=%s)", parsed.Op, hex.EncodeToString(rawResp))
			continue
		}
		return conn, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("failed to open svpn data stream (op=0x%02x)", op)
}

// VirtualIP 返回当前隧道协商得到的虚拟网卡 IPv4 地址。
func (c *SvpnClient) VirtualIP() netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.virtualIP
}

// MTU 返回协商后的隧道 MTU。
func (c *SvpnClient) MTU() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mtu <= 0 {
		return DefaultTunnelMTU
	}
	return c.mtu
}

// WritePacket 将一个原始 L3 IPv4 数据包直接写入 TX 隧道流（对齐抓包验证的裸 IP 包格式）。
func (c *SvpnClient) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	conn := c.activeTXConn()
	if conn == nil {
		return errors.New("svpn tx tunnel is not connected")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	for written := 0; written < len(pkt); {
		n, err := conn.Write(pkt[written:])
		if err != nil {
			return fmt.Errorf("write svpn tx packet: %w", err)
		}
		written += n
	}
	return nil
}

// ReadPacket 从 RX 隧道流按 IPv4 首部总长度定界读取一条完整 L3 数据包。
func (c *SvpnClient) ReadPacket() ([]byte, error) {
	conn := c.activeRXConn()
	if conn == nil {
		return nil, errors.New("svpn rx tunnel is not connected")
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		var hdr [minIPv4HeaderBytes]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, fmt.Errorf("read svpn rx ipv4 header: %w", err)
		}

		ver := hdr[0] >> 4
		// 跳过网关偶发注入的 40 字节 0xAABB 控制帧（大端 AA BB 或小端 BB AA）。
		if (hdr[0] == 0xAA && hdr[1] == 0xBB) || (hdr[0] == 0xBB && hdr[1] == 0xAA) {
			var tail [controlFrameAABBSize - minIPv4HeaderBytes]byte
			if _, err := io.ReadFull(conn, tail[:]); err != nil {
				return nil, fmt.Errorf("read svpn 0xAABB control frame tail: %w", err)
			}
			continue
		}
		if ver == 6 {
			// 跳过隧道偶发注入的 IPv6 广播/邻居包，避免中断 RX 循环。
			v6PayloadLen := int(binary.BigEndian.Uint16(hdr[4:6]))
			skipLen := 40 + v6PayloadLen - minIPv4HeaderBytes
			if skipLen > 0 {
				if _, err := io.CopyN(io.Discard, conn, int64(skipLen)); err != nil {
					return nil, fmt.Errorf("discard svpn rx ipv6 packet: %w", err)
				}
			}
			continue
		}
		if ver != 4 {
			return nil, fmt.Errorf("unexpected ip version on rx stream: %d (hdr=%s)", ver, hex.EncodeToString(hdr[:]))
		}
		totalLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		if totalLen < minIPv4HeaderBytes || totalLen > maxSvpnPayloadBytes {
			return nil, fmt.Errorf("invalid ipv4 packet length on rx stream: %d", totalLen)
		}

		pkt := make([]byte, totalLen)
		copy(pkt[:minIPv4HeaderBytes], hdr[:])
		if totalLen > minIPv4HeaderBytes {
			if _, err := io.ReadFull(conn, pkt[minIPv4HeaderBytes:]); err != nil {
				return nil, fmt.Errorf("read svpn rx ipv4 payload (%d bytes): %w", totalLen-minIPv4HeaderBytes, err)
			}
		}
		return pkt, nil
	}
}

// SendHeartbeat 在控制通道上发送 64 字节保活帧以维持网关隧道会话（默认每 20 秒一次）。
func (c *SvpnClient) SendHeartbeat() error {
	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()

	c.mu.Lock()
	if c.closed || c.ctrlConn == nil {
		c.mu.Unlock()
		return errors.New("svpn control tunnel is not connected")
	}
	ctrl := c.ctrlConn
	token := c.token
	vip := c.virtualIP
	c.mu.Unlock()

	hb := ControlFrame{
		Token:     token,
		Op:        ControlOpHeartbeat,
		VirtualIP: vip,
	}.Encode()
	if err := writeControlWithDeadline(ctrl, hb[:]); err != nil {
		return err
	}
	_, err := readControlWithDeadline(ctrl)
	return err
}

// Close 关闭 SVPN 控制、RX 与 TX 全部底层隧道连接。
func (c *SvpnClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	ctrl, rx, tx := c.ctrlConn, c.rxConn, c.txConn
	c.ctrlConn, c.rxConn, c.txConn = nil, nil, nil
	c.mu.Unlock()

	var firstErr error
	for _, conn := range []net.Conn{tx, rx, ctrl} {
		if conn != nil {
			if err := conn.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (c *SvpnClient) activeRXConn() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	return c.rxConn
}

func (c *SvpnClient) activeTXConn() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	return c.txConn
}

// QueryIPLayoutProbeResult 记录单个 Query-IP 报文布局候选的探测结果。
type QueryIPLayoutProbeResult struct {
	Name      string
	ReplyHex  string
	Op        uint8
	VirtualIP netip.Addr
	Error     string
}

// ProbeQueryIPLayouts 用于校外诊断时逐一探测 64 字节 Query-IP 控制帧的不同令牌来源与偏移布局。
func (c *SvpnClient) ProbeQueryIPLayouts(ctx context.Context, ticket model.SessionTicket) []QueryIPLayoutProbeResult {
	host := strings.TrimSpace(ticket.GatewayHost)
	port := ticket.GatewayPort
	if port <= 0 {
		port = DefaultGatewayPort
	}
	eigenvalue := strings.TrimSpace(ticket.L3Eigenvalue)
	if eigenvalue == "" {
		eigenvalue = EigenvalueL3IP
	}

	type layoutCandidate struct {
		name string
		make func(serverSID []byte) [ControlMessageSize]byte
	}

	buildTokenFromSID := func(serverSID []byte) [TunnelTokenSize]byte {
		var tok [TunnelTokenSize]byte
		sidHex := hex.EncodeToString(serverSID)
		if len(sidHex) > 31 {
			sidHex = sidHex[:31]
		}
		copy(tok[:], []byte(sidHex))
		tok[31] = 0x00
		copy(tok[32:48], []byte(strings.TrimSpace(ticket.TwfID)))
		return tok
	}

	var sslctxTok [TunnelTokenSize]byte
	if len(ticket.TunnelToken) == TunnelTokenSize {
		copy(sslctxTok[:], ticket.TunnelToken)
	}

	candidates := []layoutCandidate{
		{
			name: "op-first-sslctx[4:52]",
			make: func(_ []byte) [ControlMessageSize]byte {
				var buf [ControlMessageSize]byte
				copy(buf[4:52], sslctxTok[:])
				return buf
			},
		},
		{
			name: "token-first-shsid[0:48]",
			make: func(sid []byte) [ControlMessageSize]byte {
				var buf [ControlMessageSize]byte
				tok := buildTokenFromSID(sid)
				copy(buf[0:48], tok[:])
				return buf
			},
		},
		{
			name: "op-first-shsid[4:52]",
			make: func(sid []byte) [ControlMessageSize]byte {
				var buf [ControlMessageSize]byte
				tok := buildTokenFromSID(sid)
				copy(buf[4:52], tok[:])
				return buf
			},
		},
		{
			name: "twfid-first[0:16]",
			make: func(_ []byte) [ControlMessageSize]byte {
				var buf [ControlMessageSize]byte
				copy(buf[0:16], []byte(strings.TrimSpace(ticket.TwfID)))
				return buf
			},
		},
		{
			name: "op-first-twfid[4:20]",
			make: func(_ []byte) [ControlMessageSize]byte {
				var buf [ControlMessageSize]byte
				copy(buf[4:20], []byte(strings.TrimSpace(ticket.TwfID)))
				return buf
			},
		},
	}

	results := make([]QueryIPLayoutProbeResult, 0, len(candidates))
	for _, cand := range candidates {
		res := QueryIPLayoutProbeResult{Name: cand.name}
		conn, err := c.dialer.DialTunnel(ctx, host, port, eigenvalue, ticket.L3CipherSuite)
		if err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}

		var serverSID []byte
		if p, ok := conn.(ServerSessionIDProvider); ok {
			serverSID = p.ServerSessionID()
		}
		req := cand.make(serverSID)
		if err := writeControlWithDeadline(conn, req[:]); err != nil {
			res.Error = err.Error()
			_ = conn.Close()
			results = append(results, res)
			continue
		}
		rawResp, err := readControlWithDeadline(conn)
		_ = conn.Close()
		if err != nil {
			res.Error = err.Error()
			results = append(results, res)
			continue
		}
		res.ReplyHex = hex.EncodeToString(rawResp)
		if parsed, pErr := ParseControlFrame(rawResp); pErr == nil {
			res.Op = parsed.Op
			res.VirtualIP = parsed.VirtualIP
		}
		results = append(results, res)
	}
	return results
}

// DataStreamProbeResult 记录在 Query-IP 成功后对 RX/TX 数据流握手的单个候选探测结果。
type DataStreamProbeResult struct {
	Name      string
	ReqOp     uint8
	ReplyOp   uint8
	VirtualIP netip.Addr
	ReplyHex  string
	Error     string
}

// ProbeDataStreamLayouts 在 Query-IP 成功分配虚拟 IP 后，逐一探测 RX/TX 隧道流握手的操作码、顺序与字段布局。
func (c *SvpnClient) ProbeDataStreamLayouts(ctx context.Context, ticket model.SessionTicket) (netip.Addr, []DataStreamProbeResult) {
	host := strings.TrimSpace(ticket.GatewayHost)
	port := ticket.GatewayPort
	if port <= 0 {
		port = DefaultGatewayPort
	}
	eigenvalue := strings.TrimSpace(ticket.L3Eigenvalue)
	if eigenvalue == "" {
		eigenvalue = EigenvalueL3IP
	}

	var sslctxTok [TunnelTokenSize]byte
	if len(ticket.TunnelToken) == TunnelTokenSize {
		copy(sslctxTok[:], ticket.TunnelToken)
	} else if tok, err := BuildTunnelToken(ticket.TwfID); err == nil {
		sslctxTok = tok
	}

	ctrlConn, err := c.dialer.DialTunnel(ctx, host, port, eigenvalue, ticket.L3CipherSuite)
	if err != nil {
		return netip.Addr{}, []DataStreamProbeResult{{Name: "dial-ctrl", Error: err.Error()}}
	}
	defer func() { _ = ctrlConn.Close() }()

	var ctrlSID []byte
	if p, ok := ctrlConn.(ServerSessionIDProvider); ok {
		ctrlSID = p.ServerSessionID()
	}

	queryReq := ControlFrame{
		Op:        ControlOpQueryIP,
		Token:     sslctxTok,
		VirtualIP: ticket.VirtualIP,
	}.Encode()
	if err := writeControlWithDeadline(ctrlConn, queryReq[:]); err != nil {
		return netip.Addr{}, []DataStreamProbeResult{{Name: "send-query-ip", Error: err.Error()}}
	}
	queryRespRaw, err := readControlWithDeadline(ctrlConn)
	if err != nil {
		return netip.Addr{}, []DataStreamProbeResult{{Name: "read-query-ip", Error: err.Error()}}
	}
	queryParsed, err := ParseControlFrame(queryRespRaw)
	if err != nil {
		return netip.Addr{}, []DataStreamProbeResult{{Name: "parse-query-ip", ReplyHex: hex.EncodeToString(queryRespRaw), Error: err.Error()}}
	}
	vip := queryParsed.VirtualIP
	if queryParsed.Op == ControlOpShutdown || !vip.IsValid() {
		return vip, []DataStreamProbeResult{{
			Name:      "query-ip-rejected",
			ReplyOp:   queryParsed.Op,
			VirtualIP: vip,
			ReplyHex:  hex.EncodeToString(queryRespRaw),
			Error:     "query-ip did not allocate valid vip",
		}}
	}

	buildTokenFromSID := func(sid []byte) [TunnelTokenSize]byte {
		var tok [TunnelTokenSize]byte
		sidHex := hex.EncodeToString(sid)
		if len(sidHex) > 31 {
			sidHex = sidHex[:31]
		}
		copy(tok[:], []byte(sidHex))
		tok[31] = 0x00
		copy(tok[32:48], []byte(strings.TrimSpace(ticket.TwfID)))
		return tok
	}

	probeOne := func(name string, op uint8, makeFrame func(streamSID []byte) [ControlMessageSize]byte, keepOpen bool) (DataStreamProbeResult, net.Conn) {
		res := DataStreamProbeResult{Name: name, ReqOp: op}
		conn, dErr := c.dialer.DialTunnel(ctx, host, port, eigenvalue, ticket.L3CipherSuite)
		if dErr != nil {
			res.Error = dErr.Error()
			return res, nil
		}
		var streamSID []byte
		if p, ok := conn.(ServerSessionIDProvider); ok {
			streamSID = p.ServerSessionID()
		}
		req := makeFrame(streamSID)
		if wErr := writeControlWithDeadline(conn, req[:]); wErr != nil {
			res.Error = wErr.Error()
			_ = conn.Close()
			return res, nil
		}
		rawResp, rErr := readControlWithTimeout(conn, 3*time.Second)
		if rErr != nil {
			res.Error = rErr.Error()
			_ = conn.Close()
			return res, nil
		}
		res.ReplyHex = hex.EncodeToString(rawResp)
		if parsed, pErr := ParseControlFrame(rawResp); pErr == nil {
			res.ReplyOp = parsed.Op
			res.VirtualIP = parsed.VirtualIP
		}
		if !keepOpen {
			_ = conn.Close()
			return res, nil
		}
		return res, conn
	}

	type streamCand struct {
		name string
		op   uint8
		make func(streamSID []byte) [ControlMessageSize]byte
	}
	cands := []streamCand{
		{
			name: "tx-op05-sslctx-rev60",
			op:   ControlOpDataTX,
			make: func(_ []byte) [ControlMessageSize]byte {
				return ControlFrame{Op: ControlOpDataTX, Token: sslctxTok, VirtualIP: vip}.Encode()
			},
		},
		{
			name: "tx-op05-sslctx-vip60",
			op:   ControlOpDataTX,
			make: func(_ []byte) [ControlMessageSize]byte {
				return ControlFrame{Op: ControlOpDataTX, Token: sslctxTok, VirtualIP: vip}.encodeNetworkOrderIPAtTail()
			},
		},
		{
			name: "tx-op05-sslctx-zero",
			op:   ControlOpDataTX,
			make: func(_ []byte) [ControlMessageSize]byte {
				return ControlFrame{Op: ControlOpDataTX, Token: sslctxTok}.Encode()
			},
		},
		{
			name: "tx-op05-ctrlshsid-rev60",
			op:   ControlOpDataTX,
			make: func(_ []byte) [ControlMessageSize]byte {
				return ControlFrame{Op: ControlOpDataTX, Token: buildTokenFromSID(ctrlSID), VirtualIP: vip}.Encode()
			},
		},
		{
			name: "tx-op05-selfshsid-rev60",
			op:   ControlOpDataTX,
			make: func(sid []byte) [ControlMessageSize]byte {
				return ControlFrame{Op: ControlOpDataTX, Token: buildTokenFromSID(sid), VirtualIP: vip}.Encode()
			},
		},
		{
			name: "rx-op06-sslctx-rev60",
			op:   ControlOpDataRX,
			make: func(_ []byte) [ControlMessageSize]byte {
				return ControlFrame{Op: ControlOpDataRX, Token: sslctxTok, VirtualIP: vip}.Encode()
			},
		},
		{
			name: "rx-op06-sslctx-zero",
			op:   ControlOpDataRX,
			make: func(_ []byte) [ControlMessageSize]byte {
				return ControlFrame{Op: ControlOpDataRX, Token: sslctxTok}.Encode()
			},
		},
		{
			name: "rx-op06-ctrlshsid-rev60",
			op:   ControlOpDataRX,
			make: func(_ []byte) [ControlMessageSize]byte {
				return ControlFrame{Op: ControlOpDataRX, Token: buildTokenFromSID(ctrlSID), VirtualIP: vip}.Encode()
			},
		},
		{
			name: "rx-op06-selfshsid-rev60",
			op:   ControlOpDataRX,
			make: func(sid []byte) [ControlMessageSize]byte {
				return ControlFrame{Op: ControlOpDataRX, Token: buildTokenFromSID(sid), VirtualIP: vip}.Encode()
			},
		},
	}

	results := make([]DataStreamProbeResult, 0, len(cands)+2)
	var keptTX net.Conn
	defer func() {
		if keptTX != nil {
			_ = keptTX.Close()
		}
	}()

	for _, cand := range cands {
		wantKeep := keptTX == nil && strings.HasPrefix(cand.name, "tx-")
		res, conn := probeOne(cand.name, cand.op, cand.make, wantKeep)
		if conn != nil {
			if res.Error == "" && res.ReplyOp != ControlOpShutdown {
				keptTX = conn
			} else {
				_ = conn.Close()
			}
		}
		results = append(results, res)
	}

	// 若 TX 先成功建立，在保持 TX 在线的条件下验证紧随其后的 RX 握手。
	if keptTX != nil {
		rxRes, _ := probeOne("rx-after-tx-sslctx-rev60", ControlOpDataRX, func(_ []byte) [ControlMessageSize]byte {
			return ControlFrame{Op: ControlOpDataRX, Token: sslctxTok, VirtualIP: vip}.Encode()
		}, false)
		results = append(results, rxRes)
	}

	// 发送一次 op=0x03 心跳后再试一次标准 RX，判断网关是否依赖首包心跳激活会话。
	hb := ControlFrame{Op: ControlOpHeartbeat, Token: sslctxTok, VirtualIP: vip}.Encode()
	if hbErr := writeControlWithDeadline(ctrlConn, hb[:]); hbErr == nil {
		hbResp, hbReadErr := readControlWithTimeout(ctrlConn, 2*time.Second)
		hbRes := DataStreamProbeResult{Name: "ctrl-heartbeat-op03", ReqOp: ControlOpHeartbeat}
		if hbReadErr != nil {
			hbRes.Error = hbReadErr.Error()
		} else {
			hbRes.ReplyHex = hex.EncodeToString(hbResp)
			if parsed, pErr := ParseControlFrame(hbResp); pErr == nil {
				hbRes.ReplyOp = parsed.Op
				hbRes.VirtualIP = parsed.VirtualIP
			}
		}
		results = append(results, hbRes)

		afterHB, _ := probeOne("rx-after-hb-sslctx-vip52", ControlOpDataRX, func(_ []byte) [ControlMessageSize]byte {
			return ControlFrame{Op: ControlOpDataRX, Token: sslctxTok, VirtualIP: vip}.Encode()
		}, false)
		results = append(results, afterHB)
	}

	return vip, results
}

func writeControlWithDeadline(conn net.Conn, data []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	defer func() {
		_ = conn.SetWriteDeadline(time.Time{})
	}()
	for written := 0; written < len(data); {
		n, err := conn.Write(data[written:])
		if err != nil {
			return err
		}
		written += n
	}
	return nil
}

func readControlWithDeadline(conn net.Conn) ([]byte, error) {
	return readControlWithTimeout(conn, 10*time.Second)
}

func readControlWithTimeout(conn net.Conn, timeout time.Duration) ([]byte, error) {
	var buf [ControlMessageSize]byte
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()

	// 先读取首帧（实测网关返回 36 字节，兼容 64 字节响应），避免 io.ReadFull(64) 丢弃有效 36B 响应触发 unexpected EOF。
	n, err := conn.Read(buf[:])
	if n == 0 && err != nil {
		return nil, err
	}
	for n < ControlReplySize {
		more, rErr := conn.Read(buf[n:])
		n += more
		if rErr != nil {
			if n > 0 {
				return buf[:n], nil
			}
			return nil, rErr
		}
	}
	return buf[:n], nil
}
