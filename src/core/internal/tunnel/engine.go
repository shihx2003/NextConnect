package tunnel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nextconnect/core/internal/protocol"
	"github.com/nextconnect/core/internal/tunnel/proxy"
	"github.com/nextconnect/core/internal/tunnel/tun"
	"github.com/nextconnect/core/pkg/model"
)

const (
	maxLogHistoryEntries = 500
	defaultStatsInterval = 1 * time.Second
	defaultKeepAliveTick = 20 * time.Second
)

// ConnectParams 描述通过本地控制接口或 CLI 发起校园网连接的输入参数。
type ConnectParams struct {
	GatewayURL  string `json:"gatewayUrl"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	CaptchaCode string `json:"captchaCode,omitempty"`
	PreTwfID    string `json:"preTwfId,omitempty"`
	CASCookie   string `json:"casCookie,omitempty"`
	RoutingMode string `json:"routingMode,omitempty"`
}

// AuthChallengeError 表示网关要求图形验证码、短信或动态令牌等二次认证。
type AuthChallengeError struct {
	AuthType     string `json:"authType"`
	NextAuth     string `json:"nextAuth"`
	Message      string `json:"message"`
	ChallengeID  string `json:"challengeId,omitempty"`
	CaptchaImage string `json:"captchaImageBase64,omitempty"`
}

func (e *AuthChallengeError) Error() string {
	return fmt.Sprintf("secondary authentication required (type=%s): %s", e.AuthType, e.Message)
}

type routeAdapter struct {
	rt *RouteTable
}

func (a routeAdapter) Match(host string) (model.RuleAction, string) {
	dec := a.rt.MatchHost(host)
	return dec.Action, dec.Rule
}

func (a routeAdapter) Rules() []model.RuleEntry {
	return a.rt.Rules()
}

func (a routeAdapter) Mode() model.RoutingMode {
	return a.rt.Mode()
}

type trackedConn struct {
	net.Conn
	id        string
	source    string
	dest      string
	network   string
	rule      string
	startedAt time.Time

	uploadBytes   atomic.Uint64
	downloadBytes atomic.Uint64
	lastUpload    atomic.Uint64
	lastDownload  atomic.Uint64
	upRateBps     atomic.Uint64
	downRateBps   atomic.Uint64

	totalUpRef   *atomic.Uint64
	totalDownRef *atomic.Uint64

	closeOnce sync.Once
	onClose   func()
}

func (tc *trackedConn) Read(p []byte) (int, error) {
	n, err := tc.Conn.Read(p)
	if n > 0 {
		u := uint64(n)
		tc.downloadBytes.Add(u)
		tc.totalDownRef.Add(u)
	}
	return n, err
}

func (tc *trackedConn) Write(p []byte) (int, error) {
	n, err := tc.Conn.Write(p)
	if n > 0 {
		u := uint64(n)
		tc.uploadBytes.Add(u)
		tc.totalUpRef.Add(u)
	}
	return n, err
}

func (tc *trackedConn) Close() error {
	var err error
	tc.closeOnce.Do(func() {
		err = tc.Conn.Close()
		if tc.onClose != nil {
			tc.onClose()
		}
	})
	return err
}

// EngineOption 用于定制 Engine（例如单元测试注入 Mock 认证器或 Mock SVPN 拨号器）。
type EngineOption func(*Engine)

// WithAuthenticator 替换默认 SangforAuthenticator。
func WithAuthenticator(auth protocol.Authenticator) EngineOption {
	return func(e *Engine) {
		if auth != nil {
			e.authenticator = auth
		}
	}
}

// WithTunnelDialer 替换端口 443 SVPN 底层 TLS 拨号器。
func WithTunnelDialer(dialer protocol.TunnelDialer) EngineOption {
	return func(e *Engine) {
		e.tunnelDialer = dialer
	}
}

// WithLocalProxyAddrs 指定本地 SOCKS5 与 HTTP 代理监听地址（测试时可传入 127.0.0.1:0）。
func WithLocalProxyAddrs(socksAddr string, httpAddr string) EngineOption {
	return func(e *Engine) {
		e.socksListenAddr = socksAddr
		e.httpListenAddr = httpAddr
	}
}

// WithLogWriter 配置实时内核日志的同步输出目标（如终端或日志文件）与最低级别（debug/info/warn/error）。
func WithLogWriter(w io.Writer, minLevel string) EngineOption {
	return func(e *Engine) {
		e.logWriter = w
		e.logMinLevel = logLevelRank(minLevel)
	}
}

// Engine 负责调度 SVPN 隧道、用户态 Netstack 代理、分流路由表、实时流量统计与日志广播。
type Engine struct {
	mu            sync.RWMutex
	state         model.ConnectionState
	profile       model.ConnectionProfile
	ticket        model.SessionTicket
	hasRealTicket bool
	connectedAt   time.Time

	routeTable    *RouteTable
	authenticator protocol.Authenticator
	tunnelDialer  protocol.TunnelDialer

	socksListenAddr string
	httpListenAddr  string
	actualSocksAddr string
	actualHTTPAddr  string

	svpnClient       *protocol.SvpnClient
	packetHub        *svpnPacketHub
	tunManager       *tun.Manager
	gatewayBypassIPs []netip.Addr
	netstackTunnel   *proxy.NetstackTunnel
	socksServer      *proxy.Socks5Server
	httpServer       *proxy.HTTPProxyServer

	runCancel context.CancelFunc
	runWG     sync.WaitGroup

	connMu      sync.RWMutex
	connections map[string]*trackedConn
	nextConnSeq atomic.Uint64

	totalUpload   atomic.Uint64
	totalDownload atomic.Uint64
	aggUpRate     atomic.Uint64
	aggDownRate   atomic.Uint64

	subMu       sync.Mutex
	trafficSubs map[chan model.TrafficSnapshot]struct{}
	logSubs     map[chan model.LogEntry]struct{}

	logMu       sync.Mutex
	logHistory  []model.LogEntry
	logWriter   io.Writer
	logMinLevel int
}

// NewEngine 创建并初始化隧道调度引擎（默认 Rule 规则分流，零驱动本地代理）。
func NewEngine(opts ...EngineOption) *Engine {
	e := &Engine{
		state:      model.StateDisconnected,
		routeTable: NewRouteTable(),
		profile: model.ConnectionProfile{
			ProfileName:    "Campus-SSL-VPN",
			GatewayURL:     protocol.DefaultGatewayURL,
			RoutingMode:    model.RoutingModeRule,
			SystemProxyOn:  true,
			TunModeOn:      false,
			LocalSocksPort: 10808,
			LocalHTTPPort:  10809,
			ControllerAddr: "127.0.0.1:9090",
		},
		authenticator: protocol.NewSangforAuthenticator(nil),
		connections:   make(map[string]*trackedConn),
		trafficSubs:   make(map[chan model.TrafficSnapshot]struct{}),
		logSubs:       make(map[chan model.LogEntry]struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	return e
}

// ConnectWithCredentials 完成校园网网关认证并拉起 SVPN 隧道与本地代理服务。
func (e *Engine) ConnectWithCredentials(ctx context.Context, params ConnectParams) (model.SessionTicket, error) {
	e.mu.Lock()
	if e.state == model.StateConnected || e.state == model.StateAuthenticating || e.state == model.StateEstablishingTunnel {
		e.mu.Unlock()
		_ = e.Stop(context.Background())
		e.mu.Lock()
	}

	if gw := strings.TrimSpace(params.GatewayURL); gw != "" {
		e.profile.GatewayURL = gw
	}
	if params.RoutingMode == string(model.RoutingModeGlobal) {
		e.profile.RoutingMode = model.RoutingModeGlobal
		e.routeTable.SetMode(model.RoutingModeGlobal)
	} else if params.RoutingMode == string(model.RoutingModeRule) {
		e.profile.RoutingMode = model.RoutingModeRule
		e.routeTable.SetMode(model.RoutingModeRule)
	}
	profile := e.profile
	e.state = model.StateAuthenticating
	e.mu.Unlock()

	e.Log("info", "auth", fmt.Sprintf("authenticating to gateway %s", profile.GatewayURL))

	var ticket model.SessionTicket
	var err error
	if strings.TrimSpace(params.CASCookie) != "" {
		ticket, err = e.authenticator.AuthenticateWithCookie(ctx, profile, params.CASCookie)
	} else if optAuth, ok := e.authenticator.(interface {
		AuthenticateWithOptions(context.Context, model.ConnectionProfile, string, string, protocol.AuthOptions) (model.SessionTicket, error)
	}); ok && (params.CaptchaCode != "" || params.PreTwfID != "") {
		ticket, err = optAuth.AuthenticateWithOptions(ctx, profile, params.Username, params.Password, protocol.AuthOptions{
			CaptchaCode: params.CaptchaCode,
			PreTwfID:    params.PreTwfID,
		})
	} else {
		ticket, err = e.authenticator.Authenticate(ctx, profile, params.Username, params.Password)
	}
	if err != nil {
		e.setState(model.StateFaulted)
		var secErr *protocol.SecondaryAuthRequiredError
		if errors.As(err, &secErr) {
			challenge := &AuthChallengeError{
				AuthType:    string(secErr.AuthType),
				NextAuth:    secErr.NextAuth,
				Message:     secErr.Message,
				ChallengeID: secErr.TwfID,
			}
			if secErr.AuthType == protocol.AuthTypeCaptcha {
				if capFetcher, ok := e.authenticator.(interface {
					FetchCaptcha(context.Context, string, string) ([]byte, string, error)
				}); ok {
					if imgBytes, updatedTwf, capErr := capFetcher.FetchCaptcha(ctx, profile.GatewayURL, secErr.TwfID); capErr == nil {
						challenge.CaptchaImage = base64.StdEncoding.EncodeToString(imgBytes)
						if updatedTwf != "" {
							challenge.ChallengeID = updatedTwf
						}
					}
				}
			}
			e.Log("warn", "auth", challenge.Error())
			return model.SessionTicket{}, challenge
		}
		e.Log("error", "auth", fmt.Sprintf("authentication failed: %v", err))
		return model.SessionTicket{}, err
	}

	e.Log("info", "auth", fmt.Sprintf("authenticated (twfid=%s, dns=%d, subnets=%d, domains=%d)",
		protocol.MaskCredential(ticket.TwfID), len(ticket.DNSServers), len(ticket.IntranetSubnets), len(ticket.IntranetDomains)))

	if err := e.startSession(ctx, ticket, true); err != nil {
		_ = e.authenticator.Logout(context.Background(), profile, ticket)
		return model.SessionTicket{}, err
	}
	return e.Ticket(), nil
}

// Start 使用外部提供的会话凭据启动隧道与本地代理分流器。
func (e *Engine) Start(ctx context.Context, ticket model.SessionTicket) error {
	return e.startSession(ctx, ticket, false)
}

func (e *Engine) startSession(ctx context.Context, ticket model.SessionTicket, realAuth bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	_ = e.Stop(context.Background())

	e.mu.Lock()
	e.state = model.StateEstablishingTunnel
	e.profile.SystemProxyOn = true
	e.mu.Unlock()

	var svpnClient *protocol.SvpnClient
	var packetHub *svpnPacketHub
	var packetTransport proxy.PacketTransport

	runCtx, runCancel := context.WithCancel(context.Background())

	if ticket.GatewayHost != "" && ticket.TwfID != "" && ticket.TwfID != "DIAGNOSTIC_PLACEHOLDER_TOKEN" {
		svpnClient = protocol.NewSvpnClient(e.tunnelDialer)
		updated, err := svpnClient.Connect(ctx, ticket)
		if err != nil {
			runCancel()
			e.setState(model.StateFaulted)
			e.Log("error", "svpn", fmt.Sprintf("port 443 tunnel handshake failed: %v", err))
			return fmt.Errorf("svpn connect failed: %w", err)
		}
		ticket = updated
		activeSvpn := svpnClient
		packetHub = newSvpnPacketHub(runCtx, svpnClient, e.Log, func(lossErr error) {
			e.mu.Lock()
			stillActive := e.svpnClient == activeSvpn && e.state == model.StateConnected
			if stillActive {
				e.state = model.StateFaulted
			}
			e.mu.Unlock()
			if stillActive {
				e.Log("error", "svpn", fmt.Sprintf("L3VPN tunnel disconnected unexpectedly: %v", lossErr))
				e.publishTrafficSnapshot(e.Snapshot())
			}
		})
		packetTransport = packetHub.netstackView()
		e.Log("info", "svpn", fmt.Sprintf("L3VPN tunnel established (vip=%v, mtu=%d)", ticket.VirtualIP, svpnClient.MTU()))
	} else {
		// 仅本地诊断模式：保留内存通道用于本地协议栈自检，公网流量走直连。
		packetTransport = newNullPacketTransport(protocol.DefaultTunnelMTU)
		e.Log("info", "svpn", "running in local proxy-only diagnostic mode without remote 443 session")
	}

	e.routeTable.LoadFromTicket(ticket)
	var gatewayBypassIPs []netip.Addr
	if ticket.GatewayHost != "" {
		if ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", ticket.GatewayHost); err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					gatewayBypassIPs = append(gatewayBypassIPs, netip.AddrFrom4([4]byte(ip4)))
				}
			}
		}
		e.routeTable.SetGatewayBypass(ticket.GatewayHost, gatewayBypassIPs)
	}

	netstackTunnel, err := proxy.NewNetstackTunnel(runCtx, packetTransport, ticket.VirtualIP, ticket.DNSServers)
	if err != nil {
		runCancel()
		if packetHub != nil {
			_ = packetHub.closeAll()
		}
		if svpnClient != nil {
			_ = svpnClient.Close()
		}
		e.setState(model.StateFaulted)
		return fmt.Errorf("start gvisor netstack failed: %w", err)
	}

	var tunnelDialer proxy.TargetDialer = netstackTunnel
	if svpnClient == nil {
		// 诊断模式没有远程 443 网关时，避免阻塞在无效虚拟通道。
		tunnelDialer = nil
	}

	socksListen := e.resolveSocksListenAddr()
	httpListen := e.resolveHTTPListenAddr()

	adapter := routeAdapter{rt: e.routeTable}
	socksSrv := proxy.NewSocks5Server(socksListen, adapter, tunnelDialer, e)
	actualSocks, err := socksSrv.ListenAndServe(runCtx)
	if err != nil {
		runCancel()
		_ = netstackTunnel.Close()
		e.setState(model.StateFaulted)
		return err
	}

	httpSrv := proxy.NewHTTPProxyServer(httpListen, adapter, tunnelDialer, e, e.PACScript)
	actualHTTP, err := httpSrv.ListenAndServe(runCtx)
	if err != nil {
		runCancel()
		_ = socksSrv.Close()
		_ = netstackTunnel.Close()
		e.setState(model.StateFaulted)
		return err
	}

	e.mu.Lock()
	e.ticket = ticket
	e.hasRealTicket = realAuth
	e.connectedAt = time.Now()
	e.svpnClient = svpnClient
	e.packetHub = packetHub
	e.gatewayBypassIPs = gatewayBypassIPs
	e.tunManager = nil
	e.netstackTunnel = netstackTunnel
	e.socksServer = socksSrv
	e.httpServer = httpSrv
	e.actualSocksAddr = actualSocks
	e.actualHTTPAddr = actualHTTP
	if port := parsePortFromAddr(actualSocks); port > 0 {
		e.profile.LocalSocksPort = port
	}
	if port := parsePortFromAddr(actualHTTP); port > 0 {
		e.profile.LocalHTTPPort = port
	}
	e.runCancel = runCancel
	e.state = model.StateConnected
	e.mu.Unlock()

	e.Log("info", "proxy", fmt.Sprintf("SOCKS5 listening on %s, HTTP/PAC listening on %s (mode=%s)",
		actualSocks, actualHTTP, e.routeTable.Mode()))

	e.runWG.Add(1)
	go e.runStatsAndKeepAliveLoop(runCtx)

	e.publishTrafficSnapshot(e.Snapshot())
	return nil
}

// Stop 优雅断开隧道、注销远程会话并确定性释放所有监听端口与活动连接。
func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	cancel := e.runCancel
	socksSrv := e.socksServer
	httpSrv := e.httpServer
	netstack := e.netstackTunnel
	tunMgr := e.tunManager
	hub := e.packetHub
	svpn := e.svpnClient
	ticket := e.ticket
	profile := e.profile
	realAuth := e.hasRealTicket

	e.runCancel = nil
	e.socksServer = nil
	e.httpServer = nil
	e.netstackTunnel = nil
	e.tunManager = nil
	e.packetHub = nil
	e.gatewayBypassIPs = nil
	e.svpnClient = nil
	e.hasRealTicket = false
	e.actualSocksAddr = ""
	e.actualHTTPAddr = ""
	e.profile.TunModeOn = false
	e.state = model.StateDisconnected
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	// 关闭所有正在转发的活动连接，确保 io.Copy 协程立即返回。
	e.connMu.Lock()
	active := make([]*trackedConn, 0, len(e.connections))
	for _, tc := range e.connections {
		active = append(active, tc)
	}
	e.connections = make(map[string]*trackedConn)
	e.connMu.Unlock()
	for _, tc := range active {
		_ = tc.Close()
	}

	if tunMgr != nil {
		_ = tunMgr.Close()
		e.Log("info", "tun", "Wintun virtual adapter closed and routes removed")
	}
	if socksSrv != nil {
		_ = socksSrv.Close()
	}
	if httpSrv != nil {
		_ = httpSrv.Close()
	}
	if netstack != nil {
		_ = netstack.Close()
	}
	if hub != nil {
		_ = hub.closeAll()
	}
	if svpn != nil {
		_ = svpn.Close()
	}

	e.runWG.Wait()

	if realAuth && ticket.TwfID != "" && e.authenticator != nil {
		logoutCtx, logoutCancel := context.WithTimeout(ctx, 5*time.Second)
		_ = e.authenticator.Logout(logoutCtx, profile, ticket)
		logoutCancel()
		e.Log("info", "auth", "gateway session logged out cleanly")
	}

	e.aggUpRate.Store(0)
	e.aggDownRate.Store(0)
	e.publishTrafficSnapshot(e.Snapshot())
	return nil
}

// SetModeFlags 供控制 API 动态切换系统代理或虚拟网卡模式。
func (e *Engine) SetModeFlags(systemProxyOn bool, tunModeOn bool) {
	e.mu.Lock()
	e.profile.SystemProxyOn = systemProxyOn
	e.profile.TunModeOn = tunModeOn
	e.mu.Unlock()
	e.publishTrafficSnapshot(e.Snapshot())
}

// TunCapabilities 返回当前平台的 Wintun 虚拟网卡可用性与权限检测状态。
func (e *Engine) TunCapabilities() tun.Capabilities {
	return tun.QueryCapabilities()
}

// ApplyModeFlags 动态切换系统代理与 Wintun 虚拟网卡模式；若在已连接状态下开启虚拟网卡失败会回滚开关并返回错误。
func (e *Engine) ApplyModeFlags(ctx context.Context, systemProxyOn bool, tunModeOn bool) error {
	e.mu.Lock()
	svpn := e.svpnClient
	hub := e.packetHub
	existingTun := e.tunManager
	ticket := e.ticket
	bypassIPs := append([]netip.Addr(nil), e.gatewayBypassIPs...)
	e.profile.SystemProxyOn = systemProxyOn

	if !tunModeOn {
		e.tunManager = nil
		e.profile.TunModeOn = false
		e.mu.Unlock()

		if hub != nil {
			hub.setTunTarget(nil)
		}
		if existingTun != nil {
			_ = existingTun.Close()
			e.Log("info", "tun", "Wintun virtual adapter closed and routes restored")
		}
		e.publishTrafficSnapshot(e.Snapshot())
		return nil
	}

	if svpn == nil || hub == nil {
		// 诊断模式或未连线前仅记录期望开关状态，实际拉起将在连接成功后或非诊断环境生效。
		if e.state == model.StateDisconnected || !e.hasRealTicket {
			e.profile.TunModeOn = true
			e.mu.Unlock()
			e.publishTrafficSnapshot(e.Snapshot())
			return nil
		}
	}

	if existingTun != nil {
		e.profile.TunModeOn = true
		e.mu.Unlock()
		e.publishTrafficSnapshot(e.Snapshot())
		return nil
	}
	e.mu.Unlock()

	if svpn == nil || hub == nil {
		return nil
	}

	routes := append([]netip.Prefix(nil), ticket.IntranetSubnets...)
	if len(routes) == 0 {
		routes = defaultCampusCIDRs()
	}

	cfg := tun.Config{
		AdapterName: tun.DefaultAdapterName,
		VirtualIP:   ticket.VirtualIP,
		PrefixLen:   32,
		MTU:         svpn.MTU(),
		Routes:      routes,
		BypassIPs:   bypassIPs,
	}

	mgr, err := tun.StartPlatformBridge(ctx, cfg, hub.tunBridgeView(), e.Log)
	if err != nil {
		e.mu.Lock()
		e.profile.TunModeOn = false
		e.mu.Unlock()
		e.Log("warn", "tun", fmt.Sprintf("enable Wintun failed: %v", err))
		e.publishTrafficSnapshot(e.Snapshot())
		return err
	}

	e.mu.Lock()
	e.tunManager = mgr
	e.profile.TunModeOn = true
	e.mu.Unlock()
	hub.setTunTarget(mgr)
	e.publishTrafficSnapshot(e.Snapshot())
	return nil
}

// SetRoutingMode 动态切换规则分流（rule）或全局代理（global）模式。
func (e *Engine) SetRoutingMode(mode model.RoutingMode) {
	if mode != model.RoutingModeGlobal {
		mode = model.RoutingModeRule
	}
	e.routeTable.SetMode(mode)
	e.mu.Lock()
	e.profile.RoutingMode = mode
	e.mu.Unlock()
	e.Log("info", "router", fmt.Sprintf("routing mode switched to %s", mode))
	e.publishTrafficSnapshot(e.Snapshot())
}

// Snapshot 返回当前实时状态与速率快照。
func (e *Engine) Snapshot() model.TrafficSnapshot {
	e.mu.RLock()
	state := e.state
	profile := e.profile
	vip := e.ticket.VirtualIP
	connAt := e.connectedAt
	e.mu.RUnlock()

	e.connMu.RLock()
	activeCount := len(e.connections)
	e.connMu.RUnlock()

	var uptime int64
	if state == model.StateConnected && !connAt.IsZero() {
		uptime = int64(time.Since(connAt).Seconds())
	}

	return model.TrafficSnapshot{
		State:           state,
		RoutingMode:     e.routeTable.Mode(),
		SystemProxyOn:   profile.SystemProxyOn,
		TunModeOn:       profile.TunModeOn,
		VirtualIP:       vip,
		UploadRateBps:   e.aggUpRate.Load(),
		DownloadRateBps: e.aggDownRate.Load(),
		TotalUpload:     e.totalUpload.Load(),
		TotalDownload:   e.totalDownload.Load(),
		ActiveCount:     activeCount,
		UptimeSeconds:   uptime,
	}
}

// Connections 返回当前活动连接列表副本。
func (e *Engine) Connections() []model.ActiveConnection {
	e.connMu.RLock()
	defer e.connMu.RUnlock()

	out := make([]model.ActiveConnection, 0, len(e.connections))
	for _, tc := range e.connections {
		out = append(out, model.ActiveConnection{
			ID:              tc.id,
			Source:          tc.source,
			Destination:     tc.dest,
			Network:         tc.network,
			Rule:            tc.rule,
			UploadBytes:     tc.uploadBytes.Load(),
			DownloadBytes:   tc.downloadBytes.Load(),
			UploadRateBps:   tc.upRateBps.Load(),
			DownloadRateBps: tc.downRateBps.Load(),
			StartedAt:       tc.startedAt,
		})
	}
	return out
}

// CloseConnection 根据 ID 立即中断并移除一条活动连接。
func (e *Engine) CloseConnection(id string) error {
	e.connMu.RLock()
	tc, ok := e.connections[id]
	e.connMu.RUnlock()
	if !ok {
		return fmt.Errorf("connection %q not found", id)
	}
	e.Log("info", "conn", fmt.Sprintf("closing connection %s (%s)", id, tc.dest))
	return tc.Close()
}

// RouteTable 返回引擎持有的分流路由表。
func (e *Engine) RouteTable() *RouteTable {
	return e.routeTable
}

// Ticket 返回当前生效的脱敏会话信息副本（调用方切勿打印 TwfID）。
func (e *Engine) Ticket() model.SessionTicket {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ticket
}

// ProxyAddrs 返回当前正在监听的 SOCKS5 与 HTTP 代理实际地址。
func (e *Engine) ProxyAddrs() (socksAddr string, httpAddr string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.actualSocksAddr, e.actualHTTPAddr
}

// PACScript 根据当前分流规则与本地代理端口生成实时 PAC 自动配置脚本。
func (e *Engine) PACScript() string {
	e.mu.RLock()
	httpPort := e.profile.LocalHTTPPort
	socksPort := e.profile.LocalSocksPort
	e.mu.RUnlock()
	return proxy.GeneratePAC(httpPort, socksPort, e.routeTable.Mode(), e.routeTable.Rules())
}

// WrapAndTrack 实现 proxy.ConnObserver，追踪每条活动连接的上下行字节数、速率与生命周期。
func (e *Engine) WrapAndTrack(
	conn net.Conn,
	source string,
	destination string,
	network string,
	rule string,
) net.Conn {
	id := fmt.Sprintf("conn-%d", e.nextConnSeq.Add(1))
	tc := &trackedConn{
		Conn:         conn,
		id:           id,
		source:       source,
		dest:         destination,
		network:      network,
		rule:         rule,
		startedAt:    time.Now(),
		totalUpRef:   &e.totalUpload,
		totalDownRef: &e.totalDownload,
	}
	tc.onClose = func() {
		e.connMu.Lock()
		delete(e.connections, id)
		e.connMu.Unlock()
		e.Log("debug", "proxy", fmt.Sprintf("%s %s closed (up=%dB down=%dB dur=%s)",
			network, destination, tc.uploadBytes.Load(), tc.downloadBytes.Load(), time.Since(tc.startedAt).Round(time.Millisecond)))
	}

	e.connMu.Lock()
	e.connections[id] = tc
	e.connMu.Unlock()

	e.Log("info", "proxy", fmt.Sprintf("%s %s -> [%s]", network, destination, rule))
	return tc
}

// Log 记录一条脱敏后的内核运行日志，同步写入配置的终端/文件输出并推送给订阅的 WebSocket 客户端。
func (e *Engine) Log(level string, component string, message string) {
	safeMsg := e.redactSensitive(message)
	normLevel := strings.ToLower(strings.TrimSpace(level))
	if normLevel == "" {
		normLevel = "info"
	}
	entry := model.LogEntry{
		Timestamp: time.Now(),
		Level:     normLevel,
		Component: component,
		Message:   safeMsg,
	}

	e.logMu.Lock()
	if len(e.logHistory) >= maxLogHistoryEntries {
		copy(e.logHistory, e.logHistory[1:])
		e.logHistory[len(e.logHistory)-1] = entry
	} else {
		e.logHistory = append(e.logHistory, entry)
	}
	if e.logWriter != nil && logLevelRank(normLevel) >= e.logMinLevel {
		_, _ = fmt.Fprintf(e.logWriter, "%s [%-5s] [%-10s] %s\n",
			entry.Timestamp.Format("2006/01/02 15:04:05"),
			strings.ToUpper(normLevel),
			component,
			safeMsg,
		)
	}
	e.logMu.Unlock()

	e.subMu.Lock()
	for ch := range e.logSubs {
		select {
		case ch <- entry:
		default:
		}
	}
	e.subMu.Unlock()
}

func logLevelRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return 0
	case "warn", "warning":
		return 2
	case "error", "err":
		return 3
	default:
		return 1
	}
}

// RecentLogs 返回最近若干条脱敏日志（默认最多全部历史）。
func (e *Engine) RecentLogs(limit int) []model.LogEntry {
	e.logMu.Lock()
	defer e.logMu.Unlock()

	n := len(e.logHistory)
	if limit > 0 && limit < n {
		out := make([]model.LogEntry, limit)
		copy(out, e.logHistory[n-limit:])
		return out
	}
	out := make([]model.LogEntry, n)
	copy(out, e.logHistory)
	return out
}

// SubscribeTraffic 订阅每秒实时流量与状态快照（需调用返回的取消函数清理）。
func (e *Engine) SubscribeTraffic() (<-chan model.TrafficSnapshot, func()) {
	ch := make(chan model.TrafficSnapshot, 16)
	e.subMu.Lock()
	e.trafficSubs[ch] = struct{}{}
	e.subMu.Unlock()

	return ch, func() {
		e.subMu.Lock()
		if _, ok := e.trafficSubs[ch]; ok {
			delete(e.trafficSubs, ch)
			close(ch)
		}
		e.subMu.Unlock()
	}
}

// SubscribeLogs 订阅实时脱敏日志流（需调用返回的取消函数清理）。
func (e *Engine) SubscribeLogs() (<-chan model.LogEntry, func()) {
	ch := make(chan model.LogEntry, 32)
	e.subMu.Lock()
	e.logSubs[ch] = struct{}{}
	e.subMu.Unlock()

	return ch, func() {
		e.subMu.Lock()
		if _, ok := e.logSubs[ch]; ok {
			delete(e.logSubs, ch)
			close(ch)
		}
		e.subMu.Unlock()
	}
}

func (e *Engine) runStatsAndKeepAliveLoop(ctx context.Context) {
	defer e.runWG.Done()

	statsTicker := time.NewTicker(defaultStatsInterval)
	keepAliveTicker := time.NewTicker(defaultKeepAliveTick)
	defer statsTicker.Stop()
	defer keepAliveTicker.Stop()

	var prevTotalUp = e.totalUpload.Load()
	var prevTotalDown = e.totalDownload.Load()
	var keepAliveTickCount uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-statsTicker.C:
			curUp := e.totalUpload.Load()
			curDown := e.totalDownload.Load()
			if curUp >= prevTotalUp {
				e.aggUpRate.Store(curUp - prevTotalUp)
			}
			if curDown >= prevTotalDown {
				e.aggDownRate.Store(curDown - prevTotalDown)
			}
			prevTotalUp = curUp
			prevTotalDown = curDown

			e.connMu.RLock()
			for _, tc := range e.connections {
				u := tc.uploadBytes.Load()
				d := tc.downloadBytes.Load()
				lu := tc.lastUpload.Swap(u)
				ld := tc.lastDownload.Swap(d)
				if u >= lu {
					tc.upRateBps.Store(u - lu)
				}
				if d >= ld {
					tc.downRateBps.Store(d - ld)
				}
			}
			e.connMu.RUnlock()

			e.publishTrafficSnapshot(e.Snapshot())

		case <-keepAliveTicker.C:
			keepAliveTickCount++
			e.mu.RLock()
			svpn := e.svpnClient
			netstack := e.netstackTunnel
			realAuth := e.hasRealTicket
			profile := e.profile
			ticket := e.ticket
			e.mu.RUnlock()

			if svpn != nil {
				if err := svpn.SendHeartbeat(); err != nil {
					e.Log("warn", "svpn", fmt.Sprintf("tunnel heartbeat failed: %v", err))
				} else {
					e.Log("debug", "svpn", "tunnel control heartbeat ok")
				}
			}
			// 周期性在 L3 数据通道发送轻量 DNS A 记录保活包，避免网关因 60s 无 IP 包主动关闭 RX 流。
			if svpn != nil && netstack != nil {
				l3Ctx, l3Cancel := context.WithTimeout(ctx, 4*time.Second)
				if err := netstack.KeepAlive(l3Ctx); err != nil {
					e.Log("debug", "svpn", fmt.Sprintf("l3 dns keepalive probe: %v", err))
				} else {
					e.Log("debug", "svpn", "l3 dns keepalive probe ok")
				}
				l3Cancel()
			}
			// 每 40 秒发送一次 /por/update_session.csp，避免网关 60 秒空闲淘汰会话。
			if keepAliveTickCount%2 == 0 && realAuth && e.authenticator != nil && ticket.TwfID != "" {
				kaCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				err := e.authenticator.KeepAlive(kaCtx, profile, ticket)
				cancel()
				if err != nil {
					e.Log("warn", "auth", fmt.Sprintf("session keepalive warning: %v", err))
				} else {
					e.Log("debug", "auth", "session keepalive ok")
				}
			}
		}
	}
}

func (e *Engine) publishTrafficSnapshot(snap model.TrafficSnapshot) {
	e.subMu.Lock()
	for ch := range e.trafficSubs {
		select {
		case ch <- snap:
		default:
		}
	}
	e.subMu.Unlock()
}

func (e *Engine) setState(state model.ConnectionState) {
	e.mu.Lock()
	e.state = state
	e.mu.Unlock()
	e.publishTrafficSnapshot(e.Snapshot())
}

func (e *Engine) redactSensitive(msg string) string {
	e.mu.RLock()
	twfID := e.ticket.TwfID
	e.mu.RUnlock()
	if twfID != "" && twfID != "DIAGNOSTIC_PLACEHOLDER_TOKEN" {
		msg = strings.ReplaceAll(msg, twfID, protocol.MaskCredential(twfID))
	}
	return msg
}

func (e *Engine) resolveSocksListenAddr() string {
	if e.socksListenAddr != "" {
		return e.socksListenAddr
	}
	e.mu.RLock()
	port := e.profile.LocalSocksPort
	e.mu.RUnlock()
	if port <= 0 {
		port = 10808
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func (e *Engine) resolveHTTPListenAddr() string {
	if e.httpListenAddr != "" {
		return e.httpListenAddr
	}
	e.mu.RLock()
	port := e.profile.LocalHTTPPort
	e.mu.RUnlock()
	if port <= 0 {
		port = 10809
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func parsePortFromAddr(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return p
}

type nullPacketTransport struct {
	mtu    int
	closed chan struct{}
	once   sync.Once
}

func newNullPacketTransport(mtu int) *nullPacketTransport {
	return &nullPacketTransport{
		mtu:    mtu,
		closed: make(chan struct{}),
	}
}

func (n *nullPacketTransport) ReadPacket() ([]byte, error) {
	<-n.closed
	return nil, errors.New("diagnostic transport closed")
}

func (n *nullPacketTransport) WritePacket(_ []byte) error {
	return nil
}

func (n *nullPacketTransport) MTU() int { return n.mtu }

func (n *nullPacketTransport) Close() error {
	n.once.Do(func() {
		close(n.closed)
	})
	return nil
}

type svpnPacketHub struct {
	svpn      *protocol.SvpnClient
	onLog     func(level, component, msg string)
	onLoss    func(error)
	netInCh   chan []byte
	tunInCh   chan []byte
	closed    chan struct{}
	closeOnce sync.Once

	tunMu     sync.RWMutex
	tunActive bool
}

func newSvpnPacketHub(
	ctx context.Context,
	svpn *protocol.SvpnClient,
	onLog func(level, component, msg string),
	onLoss func(error),
) *svpnPacketHub {
	h := &svpnPacketHub{
		svpn:    svpn,
		onLog:   onLog,
		onLoss:  onLoss,
		netInCh: make(chan []byte, 256),
		tunInCh: make(chan []byte, 256),
		closed:  make(chan struct{}),
	}
	go h.readLoop(ctx)
	return h
}

func (h *svpnPacketHub) readLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.closed:
			return
		default:
		}
		pkt, err := h.svpn.ReadPacket()
		if err != nil {
			if ctx.Err() != nil || h.isClosed() {
				return
			}
			if recovered, recErr := h.tryRecoverRX(ctx, err); recovered {
				continue
			} else if !h.isClosed() && ctx.Err() == nil {
				if h.onLog != nil {
					h.onLog("warn", "svpn", fmt.Sprintf("rx packet loop exited: %v", recErr))
				}
				if h.onLoss != nil {
					h.onLoss(recErr)
				}
			}
			return
		}

		h.tunMu.RLock()
		toTun := h.tunActive
		h.tunMu.RUnlock()

		if toTun {
			select {
			case h.tunInCh <- pkt:
			default:
			}
			continue
		}
		select {
		case h.netInCh <- pkt:
		default:
		}
	}
}

func (h *svpnPacketHub) isClosed() bool {
	select {
	case <-h.closed:
		return true
	default:
		return false
	}
}

func (h *svpnPacketHub) tryRecoverRX(ctx context.Context, readErr error) (bool, error) {
	if errors.Is(readErr, protocol.ErrSvpnShutdown) {
		return false, readErr
	}
	if h.onLog != nil {
		h.onLog("warn", "svpn", fmt.Sprintf("rx stream interrupted (%v), attempting stream recovery", readErr))
	}

	backoffs := []time.Duration{500 * time.Millisecond, 1 * time.Second, 2 * time.Second}
	lastErr := readErr
	for _, wait := range backoffs {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-h.closed:
			timer.Stop()
			return false, errors.New("svpn packet hub closed")
		case <-timer.C:
		}

		recCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		recErr := h.svpn.ReconnectDataStreams(recCtx)
		cancel()
		if recErr == nil {
			if h.onLog != nil {
				h.onLog("info", "svpn", "L3VPN data streams recovered after transient EOF")
			}
			return true, nil
		}
		lastErr = recErr
		if errors.Is(recErr, protocol.ErrSvpnShutdown) {
			return false, recErr
		}
	}
	return false, lastErr
}

func (h *svpnPacketHub) setTunTarget(mgr *tun.Manager) {
	h.tunMu.Lock()
	h.tunActive = mgr != nil
	h.tunMu.Unlock()
}

func (h *svpnPacketHub) closeAll() error {
	h.closeOnce.Do(func() {
		close(h.closed)
	})
	return nil
}

func (h *svpnPacketHub) netstackView() proxy.PacketTransport {
	return &hubTransportView{hub: h, isTun: false, viewClosed: make(chan struct{})}
}

func (h *svpnPacketHub) tunBridgeView() tun.PacketBridge {
	return &hubTransportView{hub: h, isTun: true, viewClosed: make(chan struct{})}
}

type hubTransportView struct {
	hub        *svpnPacketHub
	isTun      bool
	viewClosed chan struct{}
	closeOnce  sync.Once
}

func (v *hubTransportView) WritePacket(pkt []byte) error {
	err := v.hub.svpn.WritePacket(pkt)
	if err != nil && v.hub.onLog != nil {
		v.hub.onLog("warn", "svpn", fmt.Sprintf("tx WritePacket failed: %v", err))
	}
	return err
}

func (v *hubTransportView) ReadPacket() ([]byte, error) {
	ch := v.hub.netInCh
	if v.isTun {
		ch = v.hub.tunInCh
	}
	select {
	case <-v.viewClosed:
		return nil, errors.New("svpn view closed")
	case <-v.hub.closed:
		return nil, errors.New("svpn packet hub closed")
	case pkt, ok := <-ch:
		if !ok {
			return nil, errors.New("svpn packet hub closed")
		}
		return pkt, nil
	}
}

func (v *hubTransportView) MTU() int {
	return v.hub.svpn.MTU()
}

func (v *hubTransportView) Close() error {
	// 仅关闭当前视图（解除协程阻塞），不销毁底层 SvpnClient，便于在系统代理与 Wintun 模式间无缝切换。
	v.closeOnce.Do(func() {
		close(v.viewClosed)
	})
	return nil
}

func defaultCampusCIDRs() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
}
