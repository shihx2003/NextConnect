package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nextconnect/core/pkg/model"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

type chanPacketTransport struct {
	rx     <-chan []byte
	tx     chan<- []byte
	mtu    int
	closed chan struct{}
	once   sync.Once
}

func (c *chanPacketTransport) ReadPacket() ([]byte, error) {
	select {
	case <-c.closed:
		return nil, io.EOF
	case pkt, ok := <-c.rx:
		if !ok {
			return nil, io.EOF
		}
		return pkt, nil
	}
}

func (c *chanPacketTransport) WritePacket(pkt []byte) error {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case <-c.closed:
		return io.EOF
	case c.tx <- cp:
		return nil
	default:
		return errors.New("packet channel full")
	}
}

func (c *chanPacketTransport) MTU() int { return c.mtu }

func (c *chanPacketTransport) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return nil
}

func TestNetstackTunnelL3PacketTCPEcho(t *testing.T) {
	aToB := make(chan []byte, 128)
	bToA := make(chan []byte, 128)

	transA := &chanPacketTransport{
		rx:     bToA,
		tx:     aToB,
		mtu:    1400,
		closed: make(chan struct{}),
	}
	transB := &chanPacketTransport{
		rx:     aToB,
		tx:     bToA,
		mtu:    1400,
		closed: make(chan struct{}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	clientStack, err := NewNetstackTunnel(ctx, transA, netip.MustParseAddr("10.88.0.2"), nil)
	if err != nil {
		t.Fatalf("NewNetstackTunnel client failed: %v", err)
	}
	defer clientStack.Close()

	// Simulated remote intranet host (10.20.30.40:5244) using its own gVisor stack connected via L3 packets.
	serverVIP := netip.MustParseAddr("10.20.30.40")
	serverStack, err := NewNetstackTunnel(ctx, transB, serverVIP, nil)
	if err != nil {
		t.Fatalf("NewNetstackTunnel server failed: %v", err)
	}
	defer serverStack.Close()

	ln, err := gonet.ListenTCP(serverStack.stack, tcpip.FullAddress{
		NIC:  defaultNetstackNICID,
		Port: 5244,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.ListenTCP failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		_, _ = conn.Write([]byte("ECHO:" + string(buf[:n])))
	}()

	conn, err := clientStack.DialContext(ctx, "tcp", "10.20.30.40:5244")
	if err != nil {
		t.Fatalf("clientStack.DialContext failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("HELLO-INTRANET")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	reply := make([]byte, 64)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(reply[:n]) != "ECHO:HELLO-INTRANET" {
		t.Fatalf("unexpected netstack echo reply: %q", string(reply[:n]))
	}
}

type stubRouter struct {
	mode  model.RoutingMode
	rules []model.RuleEntry
}

func (r *stubRouter) Match(host string) (model.RuleAction, string) {
	if strings.HasPrefix(host, "10.") || strings.Contains(host, "example.edu") {
		return model.RuleActionTunnel, "TEST-INTRANET"
	}
	return model.RuleActionDirect, "DEFAULT-DIRECT"
}

func (r *stubRouter) Rules() []model.RuleEntry { return r.rules }
func (r *stubRouter) Mode() model.RoutingMode  { return r.mode }

type stubDialer struct {
	targetAddr string
}

func (d *stubDialer) DialContext(ctx context.Context, network string, _ string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, d.targetAddr)
}

type stubObserver struct {
	mu      sync.Mutex
	rules   []string
	tracked int
}

func (o *stubObserver) WrapAndTrack(conn net.Conn, _ string, _ string, _ string, rule string) net.Conn {
	o.mu.Lock()
	o.tracked++
	o.rules = append(o.rules, rule)
	o.mu.Unlock()
	return conn
}

func (o *stubObserver) Log(_ string, _ string, _ string) {}

func TestSocks5AndHTTPProxyDispatchAndPAC(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "OK:"+r.URL.Path)
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	router := &stubRouter{
		mode: model.RoutingModeRule,
		rules: []model.RuleEntry{
			{Type: "DOMAIN-WILDCARD", Pattern: "*.example.edu", Action: model.RuleActionTunnel, Source: "builtin-intranet"},
			{Type: "IP-CIDR", Pattern: "10.0.0.0/8", Action: model.RuleActionTunnel, Source: "builtin-intranet"},
		},
	}
	observer := &stubObserver{}
	tunnelDialer := &stubDialer{targetAddr: backendURL.Host}

	// 1. Test SOCKS5 routing through tunnelDialer for intranet domain.
	s5 := NewSocks5Server("127.0.0.1:0", router, tunnelDialer, observer)
	s5Addr, err := s5.ListenAndServe(ctx)
	if err != nil {
		t.Fatalf("Socks5 ListenAndServe failed: %v", err)
	}
	defer s5.Close()

	rawConn, err := net.DialTimeout("tcp", s5Addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial socks5 failed: %v", err)
	}
	// Greeting: VER=5, NMETHODS=1, NOAUTH=0
	_, _ = rawConn.Write([]byte{0x05, 0x01, 0x00})
	var authResp [2]byte
	if _, err := io.ReadFull(rawConn, authResp[:]); err != nil || authResp != [2]byte{0x05, 0x00} {
		t.Fatalf("unexpected socks5 auth resp: %v %v", authResp, err)
	}
	// CONNECT to portal.example.edu:80
	hostBytes := []byte("portal.example.edu")
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(hostBytes))}, hostBytes...)
	req = append(req, 0x00, 0x50)
	_, _ = rawConn.Write(req)
	var connResp [10]byte
	if _, err := io.ReadFull(rawConn, connResp[:]); err != nil || connResp[1] != 0x00 {
		t.Fatalf("unexpected socks5 connect resp: %v %v", connResp, err)
	}
	_, _ = io.WriteString(rawConn, "GET /campus HTTP/1.1\r\nHost: portal.example.edu\r\nConnection: close\r\n\r\n")
	respBytes, _ := io.ReadAll(rawConn)
	_ = rawConn.Close()
	if !strings.Contains(string(respBytes), "OK:/campus") {
		t.Fatalf("expected backend response through socks5 tunnel, got %q", string(respBytes))
	}

	// 2. Test HTTP proxy CONNECT + /proxy.pac.
	pacFn := func() string {
		return GeneratePAC(10809, 10808, router.mode, router.rules)
	}
	hp := NewHTTPProxyServer("127.0.0.1:0", router, tunnelDialer, observer, pacFn)
	hpAddr, err := hp.ListenAndServe(ctx)
	if err != nil {
		t.Fatalf("HTTPProxyServer ListenAndServe failed: %v", err)
	}
	defer hp.Close()

	pacResp, err := http.Get("http://" + hpAddr + "/proxy.pac")
	if err != nil {
		t.Fatalf("GET /proxy.pac failed: %v", err)
	}
	pacBody, _ := io.ReadAll(pacResp.Body)
	_ = pacResp.Body.Close()
	if !strings.Contains(string(pacBody), "FindProxyForURL") || !strings.Contains(string(pacBody), "10.0.0.0") {
		t.Fatalf("unexpected PAC body: %s", string(pacBody))
	}

	proxyConn, err := net.DialTimeout("tcp", hpAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial http proxy failed: %v", err)
	}
	_, _ = io.WriteString(proxyConn, "CONNECT 10.20.30.40:5244 HTTP/1.1\r\nHost: 10.20.30.40:5244\r\n\r\n")
	br := bufio.NewReader(proxyConn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		t.Fatalf("CONNECT failed: %q err=%v", statusLine, err)
	}
	for {
		line, _ := br.ReadString('\n')
		if line == "\r\n" || line == "\n" || line == "" {
			break
		}
	}
	_, _ = io.WriteString(proxyConn, "GET /service HTTP/1.1\r\nHost: 10.20.30.40:5244\r\nConnection: close\r\n\r\n")
	httpRes, _ := io.ReadAll(br)
	_ = proxyConn.Close()
	if !strings.Contains(string(httpRes), "OK:/service") {
		t.Fatalf("expected backend response via HTTP CONNECT, got %q", string(httpRes))
	}

	observer.mu.Lock()
	tracked := observer.tracked
	observer.mu.Unlock()
	if tracked < 2 {
		t.Fatalf("expected at least 2 tracked connections, got %d", tracked)
	}
}
