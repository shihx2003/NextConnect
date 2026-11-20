package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nextconnect/core/internal/protocol"
	"github.com/nextconnect/core/pkg/model"
)

func TestEngineStartStopAndTrafficTracking(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "ENGINE-DIRECT-OK")
	}))
	defer backend.Close()

	engine := NewEngine(WithLocalProxyAddrs("127.0.0.1:0", "127.0.0.1:0"))
	defer func() {
		_ = engine.Stop(context.Background())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ticket := protocol.CreateDiagnosticTicket()
	if err := engine.Start(ctx, ticket); err != nil {
		t.Fatalf("Engine.Start failed: %v", err)
	}

	snap := engine.Snapshot()
	if snap.State != model.StateConnected || snap.RoutingMode != model.RoutingModeRule {
		t.Fatalf("unexpected initial snapshot: %+v", snap)
	}

	_, httpAddr := engine.ProxyAddrs()
	if httpAddr == "" {
		t.Fatal("expected HTTP proxy address to be populated")
	}

	proxyURL, _ := url.Parse("http://" + httpAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   3 * time.Second,
	}
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("HTTP proxy request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ENGINE-DIRECT-OK" {
		t.Fatalf("unexpected proxied body: %q", string(body))
	}

	if err := engine.Stop(context.Background()); err != nil {
		t.Fatalf("Engine.Stop failed: %v", err)
	}
	afterStop := engine.Snapshot()
	if afterStop.State != model.StateDisconnected || afterStop.ActiveCount != 0 {
		t.Fatalf("unexpected snapshot after Stop: %+v", afterStop)
	}
	if _, err := net.DialTimeout("tcp", httpAddr, 300*time.Millisecond); err == nil {
		t.Fatal("expected HTTP proxy listener to be closed after Stop")
	}
}

func TestEngineCloseConnectionAndRedactedLogs(t *testing.T) {
	engine := NewEngine(WithLocalProxyAddrs("127.0.0.1:0", "127.0.0.1:0"))
	engine.mu.Lock()
	engine.ticket.TwfID = "super_secret_twfid_1234"
	engine.mu.Unlock()

	logCh, unsub := engine.SubscribeLogs()
	defer unsub()

	engine.Log("info", "test", "session token=super_secret_twfid_1234 connected")
	select {
	case entry := <-logCh:
		if strings.Contains(entry.Message, "super_secret_twfid_1234") {
			t.Fatalf("expected TWFID to be redacted from log message: %q", entry.Message)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for log subscription")
	}

	c1, c2 := net.Pipe()
	defer c2.Close()

	tracked := engine.WrapAndTrack(c1, "127.0.0.1:5000", "10.20.30.40:5244", "TCP", "INTRANET-CIDR:10.0.0.0/8")
	conns := engine.Connections()
	if len(conns) != 1 {
		t.Fatalf("expected 1 active connection, got %d", len(conns))
	}
	if err := engine.CloseConnection(conns[0].ID); err != nil {
		t.Fatalf("CloseConnection failed: %v", err)
	}
	if len(engine.Connections()) != 0 {
		t.Fatalf("expected 0 active connections after close")
	}
	_ = tracked.Close()
}

func TestEngineRoutingModeAndPAC(t *testing.T) {
	engine := NewEngine(WithLocalProxyAddrs("127.0.0.1:0", "127.0.0.1:0"))
	engine.RouteTable().LoadFromTicket(model.SessionTicket{
		GatewayHost: "vpn.example.edu",
		IntranetSubnets: []netip.Prefix{
			netip.MustParsePrefix("198.51.100.70/32"),
		},
		IntranetDomains: []string{"*.cnki.net"},
	})

	pac := engine.PACScript()
	if !strings.Contains(pac, "*.cnki.net") || !strings.Contains(pac, "198.51.100.70") {
		t.Fatalf("expected gateway rules inside PAC: %s", pac)
	}

	engine.SetRoutingMode(model.RoutingModeGlobal)
	if engine.Snapshot().RoutingMode != model.RoutingModeGlobal {
		t.Fatalf("expected global routing mode in snapshot")
	}
	globalPAC := engine.PACScript()
	if !strings.Contains(globalPAC, "PROXY 127.0.0.1:") {
		t.Fatalf("unexpected global PAC: %s", globalPAC)
	}
}

func TestEngineWithLogWriterFilteringAndRedaction(t *testing.T) {
	var buf bytes.Buffer
	engine := NewEngine(WithLogWriter(&buf, "info"))
	engine.ticket.TwfID = "SECRET_TWFID_SAMPLE_TOKEN_1234"

	engine.Log("debug", "svpn", "suppressed debug detail")
	engine.Log("info", "auth", "authenticated twfid=SECRET_TWFID_SAMPLE_TOKEN_1234")
	engine.Log("warn", "proxy", "transient dial timeout")

	out := buf.String()
	if strings.Contains(out, "suppressed debug detail") {
		t.Fatalf("expected debug log to be filtered out at info level, got: %s", out)
	}
	if strings.Contains(out, "SECRET_TWFID_SAMPLE_TOKEN_1234") {
		t.Fatalf("expected TWFID secret to be redacted in log writer output, got: %s", out)
	}
	if !strings.Contains(out, "[INFO ] [auth      ]") || !strings.Contains(out, "[WARN ] [proxy     ]") {
		t.Fatalf("unexpected formatted log output: %s", out)
	}
}
