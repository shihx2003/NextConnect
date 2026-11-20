package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nextconnect/core/internal/tunnel"
	"github.com/nextconnect/core/pkg/model"
)

func TestServerRESTRulesConnectionsAndPAC(t *testing.T) {
	engine := tunnel.NewEngine(tunnel.WithLocalProxyAddrs("127.0.0.1:0", "127.0.0.1:0"))
	engine.RouteTable().LoadFromTicket(model.SessionTicket{
		GatewayHost:     "vpn.example.edu",
		IntranetSubnets: []netip.Prefix{netip.MustParsePrefix("198.51.100.70/32")},
		IntranetDomains: []string{"*.cnki.net"},
	})

	srv := NewServer("127.0.0.1:9090", engine)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Check initial status (disconnected, rule mode).
	resp, err := http.Get(ts.URL + "/api/v1/status")
	if err != nil {
		t.Fatalf("GET /status failed: %v", err)
	}
	var snap model.TrafficSnapshot
	_ = json.NewDecoder(resp.Body).Decode(&snap)
	_ = resp.Body.Close()
	if snap.State != model.StateDisconnected || snap.RoutingMode != model.RoutingModeRule {
		t.Fatalf("unexpected initial status: %+v", snap)
	}

	// 2. PATCH /api/v1/mode to global & tunModeOn=true.
	patchReq, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/mode",
		bytes.NewBufferString(`{"routingMode":"global","tunModeOn":true}`))
	patchReq.Header.Set("Content-Type", "application/json")
	patchResp, err := http.DefaultClient.Do(patchReq)
	if err != nil {
		t.Fatalf("PATCH /mode failed: %v", err)
	}
	_ = json.NewDecoder(patchResp.Body).Decode(&snap)
	_ = patchResp.Body.Close()
	if snap.RoutingMode != model.RoutingModeGlobal || !snap.TunModeOn {
		t.Fatalf("unexpected patched status: %+v", snap)
	}

	// 3. GET /api/v1/rules
	rulesResp, err := http.Get(ts.URL + "/api/v1/rules")
	if err != nil {
		t.Fatalf("GET /rules failed: %v", err)
	}
	var rulesBody struct {
		RoutingMode model.RoutingMode `json:"routingMode"`
		Rules       []model.RuleEntry `json:"rules"`
	}
	_ = json.NewDecoder(rulesResp.Body).Decode(&rulesBody)
	_ = rulesResp.Body.Close()
	if len(rulesBody.Rules) == 0 {
		t.Fatal("expected non-empty rules list")
	}

	// 4. DELETE /api/v1/connections/{id}
	c1, c2 := net.Pipe()
	defer c2.Close()
	_ = engine.WrapAndTrack(c1, "127.0.0.1:4000", "10.20.30.40:5244", "SOCKS5(TCP)", "INTRANET-CIDR:10.0.0.0/8")
	conns := engine.Connections()
	if len(conns) != 1 {
		t.Fatalf("expected 1 tracked connection, got %d", len(conns))
	}
	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/connections/"+conns[0].ID, nil)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE /connections failed: %v", err)
	}
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK || len(engine.Connections()) != 0 {
		t.Fatalf("expected connection closed via DELETE API, status=%d remaining=%d",
			delResp.StatusCode, len(engine.Connections()))
	}

	// 5. GET /api/v1/proxy.pac
	pacResp, err := http.Get(ts.URL + "/api/v1/proxy.pac")
	if err != nil {
		t.Fatalf("GET /proxy.pac failed: %v", err)
	}
	var pacBuf bytes.Buffer
	_, _ = pacBuf.ReadFrom(pacResp.Body)
	_ = pacResp.Body.Close()
	if !strings.Contains(pacBuf.String(), "FindProxyForURL") {
		t.Fatalf("expected PAC script, got %q", pacBuf.String())
	}
}

func TestServerWebSocketTrafficAndLogs(t *testing.T) {
	engine := tunnel.NewEngine(tunnel.WithLocalProxyAddrs("127.0.0.1:0", "127.0.0.1:0"))
	defer func() {
		_ = engine.Stop(context.Background())
	}()

	srv := NewServer("127.0.0.1:9090", engine)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	wsBase := "ws" + strings.TrimPrefix(ts.URL, "http")

	trafficConn, _, err := websocket.DefaultDialer.Dial(wsBase+"/api/v1/ws/traffic", nil)
	if err != nil {
		t.Fatalf("dial /ws/traffic failed: %v", err)
	}
	defer trafficConn.Close()

	_ = trafficConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var snap model.TrafficSnapshot
	if err := trafficConn.ReadJSON(&snap); err != nil {
		t.Fatalf("read initial ws traffic snapshot failed: %v", err)
	}
	if snap.RoutingMode != model.RoutingModeRule {
		t.Fatalf("expected rule mode on ws snapshot, got %q", snap.RoutingMode)
	}

	engine.Log("info", "api-test", "ws log streaming check")
	logsConn, _, err := websocket.DefaultDialer.Dial(wsBase+"/api/v1/ws/logs", nil)
	if err != nil {
		t.Fatalf("dial /ws/logs failed: %v", err)
	}
	defer logsConn.Close()

	_ = logsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var entry model.LogEntry
	if err := logsConn.ReadJSON(&entry); err != nil {
		t.Fatalf("read ws log entry failed: %v", err)
	}
	if entry.Component != "api-test" || !strings.Contains(entry.Message, "ws log streaming check") {
		t.Fatalf("unexpected ws log entry: %+v", entry)
	}
}
