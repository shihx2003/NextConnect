package tunnel

import (
	"net/netip"
	"testing"

	"github.com/nextconnect/core/pkg/model"
)

func TestRouteTableRuleModeDefaultsAndSplitting(t *testing.T) {
	rt := NewRouteTable()
	if rt.Mode() != model.RoutingModeRule {
		t.Fatalf("expected default mode %q, got %q", model.RoutingModeRule, rt.Mode())
	}

	rt.LoadFromTicket(model.SessionTicket{
		GatewayHost: "vpn.example.edu",
		DNSServers: []netip.Addr{
			netip.MustParseAddr("10.84.1.1"),
			netip.MustParseAddr("8.8.8.8"),
		},
		IntranetSubnets: []netip.Prefix{
			netip.MustParsePrefix("198.51.100.70/32"),
		},
		IntranetDomains: []string{
			"*.example.edu",
			"*.cnki.net",
			"*.ieeexplore.ieee.org",
			"www.sciencedirect.com",
		},
	})

	cases := []struct {
		target string
		want   model.RuleAction
	}{
		{"10.20.30.40:5244", model.RuleActionTunnel}, // 私有内网测试节点（10.0.0.0/8）
		{"10.84.1.1", model.RuleActionTunnel},
		{"198.51.100.70:80", model.RuleActionTunnel},
		{"jwxt.example.edu:443", model.RuleActionTunnel},
		{"acad.cnki.net:443", model.RuleActionTunnel},
		{"ieeexplore.ieee.org", model.RuleActionTunnel},
		{"www.sciencedirect.com:443", model.RuleActionTunnel},
		{"vpn.example.edu:443", model.RuleActionDirect}, // 网关自身必须旁路直连
		{"8.8.8.8:53", model.RuleActionDirect},          // 公网 DNS 不应写入内网路由
		{"www.baidu.com:443", model.RuleActionDirect},   // 公网直连
		{"127.0.0.1:9090", model.RuleActionDirect},
	}

	for _, tc := range cases {
		dec := rt.MatchHost(tc.target)
		if dec.Action != tc.want {
			t.Errorf("MatchHost(%q) = %s (rule=%s), want %s", tc.target, dec.Action, dec.Rule, tc.want)
		}
	}
}

func TestRouteTableGlobalModeSwitch(t *testing.T) {
	rt := NewRouteTable()
	rt.SetGatewayBypass("vpn.example.edu", []netip.Addr{netip.MustParseAddr("198.51.100.1")})
	rt.SetMode(model.RoutingModeGlobal)

	if dec := rt.MatchHost("www.baidu.com:443"); dec.Action != model.RuleActionTunnel {
		t.Fatalf("expected global mode to tunnel public domain, got %+v", dec)
	}
	if dec := rt.MatchHost("vpn.example.edu:443"); dec.Action != model.RuleActionDirect {
		t.Fatalf("expected gateway host to bypass even in global mode, got %+v", dec)
	}
	if dec := rt.MatchHost("198.51.100.1:443"); dec.Action != model.RuleActionDirect {
		t.Fatalf("expected gateway IP to bypass even in global mode, got %+v", dec)
	}
	if dec := rt.MatchHost("127.0.0.1:10808"); dec.Action != model.RuleActionDirect {
		t.Fatalf("expected loopback to stay direct in global mode, got %+v", dec)
	}
}
