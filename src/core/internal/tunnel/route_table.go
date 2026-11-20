package tunnel

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/nextconnect/core/pkg/model"
)

var (
	loopbackV4Prefix = netip.MustParsePrefix("127.0.0.0/8")
	loopbackV6Prefix = netip.MustParsePrefix("::1/128")
	linkLocalV4      = netip.MustParsePrefix("169.254.0.0/16")

	defaultCampusPrefixes = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	}

	defaultCampusDomains []string
)

// RouteDecision 描述单次目标地址分流评估的命中结果。
type RouteDecision struct {
	Action model.RuleAction `json:"action"`
	Rule   string           `json:"rule"`
}

// RouteTable 管理校园网/内网 CIDR、域名规则与分流模式（默认规则分流，按需全局）。
type RouteTable struct {
	mu             sync.RWMutex
	mode           model.RoutingMode
	gatewayHost    string
	gatewayAddrs   []netip.Addr
	builtinCIDRs   []netip.Prefix
	gatewayCIDRs   []netip.Prefix
	builtinDomains []string
	gatewayDomains []string
}

// NewRouteTable 创建一个预置通用内网私有网段规则（Rule 模式）的路由表实例，具体内网域名由网关动态下发。
func NewRouteTable() *RouteTable {
	rt := &RouteTable{
		mode:           model.RoutingModeRule,
		builtinCIDRs:   append([]netip.Prefix(nil), defaultCampusPrefixes...),
		builtinDomains: append([]string(nil), defaultCampusDomains...),
	}
	return rt
}

// SetMode 切换分流模式（rule / global）。
func (rt *RouteTable) SetMode(mode model.RoutingMode) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if mode == model.RoutingModeGlobal {
		rt.mode = model.RoutingModeGlobal
		return
	}
	rt.mode = model.RoutingModeRule
}

// Mode 返回当前生效的分流模式。
func (rt *RouteTable) Mode() model.RoutingMode {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if rt.mode == "" {
		return model.RoutingModeRule
	}
	return rt.mode
}

// SetGatewayBypass 配置必须始终直连的 VPN 网关域名与解析 IP，防止隧道自身流量回环。
func (rt *RouteTable) SetGatewayBypass(host string, addrs []netip.Addr) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.gatewayHost = strings.ToLower(strings.TrimSpace(host))
	rt.gatewayAddrs = append([]netip.Addr(nil), addrs...)
}

// LoadPrefixes 替换当前网关下发的校园网分流网段列表。
func (rt *RouteTable) LoadPrefixes(prefixes []netip.Prefix) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.gatewayCIDRs = dedupePrefixes(prefixes)
}

// LoadFromTicket 从认证后的 SessionTicket 同步网关旁路、内网 CIDR、DNS 与域名分流规则。
func (rt *RouteTable) LoadFromTicket(ticket model.SessionTicket) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if gwHost := strings.ToLower(strings.TrimSpace(ticket.GatewayHost)); gwHost != "" {
		rt.gatewayHost = gwHost
	}

	combinedCIDRs := make([]netip.Prefix, 0, len(ticket.IntranetSubnets)+len(ticket.DNSServers))
	combinedCIDRs = append(combinedCIDRs, ticket.IntranetSubnets...)
	for _, dns := range ticket.DNSServers {
		if dns.IsValid() && (dns.IsPrivate() || isCampusDNS(dns)) {
			combinedCIDRs = append(combinedCIDRs, netip.PrefixFrom(dns, dns.BitLen()))
		}
	}
	rt.gatewayCIDRs = dedupePrefixes(combinedCIDRs)

	seenDom := make(map[string]struct{})
	var domains []string
	for _, raw := range ticket.IntranetDomains {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" || d == rt.gatewayHost {
			continue
		}
		if _, ok := seenDom[d]; ok {
			continue
		}
		seenDom[d] = struct{}{}
		domains = append(domains, d)
	}
	sort.Strings(domains)
	rt.gatewayDomains = domains
}

// ShouldRouteThroughTunnel 判断目标 IP 是否应走校园网 SVPN 隧道。
func (rt *RouteTable) ShouldRouteThroughTunnel(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	return rt.MatchHost(addr.String()).Action == model.RuleActionTunnel
}

// MatchHost 根据当前分流模式与规则表决定目标主机（IP 或域名）应走隧道还是直连。
func (rt *RouteTable) MatchHost(host string) RouteDecision {
	cleaned := normalizeTargetHost(host)
	if cleaned == "" {
		return RouteDecision{Action: model.RuleActionDirect, Rule: "EMPTY-DIRECT"}
	}

	rt.mu.RLock()
	defer rt.mu.RUnlock()

	// 本地回环与链路本地地址始终直连。
	if cleaned == "localhost" {
		return RouteDecision{Action: model.RuleActionDirect, Rule: "LOCALHOST-DIRECT"}
	}
	if addr, err := netip.ParseAddr(cleaned); err == nil {
		if loopbackV4Prefix.Contains(addr) || loopbackV6Prefix.Contains(addr) || linkLocalV4.Contains(addr) {
			return RouteDecision{Action: model.RuleActionDirect, Rule: "LOOPBACK-DIRECT"}
		}
		for _, gwAddr := range rt.gatewayAddrs {
			if addr == gwAddr {
				return RouteDecision{Action: model.RuleActionDirect, Rule: "GATEWAY-BYPASS"}
			}
		}
		if rt.mode == model.RoutingModeGlobal {
			return RouteDecision{Action: model.RuleActionTunnel, Rule: "GLOBAL-TUNNEL"}
		}
		for _, pfx := range rt.gatewayCIDRs {
			if pfx.Contains(addr) {
				return RouteDecision{Action: model.RuleActionTunnel, Rule: "GATEWAY-CIDR:" + pfx.String()}
			}
		}
		for _, pfx := range rt.builtinCIDRs {
			if pfx.Contains(addr) {
				return RouteDecision{Action: model.RuleActionTunnel, Rule: "INTRANET-CIDR:" + pfx.String()}
			}
		}
		return RouteDecision{Action: model.RuleActionDirect, Rule: "DEFAULT-DIRECT"}
	}

	// VPN 网关自身域名始终直连，避免回环。
	if rt.gatewayHost != "" && cleaned == rt.gatewayHost {
		return RouteDecision{Action: model.RuleActionDirect, Rule: "GATEWAY-BYPASS"}
	}

	if rt.mode == model.RoutingModeGlobal {
		return RouteDecision{Action: model.RuleActionTunnel, Rule: "GLOBAL-TUNNEL"}
	}

	for _, pattern := range rt.builtinDomains {
		if matchDomainPattern(cleaned, pattern) {
			return RouteDecision{Action: model.RuleActionTunnel, Rule: "INTRANET-DOMAIN:" + pattern}
		}
	}
	for _, pattern := range rt.gatewayDomains {
		if matchDomainPattern(cleaned, pattern) {
			return RouteDecision{Action: model.RuleActionTunnel, Rule: "GATEWAY-DOMAIN:" + pattern}
		}
	}

	return RouteDecision{Action: model.RuleActionDirect, Rule: "DEFAULT-DIRECT"}
}

// Prefixes 返回当前生效的只读网段副本（含网关下发与预置校内 CIDR）。
func (rt *RouteTable) Prefixes() []netip.Prefix {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	combined := make([]netip.Prefix, 0, len(rt.gatewayCIDRs)+len(rt.builtinCIDRs))
	combined = append(combined, rt.gatewayCIDRs...)
	combined = append(combined, rt.builtinCIDRs...)
	return dedupePrefixes(combined)
}

// Rules 返回用于控制 API 与 PAC 生成的结构化规则清单。
func (rt *RouteTable) Rules() []model.RuleEntry {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var rules []model.RuleEntry
	if rt.gatewayHost != "" {
		rules = append(rules, model.RuleEntry{
			Type:    "DOMAIN",
			Pattern: rt.gatewayHost,
			Action:  model.RuleActionDirect,
			Source:  "gateway-bypass",
		})
	}
	for _, d := range rt.builtinDomains {
		rules = append(rules, model.RuleEntry{
			Type:    ruleTypeForDomain(d),
			Pattern: d,
			Action:  model.RuleActionTunnel,
			Source:  "builtin-intranet",
		})
	}
	for _, p := range rt.builtinCIDRs {
		rules = append(rules, model.RuleEntry{
			Type:    "IP-CIDR",
			Pattern: p.String(),
			Action:  model.RuleActionTunnel,
			Source:  "builtin-intranet",
		})
	}
	for _, d := range rt.gatewayDomains {
		rules = append(rules, model.RuleEntry{
			Type:    ruleTypeForDomain(d),
			Pattern: d,
			Action:  model.RuleActionTunnel,
			Source:  "gateway-autorule",
		})
	}
	for _, p := range rt.gatewayCIDRs {
		rules = append(rules, model.RuleEntry{
			Type:    "IP-CIDR",
			Pattern: p.String(),
			Action:  model.RuleActionTunnel,
			Source:  "gateway-rclist",
		})
	}
	return rules
}

func ruleTypeForDomain(pattern string) string {
	if strings.Contains(pattern, "*") {
		return "DOMAIN-WILDCARD"
	}
	return "DOMAIN"
}

func normalizeTargetHost(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	return s
}

// matchDomainPattern 支持精确域名及常见通配符（*.cnki.net、*d.cnki.net、*.cnki.*）。
func matchDomainPattern(host string, pattern string) bool {
	if pattern == "" || host == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return host == pattern
	}
	// 对 *.example.com 额外兼容根域名 example.com 本身，贴合代理分流习惯。
	if strings.HasPrefix(pattern, "*.") && strings.Count(pattern, "*") == 1 {
		suffix := pattern[1:] // ".example.com"
		bare := pattern[2:]   // "example.com"
		if host == bare || strings.HasSuffix(host, suffix) {
			return true
		}
		return false
	}
	return wildcardMatch(host, pattern)
}

func wildcardMatch(s string, p string) bool {
	si, pi := 0, 0
	starIdx, matchIdx := -1, 0

	for si < len(s) {
		if pi < len(p) && p[pi] == s[si] {
			si++
			pi++
		} else if pi < len(p) && p[pi] == '*' {
			starIdx = pi
			matchIdx = si
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func dedupePrefixes(in []netip.Prefix) []netip.Prefix {
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() {
			continue
		}
		m := p.Masked()
		if _, exists := seen[m]; exists {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	return out
}

func isCampusDNS(addr netip.Addr) bool {
	// 避免将公共 DNS（如 8.8.8.8 / 1.1.1.1 / 114.114.114.114）写入内网隧道路由。
	return addr.IsPrivate()
}
