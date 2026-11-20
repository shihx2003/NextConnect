package protocol

import (
	"net"
	"net/netip"
	"testing"
)

func TestUnderlayVirtualInterfaceFiltering(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces failed: %v", err)
	}

	dialer := NewUnderlayDialer(0)
	dialer.ExcludeIP(netip.MustParseAddr("198.18.0.1"))
	candidates := dialer.candidateInterfaces()

	for _, cand := range candidates {
		if cand.Flags&net.FlagLoopback != 0 {
			t.Errorf("loopback interface should be excluded: %s", cand.Name)
		}
		if cand.Name == "Mihomo" || cand.Name == "NextConnect" {
			t.Errorf("virtual TUN interface should be excluded: %s", cand.Name)
		}
	}
	_ = ifaces
}
