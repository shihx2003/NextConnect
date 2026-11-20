package tun

import (
	"context"
	"net/netip"
	"sync"
	"testing"
)

type mockTunDevice struct {
	mu       sync.Mutex
	inQueue  chan []byte
	outQueue chan []byte
	closed   bool
}

func newMockTunDevice() *mockTunDevice {
	return &mockTunDevice{
		inQueue:  make(chan []byte, 4),
		outQueue: make(chan []byte, 4),
	}
}

func (d *mockTunDevice) Name() string { return "MockTun" }
func (d *mockTunDevice) LUID() uint64 { return 1 }

func (d *mockTunDevice) ReadPacket(buf []byte) (int, error) {
	pkt, ok := <-d.inQueue
	if !ok {
		return 0, ErrTunUnsupportedPlatform
	}
	n := copy(buf, pkt)
	return n, nil
}

func (d *mockTunDevice) WritePacket(pkt []byte) error {
	cp := append([]byte(nil), pkt...)
	d.outQueue <- cp
	return nil
}

func (d *mockTunDevice) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		close(d.inQueue)
	}
	return nil
}

type mockBridge struct {
	txCh      chan []byte
	rxCh      chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func (b *mockBridge) WritePacket(pkt []byte) error {
	b.txCh <- append([]byte(nil), pkt...)
	return nil
}

func (b *mockBridge) ReadPacket() ([]byte, error) {
	select {
	case <-b.closed:
		return nil, ErrTunUnsupportedPlatform
	case pkt, ok := <-b.rxCh:
		if !ok {
			return nil, ErrTunUnsupportedPlatform
		}
		return pkt, nil
	}
}

func (b *mockBridge) Close() error {
	b.closeOnce.Do(func() {
		close(b.closed)
	})
	return nil
}

func TestFilterCampusRoutesRejectsDefaultAndDuplicates(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.20.30.40/8"), // normalizes to 10.0.0.0/8
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("::/0"),
	}
	got := FilterCampusRoutes(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 filtered IPv4 campus prefixes, got %v", got)
	}
	if got[0].String() != "10.0.0.0/8" || got[1].String() != "198.51.100.0/24" {
		t.Fatalf("unexpected filtered routes: %v", got)
	}
}

func TestTunManagerBridgesIPv4AndClosesCleanly(t *testing.T) {
	dev := newMockTunDevice()
	bridge := &mockBridge{
		txCh:   make(chan []byte, 2),
		rxCh:   make(chan []byte, 2),
		closed: make(chan struct{}),
	}
	defer bridge.Close()

	mgr, err := StartBridgeWithDevice(context.Background(), dev, bridge, nil)
	if err != nil {
		t.Fatalf("StartBridgeWithDevice failed: %v", err)
	}

	sampleOut := make([]byte, 24)
	sampleOut[0] = 0x45
	sampleOut[23] = 0x42
	dev.inQueue <- sampleOut

	gotTX := <-bridge.txCh
	if len(gotTX) != 24 || gotTX[23] != 0x42 {
		t.Fatalf("unexpected bridged TX packet: %x", gotTX)
	}

	sampleIn := make([]byte, 24)
	sampleIn[0] = 0x45
	sampleIn[23] = 0x99
	bridge.rxCh <- sampleIn

	gotRX := <-dev.outQueue
	if len(gotRX) != 24 || gotRX[23] != 0x99 {
		t.Fatalf("unexpected bridged RX packet: %x", gotRX)
	}

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !dev.closed {
		t.Fatal("expected underlying tun device to be closed")
	}
}

func TestQueryCapabilitiesReturnsPlatformName(t *testing.T) {
	caps := QueryCapabilities()
	if caps.Platform == "" || caps.AdapterName == "" {
		t.Fatalf("expected non-empty capabilities metadata, got %+v", caps)
	}
}
