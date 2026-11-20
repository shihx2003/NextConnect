package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/nextconnect/core/pkg/model"
)

func TestEncodeAndDecodeSvpnHeader(t *testing.T) {
	in := SvpnHeader{
		MagicNumber:   SvpnMagicNumber,
		PayloadLength: 1380,
		Flags:         SvpnFlagData,
	}
	encoded := EncodeHeader(in)
	if len(encoded) != HeaderSizeBytes {
		t.Fatalf("unexpected encoded header length: %d", len(encoded))
	}

	out, err := DecodeHeader(encoded[:])
	if err != nil {
		t.Fatalf("DecodeHeader failed: %v", err)
	}
	if out != in {
		t.Fatalf("decoded header mismatch: got %+v, want %+v", out, in)
	}

	bad := encoded
	bad[0] = 0x00
	if _, err := DecodeHeader(bad[:]); err == nil {
		t.Fatal("expected error for invalid magic number")
	}
}

func TestBuildAndParseControlFrame(t *testing.T) {
	token, err := BuildTunnelToken("1234567890abcdef")
	if err != nil {
		t.Fatalf("BuildTunnelToken failed: %v", err)
	}
	if string(token[:16]) != "1234567890abcdef" {
		t.Fatalf("unexpected token prefix: %q", string(token[:16]))
	}
	for i := 16; i < TunnelTokenSize; i++ {
		if token[i] != 0 {
			t.Fatalf("expected zero padding at token[%d], got %d", i, token[i])
		}
	}

	vip := netip.MustParseAddr("10.88.12.34")
	cf := ControlFrame{
		Token:     token,
		Op:        ControlOpSuccess,
		VirtualIP: vip,
	}
	wire := cf.Encode()
	if len(wire) != ControlMessageSize {
		t.Fatalf("unexpected control frame size: %d", len(wire))
	}
	// Verify [0]=Op, [4:52]=token, [52:60]=0, [60:64]=reversed (LE) IPv4 bytes.
	if wire[0] != ControlOpSuccess {
		t.Fatalf("expected op 0x%02x at offset 0, got 0x%02x", ControlOpSuccess, wire[0])
	}
	for i := 52; i < 60; i++ {
		if wire[i] != 0 {
			t.Fatalf("expected zero padding at wire[%d], got 0x%02x", i, wire[i])
		}
	}
	if wire[60] != 34 || wire[61] != 12 || wire[62] != 88 || wire[63] != 10 {
		t.Fatalf("unexpected encoded reversed IPv4 byte order at [60:64]: %v", wire[60:64])
	}

	queryWire := ControlFrame{Op: ControlOpQueryIP, Token: token}.Encode()
	if queryWire[60] != 0xff || queryWire[61] != 0xff || queryWire[62] != 0xff || queryWire[63] != 0xff {
		t.Fatalf("expected Query-IP tail 0xffffffff at [60:64], got %x", queryWire[60:64])
	}

	parsed, err := ParseControlFrame(wire[:])
	if err != nil {
		t.Fatalf("ParseControlFrame failed: %v", err)
	}
	if parsed.Op != ControlOpSuccess || parsed.VirtualIP != vip || parsed.Token != token {
		t.Fatalf("parsed control frame mismatch: %+v", parsed)
	}
}

func TestBuildL3IPSessionID(t *testing.T) {
	sid := BuildL3IPSessionID(EigenvalueL3IP)
	if len(sid) != 32 {
		t.Fatalf("expected 32-byte SessionID, got %d", len(sid))
	}
	if string(sid[:4]) != "L3IP" {
		t.Fatalf("expected L3IP prefix, got %q", string(sid[:4]))
	}
	for i := 4; i < len(sid); i++ {
		if sid[i] != 0 {
			t.Fatalf("expected zero padding at sid[%d], got %d", i, sid[i])
		}
	}
}

type mockTunnelDialer struct {
	dialFn func(ctx context.Context, host string, port int, eigenvalue string, cipherHint string) (net.Conn, error)
}

func (m *mockTunnelDialer) DialTunnel(ctx context.Context, host string, port int, eigenvalue string, cipherHint string) (net.Conn, error) {
	return m.dialFn(ctx, host, port, eigenvalue, cipherHint)
}

func buildMockIPv4Packet(payload string) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], []byte{10, 99, 4, 25})
	copy(pkt[16:20], []byte{10, 95, 10, 161})
	copy(pkt[20:], payload)
	return pkt
}

func TestSvpnClientThreeStreamConnectAndRawIPv4RoundTrip(t *testing.T) {
	ctrlC, ctrlS := net.Pipe()
	rxC, rxS := net.Pipe()
	txC, txS := net.Pipe()
	defer ctrlS.Close()
	defer rxS.Close()
	defer txS.Close()

	assignedVIP := netip.MustParseAddr("10.99.4.25")
	testPacket := buildMockIPv4Packet("ALIST-5244-SYN-TEST")

	var tunnelToken [TunnelTokenSize]byte
	copy(tunnelToken[:], "0123456789abcdef0123456789abcde\x00abcdef1234567890")

	serverErrCh := make(chan error, 3)

	// 1. Control stream server (returns 36-byte reply matching real capture)
	go func() {
		var req [ControlMessageSize]byte
		if _, err := io.ReadFull(ctrlS, req[:]); err != nil {
			serverErrCh <- err
			return
		}
		cf, err := ParseControlFrame(req[:])
		if err != nil {
			serverErrCh <- err
			return
		}
		if cf.Op != ControlOpQueryIP || cf.Token != tunnelToken {
			serverErrCh <- errors.New("unexpected QueryIP frame or token")
			return
		}
		var resp [ControlReplySize]byte
		resp[0] = ControlOpSuccess
		ip4 := assignedVIP.As4()
		resp[4], resp[5], resp[6], resp[7] = ip4[3], ip4[2], ip4[1], ip4[0]
		if _, err := ctrlS.Write(resp[:]); err != nil {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	// 2. TX (0x05 -> reply 0x02) then RX (0x06 -> reply 0x01) stream handshakes + IPv4 packet bridge
	rxReady := make(chan struct{})
	go func() {
		var req [ControlMessageSize]byte
		if _, err := io.ReadFull(txS, req[:]); err != nil {
			serverErrCh <- err
			return
		}
		cf, _ := ParseControlFrame(req[:])
		if cf.Op != ControlOpDataTX || cf.VirtualIP != assignedVIP {
			serverErrCh <- errors.New("unexpected TX handshake")
			return
		}
		var ack [ControlReplySize]byte
		ack[0] = ControlOpSuccess
		if _, err := txS.Write(ack[:]); err != nil {
			serverErrCh <- err
			return
		}
		buf := make([]byte, len(testPacket))
		if _, err := io.ReadFull(txS, buf); err != nil {
			serverErrCh <- err
			return
		}
		<-rxReady
		// Send a 40-byte 0xAABB control frame first to verify ReadPacket skips it cleanly.
		var aabb [controlFrameAABBSize]byte
		aabb[0], aabb[1] = 0xAA, 0xBB
		if _, err := rxS.Write(aabb[:]); err != nil {
			serverErrCh <- err
			return
		}
		if _, err := rxS.Write(buf); err != nil {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	go func() {
		var req [ControlMessageSize]byte
		if _, err := io.ReadFull(rxS, req[:]); err != nil {
			serverErrCh <- err
			return
		}
		cf, _ := ParseControlFrame(req[:])
		if cf.Op != ControlOpDataRX || cf.VirtualIP != assignedVIP {
			serverErrCh <- errors.New("unexpected RX handshake")
			return
		}
		var ack [ControlReplySize]byte
		ack[0] = ControlOpRecvSuccess
		if _, err := rxS.Write(ack[:]); err != nil {
			serverErrCh <- err
			return
		}
		close(rxReady)
		serverErrCh <- nil
	}()

	var mu sync.Mutex
	dialIndex := 0
	var capturedEigen string
	var capturedCipher string
	client := NewSvpnClient(&mockTunnelDialer{
		dialFn: func(_ context.Context, _ string, _ int, eigenvalue string, cipherHint string) (net.Conn, error) {
			mu.Lock()
			defer mu.Unlock()
			capturedEigen = eigenvalue
			capturedCipher = cipherHint
			dialIndex++
			switch dialIndex {
			case 1:
				return ctrlC, nil
			case 2:
				return txC, nil
			case 3:
				return rxC, nil
			default:
				return nil, errors.New("unexpected extra dial")
			}
		},
	})
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ticket := model.SessionTicket{
		TwfID:         "abcdef1234567890",
		TunnelToken:   tunnelToken[:],
		GatewayHost:   "vpn.example.edu",
		GatewayPort:   443,
		L3Eigenvalue:  EigenvalueL3IP,
		L3CipherSuite: "RC4-SHA",
	}

	updated, err := client.Connect(ctx, ticket)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if capturedEigen != EigenvalueL3IP || capturedCipher != "RC4-SHA" {
		t.Fatalf("unexpected dial hints: eigen=%q cipher=%q", capturedEigen, capturedCipher)
	}
	if updated.VirtualIP != assignedVIP || client.VirtualIP() != assignedVIP {
		t.Fatalf("expected assigned VIP %v, got %v", assignedVIP, updated.VirtualIP)
	}

	if err := client.WritePacket(testPacket); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
	gotPacket, err := client.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}
	if !bytes.Equal(gotPacket, testPacket) {
		t.Fatalf("packet mismatch: got %x, want %x", gotPacket, testPacket)
	}

	for i := 0; i < 3; i++ {
		if sErr := <-serverErrCh; sErr != nil {
			t.Fatalf("mock svpn server error: %v", sErr)
		}
	}
}

func TestSvpnClientShutdownSignal(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()
	defer serverPipe.Close()

	go func() {
		var req [ControlMessageSize]byte
		_, _ = io.ReadFull(serverPipe, req[:])
		resp := ControlFrame{Op: ControlOpShutdown}.Encode()
		_, _ = serverPipe.Write(resp[:])
	}()

	client := NewSvpnClient(&mockTunnelDialer{
		dialFn: func(_ context.Context, _ string, _ int, _ string, _ string) (net.Conn, error) {
			return clientPipe, nil
		},
	})
	defer client.Close()

	_, err := client.Connect(context.Background(), model.SessionTicket{
		TwfID:       "abcdef1234567890",
		GatewayHost: "vpn.example.edu",
	})
	if !errors.Is(err, ErrSvpnShutdown) {
		t.Fatalf("expected ErrSvpnShutdown, got %v", err)
	}
}

func TestSvpnClientReconnectDataStreams(t *testing.T) {
	assignedVIP := netip.MustParseAddr("10.99.8.12")
	var token [TunnelTokenSize]byte
	copy(token[:], "0123456789abcdef0123456789abcde\x00abcdef1234567890")

	ctrlC, ctrlS := net.Pipe()
	tx1C, tx1S := net.Pipe()
	rx1C, rx1S := net.Pipe()
	tx2C, tx2S := net.Pipe()
	rx2C, rx2S := net.Pipe()
	defer ctrlS.Close()
	defer tx1S.Close()
	defer rx1S.Close()
	defer tx2S.Close()
	defer rx2S.Close()

	serveHandshake := func(conn net.Conn, expectOp uint8, replyOp uint8, withVIP bool) {
		var req [ControlMessageSize]byte
		if _, err := io.ReadFull(conn, req[:]); err != nil {
			return
		}
		var resp [ControlReplySize]byte
		resp[0] = replyOp
		if withVIP {
			ip4 := assignedVIP.As4()
			resp[4], resp[5], resp[6], resp[7] = ip4[3], ip4[2], ip4[1], ip4[0]
		}
		_, _ = conn.Write(resp[:])
	}

	go serveHandshake(ctrlS, ControlOpQueryIP, ControlOpSuccess, true)
	go serveHandshake(tx1S, ControlOpDataTX, ControlOpSuccess, false)
	go func() {
		serveHandshake(rx1S, ControlOpDataRX, ControlOpRecvSuccess, false)
		// 模拟网关在空闲后主动关闭 RX 流触发 EOF。
		_ = rx1S.Close()
	}()

	recoveredPkt := buildMockIPv4Packet("RECOVERED-AFTER-EOF")
	go serveHandshake(tx2S, ControlOpDataTX, ControlOpSuccess, false)
	go func() {
		serveHandshake(rx2S, ControlOpDataRX, ControlOpRecvSuccess, false)
		_, _ = rx2S.Write(recoveredPkt)
	}()

	var mu sync.Mutex
	var dialSeq int
	client := NewSvpnClient(&mockTunnelDialer{
		dialFn: func(_ context.Context, _ string, _ int, _ string, _ string) (net.Conn, error) {
			mu.Lock()
			defer mu.Unlock()
			dialSeq++
			switch dialSeq {
			case 1:
				return ctrlC, nil
			case 2:
				return tx1C, nil
			case 3:
				return rx1C, nil
			case 4:
				return tx2C, nil
			case 5:
				return rx2C, nil
			default:
				return nil, errors.New("unexpected dial")
			}
		},
	})
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Connect(ctx, model.SessionTicket{
		TwfID:       "abcdef1234567890",
		TunnelToken: token[:],
		GatewayHost: "vpn.example.edu",
		GatewayPort: 443,
	})
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if _, err := client.ReadPacket(); err == nil {
		t.Fatal("expected EOF error on closed initial RX stream")
	}

	if err := client.ReconnectDataStreams(ctx); err != nil {
		t.Fatalf("ReconnectDataStreams failed: %v", err)
	}

	got, err := client.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket after reconnect failed: %v", err)
	}
	if !bytes.Equal(got, recoveredPkt) {
		t.Fatalf("packet mismatch after reconnect: got %x, want %x", got, recoveredPkt)
	}
}
