package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/nextconnect/core/pkg/model"
)

const (
	socks5Version        = 0x05
	socks5AuthNone       = 0x00
	socks5AuthNoAccept   = 0xFF
	socks5CmdConnect     = 0x01
	socks5AtypIPv4       = 0x01
	socks5AtypDomain     = 0x03
	socks5AtypIPv6       = 0x04
	socks5RepSuccess     = 0x00
	socks5RepFailure     = 0x01
	socks5RepCmdNotSupp  = 0x07
	socks5RepAtypNotSupp = 0x08
)

// Socks5Server 提供基于分流路由的免驱动本地 SOCKS5 代理监听。
type Socks5Server struct {
	addr         string
	router       RouteDecider
	tunnelDialer TargetDialer
	directDialer *net.Dialer
	observer     ConnObserver

	mu       sync.Mutex
	listener net.Listener
	wg       sync.WaitGroup
}

// NewSocks5Server 创建一个本地 SOCKS5 代理服务实例。
func NewSocks5Server(
	addr string,
	router RouteDecider,
	tunnelDialer TargetDialer,
	observer ConnObserver,
) *Socks5Server {
	if addr == "" {
		addr = "127.0.0.1:10808"
	}
	return &Socks5Server{
		addr:         addr,
		router:       router,
		tunnelDialer: tunnelDialer,
		directDialer: &net.Dialer{Timeout: 10 * time.Second},
		observer:     observer,
	}
}

// ListenAndServe 启动 SOCKS5 监听并在上下文取消时优雅停止。
func (s *Socks5Server) ListenAndServe(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return "", fmt.Errorf("listen socks5 on %s failed: %w", s.addr, err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	actualAddr := ln.Addr().String()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		_ = ln.Close()
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				if errors.Is(acceptErr, net.ErrClosed) || ctx.Err() != nil {
					return
				}
				continue
			}
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				s.handleConn(ctx, c)
			}(conn)
		}
	}()

	return actualAddr, nil
}

// Close 立即停止 SOCKS5 监听并等待处理协程退出。
func (s *Socks5Server) Close() error {
	s.mu.Lock()
	ln := s.listener
	s.listener = nil
	s.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	s.wg.Wait()
	return err
}

func (s *Socks5Server) handleConn(ctx context.Context, client net.Conn) {
	defer client.Close()

	if err := negotiateSocks5Auth(client); err != nil {
		return
	}

	targetHost, targetPort, err := readSocks5ConnectRequest(client)
	if err != nil {
		return
	}

	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	action, ruleName := s.router.Match(targetHost)

	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	var upstream net.Conn
	if action == model.RuleActionTunnel && s.tunnelDialer != nil {
		upstream, err = s.tunnelDialer.DialContext(dialCtx, "tcp", targetAddr)
	} else {
		upstream, err = s.directDialer.DialContext(dialCtx, "tcp", targetAddr)
		if action == model.RuleActionTunnel {
			ruleName = "FALLBACK-DIRECT"
		}
	}
	if err != nil {
		_ = writeSocks5Reply(client, socks5RepFailure)
		if s.observer != nil {
			s.observer.Log("warn", "socks5", fmt.Sprintf("dial %s via %s failed: %v", targetAddr, ruleName, err))
		}
		return
	}
	defer upstream.Close()

	if err := writeSocks5Reply(client, socks5RepSuccess); err != nil {
		return
	}

	trackedUpstream := upstream
	if s.observer != nil {
		trackedUpstream = s.observer.WrapAndTrack(
			upstream,
			client.RemoteAddr().String(),
			targetAddr,
			"SOCKS5(TCP)",
			ruleName,
		)
	}

	relayBidirectional(client, trackedUpstream)
}

func negotiateSocks5Auth(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != socks5Version {
		return fmt.Errorf("unsupported socks version %d", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == socks5AuthNone {
			_, err := conn.Write([]byte{socks5Version, socks5AuthNone})
			return err
		}
	}
	_, _ = conn.Write([]byte{socks5Version, socks5AuthNoAccept})
	return errors.New("no acceptable socks5 auth method")
}

func readSocks5ConnectRequest(conn net.Conn) (string, int, error) {
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return "", 0, err
	}
	if req[0] != socks5Version {
		return "", 0, errors.New("invalid socks5 request version")
	}
	if req[1] != socks5CmdConnect {
		_ = writeSocks5Reply(conn, socks5RepCmdNotSupp)
		return "", 0, fmt.Errorf("unsupported socks5 command 0x%02x", req[1])
	}

	var host string
	switch req[3] {
	case socks5AtypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	case socks5AtypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	case socks5AtypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return "", 0, err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, err
		}
		host = string(domain)
	default:
		_ = writeSocks5Reply(conn, socks5RepAtypNotSupp)
		return "", 0, fmt.Errorf("unsupported socks5 address type 0x%02x", req[3])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))
	return host, port, nil
}

func writeSocks5Reply(conn net.Conn, rep byte) error {
	reply := []byte{
		socks5Version, rep, 0x00, socks5AtypIPv4,
		0, 0, 0, 0, // bind IP
		0, 0, // bind Port
	}
	_, err := conn.Write(reply)
	return err
}

func relayBidirectional(left net.Conn, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copySide := func(dst net.Conn, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tcpC, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tcpC.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go copySide(right, left)
	go copySide(left, right)
	wg.Wait()
}
