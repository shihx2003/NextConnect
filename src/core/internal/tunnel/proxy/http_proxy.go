package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nextconnect/core/pkg/model"
)

// HTTPProxyServer 提供基于分流路由的免驱动本地 HTTP / HTTPS CONNECT 代理服务，并可直接下发 PAC。
type HTTPProxyServer struct {
	addr         string
	router       RouteDecider
	tunnelDialer TargetDialer
	directDialer *net.Dialer
	observer     ConnObserver
	pacProvider  func() string

	mu         sync.Mutex
	httpServer *http.Server
	listener   net.Listener
	wg         sync.WaitGroup
}

// NewHTTPProxyServer 创建本地 HTTP 代理服务器实例。
func NewHTTPProxyServer(
	addr string,
	router RouteDecider,
	tunnelDialer TargetDialer,
	observer ConnObserver,
	pacProvider func() string,
) *HTTPProxyServer {
	if addr == "" {
		addr = "127.0.0.1:10809"
	}
	return &HTTPProxyServer{
		addr:         addr,
		router:       router,
		tunnelDialer: tunnelDialer,
		directDialer: &net.Dialer{Timeout: 10 * time.Second},
		observer:     observer,
		pacProvider:  pacProvider,
	}
}

// ListenAndServe 启动本地 HTTP / CONNECT 代理监听。
func (h *HTTPProxyServer) ListenAndServe(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", h.addr)
	if err != nil {
		return "", fmt.Errorf("listen http proxy on %s failed: %w", h.addr, err)
	}

	srv := &http.Server{
		Handler:           http.HandlerFunc(h.handleHTTP),
		ReadHeaderTimeout: 10 * time.Second,
	}

	h.mu.Lock()
	h.listener = ln
	h.httpServer = srv
	h.mu.Unlock()

	actualAddr := ln.Addr().String()
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		_ = srv.Serve(ln)
	}()

	return actualAddr, nil
}

// Close 停止 HTTP 代理服务器并释放监听端口。
func (h *HTTPProxyServer) Close() error {
	h.mu.Lock()
	srv := h.httpServer
	ln := h.listener
	h.httpServer = nil
	h.listener = nil
	h.mu.Unlock()

	var err error
	if srv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err = srv.Shutdown(shutdownCtx)
		cancel()
	} else if ln != nil {
		err = ln.Close()
	}
	h.wg.Wait()
	return err
}

func (h *HTTPProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && (r.URL.Path == "/proxy.pac" || r.URL.Path == "/pac") && !r.URL.IsAbs() {
		pac := ""
		if h.pacProvider != nil {
			pac = h.pacProvider()
		}
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, pac)
		return
	}

	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}

	h.handleForwardHTTP(w, r)
}

func (h *HTTPProxyServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetAddr := r.Host
	if targetAddr == "" {
		targetAddr = r.URL.Host
	}
	host := extractHostOnly(targetAddr)
	if host == "" {
		http.Error(w, "missing CONNECT target host", http.StatusBadRequest)
		return
	}
	if !strings.Contains(targetAddr, ":") {
		targetAddr = net.JoinHostPort(targetAddr, "443")
	}

	action, ruleName := h.router.Match(host)
	dialCtx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	upstream, chosenRule, err := h.dialTarget(dialCtx, targetAddr, action, ruleName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		if h.observer != nil {
			h.observer.Log("warn", "http-proxy", fmt.Sprintf("CONNECT %s via %s failed: %v", targetAddr, chosenRule, err))
		}
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, bufRW, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	defer clientConn.Close()
	defer upstream.Close()

	if _, err := bufRW.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := bufRW.Flush(); err != nil {
		return
	}

	trackedUpstream := upstream
	if h.observer != nil {
		trackedUpstream = h.observer.WrapAndTrack(
			upstream,
			r.RemoteAddr,
			targetAddr,
			"HTTPS(CONNECT)",
			chosenRule,
		)
	}

	relayBidirectional(clientConn, trackedUpstream)
}

func (h *HTTPProxyServer) handleForwardHTTP(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	if !outReq.URL.IsAbs() {
		if r.Host == "" {
			http.Error(w, "proxy request requires absolute URL or Host header", http.StatusBadRequest)
			return
		}
		outReq.URL.Scheme = "http"
		outReq.URL.Host = r.Host
	}

	host := outReq.URL.Hostname()
	targetAddr := outReq.URL.Host
	if outReq.URL.Port() == "" {
		targetAddr = net.JoinHostPort(host, "80")
	}

	outReq.RequestURI = ""
	removeHopByHopHeaders(outReq.Header)

	action, ruleName := h.router.Match(host)
	transport := &http.Transport{
		DialContext: func(dialCtx context.Context, network string, addr string) (net.Conn, error) {
			conn, chosenRule, err := h.dialTarget(dialCtx, addr, action, ruleName)
			if err != nil {
				return nil, err
			}
			if h.observer != nil {
				return h.observer.WrapAndTrack(conn, r.RemoteAddr, targetAddr, "HTTP", chosenRule), nil
			}
			return conn, nil
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		if h.observer != nil {
			h.observer.Log("warn", "http-proxy", fmt.Sprintf("HTTP %s %s failed: %v", r.Method, targetAddr, err))
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (h *HTTPProxyServer) dialTarget(
	ctx context.Context,
	targetAddr string,
	action model.RuleAction,
	ruleName string,
) (net.Conn, string, error) {
	if action == model.RuleActionTunnel && h.tunnelDialer != nil {
		conn, err := h.tunnelDialer.DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			return nil, ruleName, err
		}
		return conn, ruleName, nil
	}
	conn, err := h.directDialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, ruleName, err
	}
	if action == model.RuleActionTunnel {
		return conn, "FALLBACK-DIRECT", nil
	}
	return conn, ruleName, nil
}

func extractHostOnly(hostPort string) string {
	s := strings.TrimSpace(hostPort)
	if s == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.Trim(s, "[]")
}

func removeHopByHopHeaders(hdr http.Header) {
	for _, key := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	} {
		hdr.Del(key)
	}
}

var _ = errors.Is
