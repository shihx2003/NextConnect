package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nextconnect/core/internal/tunnel"
	"github.com/nextconnect/core/pkg/model"
)

// Server 提供 Clash 风格的本地受控 REST + WebSocket API，供 Electron/React 或移动端 UI 通信。
type Server struct {
	addr       string
	engine     *tunnel.Engine
	handler    http.Handler
	httpServer *http.Server
	upgrader   websocket.Upgrader
}

type modePatchRequest struct {
	SystemProxyOn *bool              `json:"systemProxyOn"`
	TunModeOn     *bool              `json:"tunModeOn"`
	RoutingMode   *model.RoutingMode `json:"routingMode"`
}

// NewServer 创建本地控制 API 服务器。
func NewServer(addr string, engine *tunnel.Engine) *Server {
	if addr == "" {
		addr = "127.0.0.1:9090"
	}

	s := &Server{
		addr:   addr,
		engine: engine,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 4096,
			CheckOrigin: func(r *http.Request) bool {
				return isAllowedLocalOrigin(r.Header.Get("Origin"))
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", s.handleGetStatus)
	mux.HandleFunc("POST /api/v1/connect", s.handleConnect)
	mux.HandleFunc("POST /api/v1/disconnect", s.handleDisconnect)
	mux.HandleFunc("PATCH /api/v1/mode", s.handlePatchMode)
	mux.HandleFunc("GET /api/v1/rules", s.handleGetRules)
	mux.HandleFunc("GET /api/v1/connections", s.handleGetConnections)
	mux.HandleFunc("DELETE /api/v1/connections/{id}", s.handleDeleteConnection)
	mux.HandleFunc("GET /api/v1/logs", s.handleGetLogs)
	mux.HandleFunc("GET /api/v1/tun/capabilities", s.handleGetTunCapabilities)
	mux.HandleFunc("GET /api/v1/proxy.pac", s.handleGetPAC)
	mux.HandleFunc("GET /api/v1/ws/traffic", s.handleWSTraffic)
	mux.HandleFunc("GET /api/v1/ws/logs", s.handleWSLogs)

	s.handler = withLocalCORS(mux)
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// Handler 返回内部 HTTP 路由处理器（方便单元测试直接使用 httptest.NewServer）。
func (s *Server) Handler() http.Handler {
	return s.handler
}

// ListenAndServe 启动本地控制 HTTP/WebSocket 服务直至上下文取消。
func (s *Server) ListenAndServe(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("controller api server failed: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) handleGetStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.Snapshot())
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	var params tunnel.ConnectParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid connect json payload"})
		return
	}

	connectCtx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	ticket, err := s.engine.ConnectWithCredentials(connectCtx, params)
	if err != nil {
		var challenge *tunnel.AuthChallengeError
		if errors.As(err, &challenge) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"requiresSecondaryAuth": true,
				"challenge":             challenge,
			})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": s.engine.Snapshot(),
		"ticket": ticket,
	})
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.engine.Stop(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.engine.Snapshot())
}

func (s *Server) handlePatchMode(w http.ResponseWriter, r *http.Request) {
	var req modePatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	current := s.engine.Snapshot()
	sysProxy := current.SystemProxyOn
	tunMode := current.TunModeOn

	if req.SystemProxyOn != nil {
		sysProxy = *req.SystemProxyOn
	}
	if req.TunModeOn != nil {
		tunMode = *req.TunModeOn
	}
	if req.RoutingMode != nil {
		switch *req.RoutingMode {
		case model.RoutingModeRule, model.RoutingModeGlobal:
			s.engine.SetRoutingMode(*req.RoutingMode)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid routingMode: must be rule or global"})
			return
		}
	}

	if err := s.engine.ApplyModeFlags(r.Context(), sysProxy, tunMode); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  err.Error(),
			"status": s.engine.Snapshot(),
		})
		return
	}
	writeJSON(w, http.StatusOK, s.engine.Snapshot())
}

func (s *Server) handleGetTunCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.TunCapabilities())
}

func (s *Server) handleGetRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"routingMode": s.engine.RouteTable().Mode(),
		"rules":       s.engine.RouteTable().Rules(),
	})
}

func (s *Server) handleGetConnections(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"connections": s.engine.Connections(),
	})
}

func (s *Server) handleDeleteConnection(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connection id is required"})
		return
	}
	if err := s.engine.CloseConnection(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"closed": id})
}

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"logs": s.engine.RecentLogs(limit),
	})
}

func (s *Server) handleGetPAC(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(s.engine.PACScript()))
}

func (s *Server) handleWSTraffic(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	// 消费对端控制帧/关闭帧，感知客户端断连。
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		for {
			if _, _, readErr := conn.ReadMessage(); readErr != nil {
				return
			}
		}
	}()

	ch, unsubscribe := s.engine.SubscribeTraffic()
	defer unsubscribe()

	if err := writeWSJSON(conn, s.engine.Snapshot()); err != nil {
		return
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-clientDone:
			return
		case snap, ok := <-ch:
			if !ok {
				return
			}
			if err := writeWSJSON(conn, snap); err != nil {
				return
			}
		case <-ticker.C:
			if err := writeWSJSON(conn, s.engine.Snapshot()); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleWSLogs(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		for {
			if _, _, readErr := conn.ReadMessage(); readErr != nil {
				return
			}
		}
	}()

	ch, unsubscribe := s.engine.SubscribeLogs()
	defer unsubscribe()

	for _, entry := range s.engine.RecentLogs(100) {
		if err := writeWSJSON(conn, entry); err != nil {
			return
		}
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case <-clientDone:
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			if err := writeWSJSON(conn, entry); err != nil {
				return
			}
		}
	}
}

func writeWSJSON(conn *websocket.Conn, payload any) error {
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	return conn.WriteJSON(payload)
}

func isAllowedLocalOrigin(origin string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(origin))
	if trimmed == "" || trimmed == "null" || strings.HasPrefix(trimmed, "file://") || strings.HasPrefix(trimmed, "app://") {
		return true
	}
	return strings.HasPrefix(trimmed, "http://127.0.0.1") ||
		strings.HasPrefix(trimmed, "http://localhost") ||
		strings.HasPrefix(trimmed, "https://127.0.0.1") ||
		strings.HasPrefix(trimmed, "https://localhost")
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func withLocalCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
