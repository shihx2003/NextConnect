package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nextconnect/core/internal/api"
	"github.com/nextconnect/core/internal/protocol"
	"github.com/nextconnect/core/internal/tunnel"
	"github.com/nextconnect/core/pkg/model"
)

// 构建时可通过 -ldflags "-X main.version=... -X main.commit=... -X main.buildDate=..." 注入元信息。
var (
	version   = "0.2.0-dev"
	commit    = "local"
	buildDate = "dev"
)

type cliConfig struct {
	controllerAddr  string
	socksAddr       string
	httpAddr        string
	routingMode     string
	gatewayURL      string
	username        string
	casCookie       string
	enableTUN       bool
	logLevel        string
	logFile         string
	quiet           bool
	probeMode       bool
	authTestMode    bool
	tunnelProbeMode bool
	connectMode     bool
	showVersion     bool
}

func main() {
	cfg := parseFlags()

	if cfg.showVersion {
		printVersion()
		return
	}

	if err := validateConfig(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		flag.Usage()
		os.Exit(2)
	}

	logWriter, closeLogFile, err := buildLogWriter(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer closeLogFile()

	if logWriter != nil {
		log.SetOutput(logWriter)
	} else {
		log.SetOutput(io.Discard)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch {
	case cfg.probeMode:
		runProbeDiagnostic(ctx, cfg.gatewayURL, logWriter)
		return
	case cfg.authTestMode:
		runAuthDiagnostic(ctx, cfg, logWriter)
		return
	case cfg.tunnelProbeMode:
		runTunnelProbeDiagnostic(ctx, cfg, logWriter)
		return
	}

	engine := tunnel.NewEngine(
		tunnel.WithLocalProxyAddrs(cfg.socksAddr, cfg.httpAddr),
		tunnel.WithLogWriter(logWriter, cfg.logLevel),
	)
	if strings.EqualFold(cfg.routingMode, string(model.RoutingModeGlobal)) {
		engine.SetRoutingMode(model.RoutingModeGlobal)
	} else {
		engine.SetRoutingMode(model.RoutingModeRule)
	}

	engine.Log("info", "cli", fmt.Sprintf(
		"nextconnect-core %s starting (controller=http://%s, mode=%s, logLevel=%s, target=EasyConnect %s)",
		version, cfg.controllerAddr, engine.Snapshot().RoutingMode, cfg.logLevel, protocol.TargetProtocolVersion,
	))
	if cfg.logFile != "" {
		engine.Log("info", "cli", fmt.Sprintf("writing full logs to %s", cfg.logFile))
	}

	if cfg.connectMode {
		runHeadlessConnect(ctx, engine, cfg)
	} else {
		engine.Log("info", "cli", "controller sidecar ready; awaiting connect request via REST API /api/v1/connect")
	}

	server := api.NewServer(cfg.controllerAddr, engine)
	engine.Log("info", "api", fmt.Sprintf("controller HTTP/WS server listening on http://%s", cfg.controllerAddr))

	serveErr := server.ListenAndServe(ctx)

	engine.Log("info", "cli", "shutdown signal received, stopping tunnel and cleaning up local proxies...")
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if stopErr := engine.Stop(stopCtx); stopErr != nil {
		engine.Log("warn", "cli", fmt.Sprintf("cleanup warning during stop: %v", stopErr))
	}
	snap := engine.Snapshot()
	engine.Log("info", "cli", fmt.Sprintf("stopped cleanly (totalUpload=%dB, totalDownload=%dB)",
		snap.TotalUpload, snap.TotalDownload))

	if serveErr != nil {
		fmt.Fprintf(os.Stderr, "core terminated with error: %v\n", serveErr)
		os.Exit(1)
	}
}

func parseFlags() cliConfig {
	var cfg cliConfig

	flag.StringVar(&cfg.controllerAddr, "controller", "127.0.0.1:9090", "Local REST/WebSocket controller API listen address")
	flag.StringVar(&cfg.socksAddr, "socks", "127.0.0.1:10808", "Local SOCKS5 proxy listen address")
	flag.StringVar(&cfg.httpAddr, "http", "127.0.0.1:10809", "Local HTTP/PAC proxy listen address")
	flag.StringVar(&cfg.routingMode, "mode", string(model.RoutingModeRule), "Routing mode: rule (campus split-tunnel) or global")

	flag.StringVar(&cfg.gatewayURL, "gateway", protocol.DefaultGatewayURL, "Target Sangfor SSL VPN gateway URL (or NEXTCONNECT_GATEWAY)")
	flag.StringVar(&cfg.username, "user", "", "VPN account username (prompts if omitted in interactive mode)")
	flag.StringVar(&cfg.casCookie, "cas-cookie", "", "Optional CAS WebView session cookie (or NEXTCONNECT_CAS_COOKIE)")
	flag.BoolVar(&cfg.enableTUN, "tun", false, "Enable Wintun virtual NIC routing after -connect succeeds")

	flag.StringVar(&cfg.logLevel, "log-level", "info", "Engine log level: debug, info, warn, error")
	flag.StringVar(&cfg.logFile, "log-file", "", "Append structured engine logs to file path")
	flag.BoolVar(&cfg.quiet, "quiet", false, "Suppress engine logs on stdout (keep -log-file and /api/v1/logs)")

	flag.BoolVar(&cfg.probeMode, "probe", false, "Probe Sangfor EasyConnect gateway capabilities and exit")
	flag.BoolVar(&cfg.authTestMode, "auth-test", false, "Run Phase 1 authentication + keepalive + logout diagnostic and exit")
	flag.BoolVar(&cfg.tunnelProbeMode, "tunnel-probe", false, "Run Phase 2 authentication + Port 443 L3VPN handshake diagnostic and exit")
	flag.BoolVar(&cfg.connectMode, "connect", false, "Authenticate, establish SVPN tunnel, and serve proxies + controller")
	flag.BoolVar(&cfg.showVersion, "version", false, "Print version and build metadata and exit")

	flag.Usage = printUsage
	flag.Parse()

	if strings.TrimSpace(cfg.gatewayURL) == "" {
		cfg.gatewayURL = strings.TrimSpace(os.Getenv("NEXTCONNECT_GATEWAY"))
	}
	if strings.TrimSpace(cfg.casCookie) == "" {
		cfg.casCookie = strings.TrimSpace(os.Getenv("NEXTCONNECT_CAS_COOKIE"))
	}
	return cfg
}

func validateConfig(cfg *cliConfig) error {
	modeCount := 0
	for _, enabled := range []bool{cfg.probeMode, cfg.authTestMode, cfg.tunnelProbeMode, cfg.connectMode} {
		if enabled {
			modeCount++
		}
	}
	if modeCount > 1 {
		return errors.New("only one of -probe, -auth-test, -tunnel-probe, or -connect may be specified at a time")
	}

	if modeCount == 1 && strings.TrimSpace(cfg.gatewayURL) == "" {
		return errors.New("-gateway URL (or NEXTCONNECT_GATEWAY) is required, e.g. -gateway https://vpn.example.edu")
	}

	cfg.routingMode = strings.ToLower(strings.TrimSpace(cfg.routingMode))
	switch cfg.routingMode {
	case string(model.RoutingModeRule), string(model.RoutingModeGlobal):
	default:
		return fmt.Errorf("invalid -mode %q (expected rule or global)", cfg.routingMode)
	}

	cfg.logLevel = strings.ToLower(strings.TrimSpace(cfg.logLevel))
	switch cfg.logLevel {
	case "debug", "info", "warn", "warning", "error", "err":
	default:
		return fmt.Errorf("invalid -log-level %q (expected debug, info, warn, or error)", cfg.logLevel)
	}

	return nil
}

func buildLogWriter(cfg cliConfig) (io.Writer, func(), error) {
	var writers []io.Writer
	diagnosticCmd := cfg.probeMode || cfg.authTestMode || cfg.tunnelProbeMode
	if !cfg.quiet || diagnosticCmd {
		writers = append(writers, os.Stdout)
	}

	var f *os.File
	if strings.TrimSpace(cfg.logFile) != "" {
		if dir := filepath.Dir(cfg.logFile); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, func() {}, err
			}
		}
		var err error
		f, err = os.OpenFile(cfg.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, func() {}, err
		}
		writers = append(writers, f)
	}

	cleanup := func() {
		if f != nil {
			_ = f.Close()
		}
	}
	if len(writers) == 0 {
		return nil, cleanup, nil
	}
	if len(writers) == 1 {
		return writers[0], cleanup, nil
	}
	return io.MultiWriter(writers...), cleanup, nil
}

func printVersion() {
	fmt.Printf("nextconnect-core v%s (%s, %s/%s, protocol EasyConnect %s, commit=%s, built=%s)\n",
		version, runtime.Version(), runtime.GOOS, runtime.GOARCH, protocol.TargetProtocolVersion, commit, buildDate)
}

func printUsage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "NextConnect Core v%s — Lightweight headless Sangfor SVPN client (EasyConnect %s)\n\n",
		version, protocol.TargetProtocolVersion)
	fmt.Fprintln(out, "USAGE:")
	fmt.Fprintln(out, "  nextconnect-core [action] [options]")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "ACTIONS (default: run headless REST/WebSocket controller sidecar):")
	fmt.Fprintln(out, "  -connect          Authenticate, open Port 443 SVPN tunnel, and serve SOCKS5/HTTP/PAC + API")
	fmt.Fprintln(out, "  -probe            Probe Sangfor gateway capabilities and exit")
	fmt.Fprintln(out, "  -auth-test        Verify Phase 1 auth + keepalive + logout and exit")
	fmt.Fprintln(out, "  -tunnel-probe     Verify Phase 2 auth + SVPN L3VPN Query-IP handshake and exit")
	fmt.Fprintln(out, "  -version          Print version and build metadata and exit")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "OPTIONS:")
	flag.PrintDefaults()
	fmt.Fprintln(out)
	fmt.Fprintln(out, "ENVIRONMENT VARIABLES:")
	fmt.Fprintln(out, "  NEXTCONNECT_GATEWAY      Target VPN gateway URL if -gateway is omitted")
	fmt.Fprintln(out, "  NEXTCONNECT_TEST_PASS    Account password (if unset, CLI prompts interactively with echo off)")
	fmt.Fprintln(out, "  NEXTCONNECT_CAS_COOKIE   CAS WebView cookie override (e.g. TWFID=...)")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "EXAMPLES:")
	fmt.Fprintln(out, "  nextconnect-core -probe -gateway https://vpn.example.edu")
	fmt.Fprintln(out, "  nextconnect-core -connect -gateway https://vpn.example.edu -user <account> -mode rule -log-level debug")
	fmt.Fprintln(out, "  nextconnect-core -connect -gateway https://vpn.example.edu -user <account> -log-file nextconnect.log")
	fmt.Fprintln(out, "  nextconnect-core -controller 127.0.0.1:9090")
}

func resolveCredentials(gatewayURL, username, casCookie string) (string, string, error) {
	user := strings.TrimSpace(username)
	pass := os.Getenv("NEXTCONNECT_TEST_PASS")

	if strings.TrimSpace(casCookie) != "" && user == "" {
		return "", pass, nil
	}

	if user == "" {
		if !isStdinTerminal() {
			return "", "", errors.New("username (-user) is required in non-interactive mode")
		}
		var err error
		user, err = readPlainLine("Account username: ")
		if err != nil {
			return "", "", fmt.Errorf("read username: %w", err)
		}
		user = strings.TrimSpace(user)
		if user == "" {
			return "", "", errors.New("username cannot be empty")
		}
	}

	if pass == "" {
		if !isStdinTerminal() {
			return "", "", errors.New("password required: set NEXTCONNECT_TEST_PASS or run in an interactive terminal")
		}
		host := gatewayURL
		if parsed, err := url.Parse(gatewayURL); err == nil && parsed.Host != "" {
			host = parsed.Host
		}
		var err error
		pass, err = readPasswordWithNoEcho(fmt.Sprintf("Password for %s@%s: ", user, host))
		if err != nil {
			return "", "", fmt.Errorf("read password: %w", err)
		}
		if pass == "" {
			return "", "", errors.New("password cannot be empty")
		}
	}

	return user, pass, nil
}

func readPlainLine(prompt string) (string, error) {
	if prompt != "" {
		fmt.Fprint(os.Stderr, prompt)
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	trimmed := strings.TrimRight(line, "\r\n")
	if err != nil && trimmed == "" {
		return "", err
	}
	return trimmed, nil
}

func runProbeDiagnostic(ctx context.Context, gatewayURL string, out io.Writer) {
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	auth := protocol.NewSangforAuthenticator(nil)
	result, err := auth.ProbeGateway(probeCtx, gatewayURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gateway probe failed: %v\n", err)
		os.Exit(1)
	}

	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintf(out, "Gateway Probe Succeeded: %s\n", gatewayURL)
	fmt.Fprintf(out, "  RawResult           : %q\n", result.RawResult)
	fmt.Fprintf(out, "  SupportsPassword    : %v\n", result.SupportsPassword)
	fmt.Fprintf(out, "  RequiresCASWebLogin : %v\n", result.RequiresCASWebLogin)
	fmt.Fprintf(out, "  NeedsCaptcha        : %v (RndImg=%q)\n", result.NeedsCaptcha, result.RndImg)
	fmt.Fprintf(out, "  NextAuth            : %q\n", result.NextAuth)
	fmt.Fprintf(out, "  HasRSAKey           : %v (Exp=%d)\n", result.RsaModulusHex != "", result.RsaExponent)
	fmt.Fprintf(out, "  HasCSRFRandCode     : %v\n", result.CSRFRandCode != "")
	fmt.Fprintf(out, "  PreTwfID            : %s\n", protocol.MaskCredential(result.PreTwfID))
	fmt.Fprintf(out, "  XMLTags             : %v\n", result.XMLTags)
}

func authenticateInteractive(
	ctx context.Context,
	auth *protocol.SangforAuthenticator,
	cfg cliConfig,
) (model.ConnectionProfile, model.SessionTicket, error) {
	profile := model.ConnectionProfile{
		ProfileName: "NextConnect-CLI",
		GatewayURL:  cfg.gatewayURL,
		RoutingMode: model.RoutingModeRule,
	}

	if strings.TrimSpace(cfg.casCookie) != "" {
		ticket, err := auth.AuthenticateWithCookie(ctx, profile, cfg.casCookie)
		return profile, ticket, err
	}

	user, password, err := resolveCredentials(cfg.gatewayURL, cfg.username, cfg.casCookie)
	if err != nil {
		return model.ConnectionProfile{}, model.SessionTicket{}, err
	}

	ticket, err := auth.Authenticate(ctx, profile, user, password)
	var secErr *protocol.SecondaryAuthRequiredError
	if errors.As(err, &secErr) && secErr.AuthType == protocol.AuthTypeCaptcha {
		log.Printf("gateway requires captcha (%s), fetching challenge image...", secErr.Message)
		imgBytes, updatedTwf, capErr := auth.FetchCaptcha(ctx, cfg.gatewayURL, secErr.TwfID)
		if capErr != nil {
			return profile, model.SessionTicket{}, fmt.Errorf("failed to fetch captcha image: %w", capErr)
		}

		captchaPath, saveErr := saveCaptchaImage(imgBytes)
		if saveErr != nil {
			return profile, model.SessionTicket{}, saveErr
		}

		fmt.Fprintf(os.Stderr, "Captcha image saved to: %s\n", captchaPath)
		code, readErr := readPlainLine("Enter captcha code: ")
		if readErr != nil {
			return profile, model.SessionTicket{}, fmt.Errorf("failed to read captcha input: %w", readErr)
		}

		ticket, err = auth.AuthenticateWithOptions(
			ctx,
			profile,
			user,
			password,
			protocol.AuthOptions{
				CaptchaCode: strings.TrimSpace(code),
				PreTwfID:    updatedTwf,
			},
		)
	}
	return profile, ticket, err
}

func runAuthDiagnostic(ctx context.Context, cfg cliConfig, out io.Writer) {
	authCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	auth := protocol.NewSangforAuthenticator(nil)
	profile, ticket, err := authenticateInteractive(authCtx, auth, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authentication failed: %v\n", err)
		os.Exit(1)
	}

	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintf(out, "Authentication Succeeded!\n")
	fmt.Fprintf(out, "  TWFID (masked)  : %s\n", protocol.MaskCredential(ticket.TwfID))
	fmt.Fprintf(out, "  VirtualIP       : %v\n", ticket.VirtualIP)
	fmt.Fprintf(out, "  DNSServers      : %v\n", ticket.DNSServers)
	fmt.Fprintf(out, "  IntranetSubnets : %d prefixes\n", len(ticket.IntranetSubnets))
	fmt.Fprintf(out, "  IntranetDomains : %d rules\n", len(ticket.IntranetDomains))

	if err := auth.KeepAlive(authCtx, profile, ticket); err != nil {
		fmt.Fprintf(out, "KeepAlive check warning: %v\n", err)
	} else {
		fmt.Fprintf(out, "KeepAlive check : OK\n")
	}

	if err := auth.Logout(authCtx, profile, ticket); err != nil {
		fmt.Fprintf(out, "Logout warning  : %v\n", err)
	} else {
		fmt.Fprintf(out, "Logout cleanup  : OK\n")
	}
}

func runTunnelProbeDiagnostic(ctx context.Context, cfg cliConfig, out io.Writer) {
	probeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	auth := protocol.NewSangforAuthenticator(nil)
	profile, ticket, err := authenticateInteractive(probeCtx, auth, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authentication failed: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		logoutCtx, logoutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer logoutCancel()
		_ = auth.Logout(logoutCtx, profile, ticket)
	}()

	if out == nil {
		out = os.Stdout
	}
	fmt.Fprintf(out, "Auth OK (twfid=%s, hasTunnelToken=%v, eigenvalue=%q, cipher=%q), dialing Port %d SVPN L3VPN...\n",
		protocol.MaskCredential(ticket.TwfID), len(ticket.TunnelToken) == protocol.TunnelTokenSize, ticket.L3Eigenvalue, ticket.L3CipherSuite, ticket.GatewayPort)

	svpn := protocol.NewSvpnClient(nil)
	defer svpn.Close()

	updated, err := svpn.Connect(probeCtx, ticket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Primary SVPN Connect failed: %v\n", err)
		if errors.Is(err, protocol.ErrSvpnShutdown) {
			fmt.Fprintln(out, "Running candidate Query-IP layout probe...")
			for _, item := range svpn.ProbeQueryIPLayouts(probeCtx, ticket) {
				fmt.Fprintf(out, "  %-26s op=0x%02x vip=%v reply=%s err=%s\n",
					item.Name, item.Op, item.VirtualIP, item.ReplyHex, item.Error)
			}
		} else {
			fmt.Fprintln(out, "Running candidate TX/RX data stream layout probe...")
			vip, items := svpn.ProbeDataStreamLayouts(probeCtx, ticket)
			fmt.Fprintf(out, "  Query-IP assigned VirtualIP=%v\n", vip)
			for _, item := range items {
				fmt.Fprintf(out, "  %-26s reqOp=0x%02x replyOp=0x%02x vip=%v reply=%s err=%s\n",
					item.Name, item.ReqOp, item.ReplyOp, item.VirtualIP, item.ReplyHex, item.Error)
			}
		}
		os.Exit(1)
	}
	fmt.Fprintf(out, "SVPN L3VPN Handshake Succeeded! VirtualIP=%v MTU=%d\n", updated.VirtualIP, svpn.MTU())
}

func runHeadlessConnect(ctx context.Context, engine *tunnel.Engine, cfg cliConfig) {
	user, password, err := resolveCredentials(cfg.gatewayURL, cfg.username, cfg.casCookie)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect aborted: %v\n", err)
		os.Exit(1)
	}

	connectCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	params := tunnel.ConnectParams{
		GatewayURL:  cfg.gatewayURL,
		Username:    user,
		Password:    password,
		CASCookie:   cfg.casCookie,
		RoutingMode: cfg.routingMode,
	}

	ticket, err := engine.ConnectWithCredentials(connectCtx, params)
	var challenge *tunnel.AuthChallengeError
	if errors.As(err, &challenge) && challenge.AuthType == string(protocol.AuthTypeCaptcha) {
		auth := protocol.NewSangforAuthenticator(nil)
		imgBytes, updatedTwf, capErr := auth.FetchCaptcha(connectCtx, cfg.gatewayURL, challenge.ChallengeID)
		if capErr != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch captcha image: %v\n", capErr)
			os.Exit(1)
		}
		captchaPath, saveErr := saveCaptchaImage(imgBytes)
		if saveErr != nil {
			fmt.Fprintf(os.Stderr, "%v\n", saveErr)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Captcha image saved to: %s\n", captchaPath)
		code, _ := readPlainLine("Enter captcha code: ")

		params.CaptchaCode = strings.TrimSpace(code)
		params.PreTwfID = updatedTwf
		ticket, err = engine.ConnectWithCredentials(connectCtx, params)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect failed: %v\n", err)
		os.Exit(1)
	}

	if cfg.enableTUN {
		if tunErr := engine.ApplyModeFlags(connectCtx, true, true); tunErr != nil {
			engine.Log("warn", "tun", fmt.Sprintf("failed to enable Wintun mode via -tun flag: %v", tunErr))
		}
	}

	s5, hp := engine.ProxyAddrs()
	engine.Log("info", "cli", fmt.Sprintf(
		"Connected! VirtualIP=%v SOCKS5=%s HTTP=%s PAC=http://%s/proxy.pac",
		ticket.VirtualIP, s5, hp, hp,
	))
}

func saveCaptchaImage(imgBytes []byte) (string, error) {
	captchaDir := "."
	if exePath, exeErr := os.Executable(); exeErr == nil {
		captchaDir = filepath.Dir(exePath)
	}
	captchaName := fmt.Sprintf("captcha_%s%s", time.Now().Format("20060102_150405"), detectImageExt(imgBytes))
	captchaPath := filepath.Join(captchaDir, captchaName)
	if writeErr := os.WriteFile(captchaPath, imgBytes, 0o600); writeErr != nil {
		return "", fmt.Errorf("failed to save captcha image: %w", writeErr)
	}
	return captchaPath, nil
}

func detectImageExt(data []byte) string {
	switch {
	case bytes.HasPrefix(data, []byte{0x89, 'P', 'N', 'G'}):
		return ".png"
	case bytes.HasPrefix(data, []byte{'B', 'M'}):
		return ".bmp"
	case bytes.HasPrefix(data, []byte{'G', 'I', 'F'}):
		return ".gif"
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return ".jpg"
	default:
		return ".png"
	}
}
