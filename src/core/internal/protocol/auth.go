package protocol

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/bits"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nextconnect/core/pkg/model"
	utls "github.com/refraction-networking/utls"
)

const (
	// DefaultGatewayURL 为空占位默认网关；实际使用需通过 CLI 参数（-gateway）或配置显式指定。
	DefaultGatewayURL = ""

	authProbePath     = "/por/login_auth.csp"
	authLoginPswPath  = "/por/login_psw.csp"
	authConfPath      = "/por/conf.csp"
	authRCListPath    = "/por/rclist.csp"
	authKeepAlivePath = "/por/update_session.csp"
	authLogoutPath    = "/por/logout.csp"

	// 以下为 EasyConnect 7.6.7 二次认证与硬件指纹相关端点，预留供后续阶段按需接入。
	authCaptchaPath   = "/por/rand_code.csp"
	authGetSMSPath    = "/por/get_sms.csp"
	authSMSPath       = "/por/login_sms.csp"
	authSMS1Path      = "/por/login_sms1.csp"
	authSMS2Path      = "/por/login_sms2.csp"
	authTokenPath     = "/por/login_token.csp"
	authRadiusPath    = "/por/login_radius.csp"
	authSubmitHIDPath = "/por/submithid.csp"
	authHardIDPath    = "/por/hardid.csp"

	defaultRSAExponent      = 65537
	defaultSessionLifetime  = 8 * time.Hour
	maxGatewayResponseBytes = 2 << 20
	sangforClientUserAgent  = "EasyConnect_windows"
)

// AuthType 表示网关探测或二次认证挑战识别出的认证方式类型。
type AuthType string

const (
	// AuthTypePassword 表示基于 RSA 公钥加密的标准账号密码认证。
	AuthTypePassword AuthType = "password"
	// AuthTypeCASCookie 表示统一身份认证（CAS）WebView 登录后注入 TWFID Cookie 认证。
	AuthTypeCASCookie AuthType = "cas_cookie"
	// AuthTypeSMS 表示短信验证码二次认证。
	AuthTypeSMS AuthType = "sms"
	// AuthTypeToken 表示动态口令（Token / OTP）二次认证。
	AuthTypeToken AuthType = "token"
	// AuthTypeRadius 表示 Radius 挑战二次认证。
	AuthTypeRadius AuthType = "radius"
	// AuthTypeCaptcha 表示图形验证码认证。
	AuthTypeCaptcha AuthType = "captcha"
)

// AuthProbeResult 描述网关预认证探测（/por/login_auth.csp）返回的能力与加密参数。
type AuthProbeResult struct {
	RawResult           string   `json:"rawResult"`
	NextAuth            string   `json:"nextAuth"`
	RsaModulusHex       string   `json:"rsaModulusHex"`
	RsaExponent         int      `json:"rsaExponent"`
	CSRFRandCode        string   `json:"csrfRandCode"`
	RndImg              string   `json:"rndImg"`
	PreTwfID            string   `json:"-"`
	SupportsPassword    bool     `json:"supportsPassword"`
	RequiresCASWebLogin bool     `json:"requiresCasWebLogin"`
	NeedsCaptcha        bool     `json:"needsCaptcha"`
	XMLTags             []string `json:"xmlTags,omitempty"`
}

// AuthOptions 提供账密登录时的可选附加参数（例如图形验证码及对应预认证会话令牌）。
type AuthOptions struct {
	CaptchaCode string
	PreTwfID    string
}

// SecondaryAuthRequiredError 表示主账号密码校验后网关要求继续执行二次认证。
type SecondaryAuthRequiredError struct {
	AuthType AuthType
	NextAuth string
	TwfID    string
	Message  string
}

// Error 返回对 TWFID 严格脱敏后的二次认证提示信息。
func (e *SecondaryAuthRequiredError) Error() string {
	if e == nil {
		return "secondary authentication required"
	}

	parts := make([]string, 0, 4)
	if e.AuthType != "" {
		parts = append(parts, fmt.Sprintf("type=%s", e.AuthType))
	}
	if e.NextAuth != "" {
		parts = append(parts, fmt.Sprintf("nextAuth=%s", e.NextAuth))
	}
	if e.TwfID != "" {
		parts = append(parts, fmt.Sprintf("twfid=%s", MaskCredential(e.TwfID)))
	}
	if e.Message != "" {
		parts = append(parts, fmt.Sprintf("message=%s", sanitizeSecrets(e.Message, "", e.TwfID)))
	}

	if len(parts) == 0 {
		return "secondary authentication required"
	}
	return fmt.Sprintf("secondary authentication required (%s)", strings.Join(parts, ", "))
}

// MaskCredential 对敏感凭据（如 TWFID、密码或临时令牌）进行脱敏处理，禁止完整明文输出。
func MaskCredential(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	runes := []rune(trimmed)
	n := len(runes)
	switch {
	case n <= 8:
		return "****"
	case n <= 12:
		return string(runes[:2]) + "****" + string(runes[n-2:])
	default:
		return string(runes[:4]) + "****" + string(runes[n-4:])
	}
}

// Authenticator 定义校园网网关身份认证与会话生命周期契约。
type Authenticator interface {
	// ProbeGateway 探测网关认证方式并获取预认证 RSA 公钥参数。
	ProbeGateway(ctx context.Context, gatewayURL string) (AuthProbeResult, error)
	// Authenticate 执行预认证探测、RSA 账密登录并拉取虚拟网络配置与校园网分流路由。
	Authenticate(
		ctx context.Context,
		profile model.ConnectionProfile,
		username string,
		password string,
	) (model.SessionTicket, error)
	// AuthenticateWithCookie 使用 CAS WebView 登录提取到的 TWFID Cookie 直接拉取会话配置与路由。
	AuthenticateWithCookie(
		ctx context.Context,
		profile model.ConnectionProfile,
		twfID string,
	) (model.SessionTicket, error)
	// KeepAlive 发送会话保活心跳（/por/service.csp）以维持网关登录态。
	KeepAlive(ctx context.Context, profile model.ConnectionProfile, ticket model.SessionTicket) error
	// Logout 向网关发送优雅注销请求（/por/logout.csp）释放服务端会话资源。
	Logout(ctx context.Context, profile model.ConnectionProfile, ticket model.SessionTicket) error
}

// SangforAuthenticator 实现针对 Sangfor EasyConnect v7.6.7 网关的认证客户端。
type SangforAuthenticator struct {
	httpClient      *http.Client
	fallbackClients []*http.Client
	underlayDialer  *UnderlayDialer
}

// NewSangforAuthenticator 创建 Sangfor EasyConnect 认证客户端实例。
func NewSangforAuthenticator(httpClient *http.Client) *SangforAuthenticator {
	if httpClient != nil {
		return &SangforAuthenticator{httpClient: httpClient}
	}
	underlay := NewUnderlayDialer(5 * time.Second)
	return &SangforAuthenticator{
		httpClient:     newSangforHTTPClient(underlay, true),
		underlayDialer: underlay,
		fallbackClients: []*http.Client{
			newSangforHTTPClient(underlay, false),
			newSangforUTLSHTTPClient(underlay),
		},
	}
}

func newSangforHTTPClient(underlay *UnderlayDialer, allowTLS13 bool) *http.Client {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	if !allowTLS13 {
		tlsCfg.MinVersion = tls.VersionTLS10
		tlsCfg.MaxVersion = tls.VersionTLS12
	}
	transport := &http.Transport{
		// 显式绕过环境变量代理（如本地残留 HTTP_PROXY），并通过 UnderlayDialer 直连物理网卡，避免 TUN 劫持导致 EOF。
		Proxy:                 nil,
		DialContext:           underlay.DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

func newSangforUTLSHTTPClient(underlay *UnderlayDialer) *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           underlay.DialContext,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rawConn, err := underlay.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				host = addr
			}
			uConn := utls.UClient(rawConn, &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"},
			}, utls.HelloChrome_Auto)
			if err := uConn.BuildHandshakeState(); err == nil {
				for _, ext := range uConn.Extensions {
					if alpn, ok := ext.(*utls.ALPNExtension); ok {
						alpn.AlpnProtocols = []string{"http/1.1"}
					}
				}
			}
			if err := uConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			return uConn, nil
		},
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}
}

// ProbeGateway 向指定网关发起预认证探测，解析 RSA 公钥参数与支持的认证模式。
func (a *SangforAuthenticator) ProbeGateway(ctx context.Context, gatewayURL string) (AuthProbeResult, error) {
	return a.probeGatewayWithCookie(ctx, gatewayURL, "")
}

func (a *SangforAuthenticator) probeGatewayWithCookie(
	ctx context.Context,
	gatewayURL string,
	existingTwfID string,
) (AuthProbeResult, error) {
	if err := ctx.Err(); err != nil {
		return AuthProbeResult{}, err
	}

	baseURL, err := parseGatewayBaseURL(gatewayURL)
	if err != nil {
		return AuthProbeResult{}, err
	}

	explicitPortURL := withExplicitDefaultPort(baseURL)
	normalizedExisting := normalizeTwfIDCookieValue(existingTwfID)

	type probeAttempt struct {
		targetBase     *url.URL
		minimalHeaders bool
		client         *http.Client
		delay          time.Duration
	}

	attempts := []probeAttempt{
		{
			targetBase:     baseURL,
			minimalHeaders: false,
			client:         a.httpClient,
		},
		{
			targetBase:     explicitPortURL,
			minimalHeaders: true,
			client:         a.selectClient(0),
			delay:          300 * time.Millisecond,
		},
		{
			targetBase:     explicitPortURL,
			minimalHeaders: false,
			client:         a.selectClient(1),
			delay:          700 * time.Millisecond,
		},
		{
			targetBase:     explicitPortURL,
			minimalHeaders: true,
			client:         a.httpClient,
			delay:          1200 * time.Millisecond,
		},
	}

	var respCookies []*http.Cookie
	var finalReq *http.Request
	var contentType string
	var statusCode int
	var body []byte
	var lastErr error

	for idx, att := range attempts {
		if idx > 0 {
			if err := sleepWithContext(ctx, att.delay); err != nil {
				return AuthProbeResult{}, err
			}
		}

		targetURL := buildGatewayURL(att.targetBase, authProbePath, "apiversion=1")
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if reqErr != nil {
			return AuthProbeResult{}, fmt.Errorf("failed to build probe request: %w", reqErr)
		}
		if att.minimalHeaders {
			// 对齐 zju-connect：部分网关在仅携带最小 HTTP 头与显式 :443 Host 时更稳定。
			if normalizedExisting != "" {
				req.AddCookie(&http.Cookie{Name: "TWFID", Value: normalizedExisting})
			}
		} else {
			applyPortalHeaders(req, att.targetBase)
			req.AddCookie(&http.Cookie{Name: "language", Value: "zh_CN"})
			if normalizedExisting != "" {
				req.AddCookie(&http.Cookie{Name: "TWFID", Value: normalizedExisting})
			}
		}

		statusCode, contentType, respCookies, finalReq, body, err = executeHTTPGet(att.client, req)
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err
		if ctx.Err() != nil || !isRetryableTransportError(err) {
			break
		}
	}

	if lastErr != nil {
		return AuthProbeResult{}, fmt.Errorf("gateway probe request failed: %w", sanitizeHTTPError(lastErr, ""))
	}

	if statusCode >= http.StatusBadRequest {
		return AuthProbeResult{}, fmt.Errorf("gateway probe failed with status %d", statusCode)
	}

	preTwfID := extractTwfIDFromCookies(respCookies)
	redirectedToCAS := isCASRedirectURL(finalReq)

	if looksLikeHTMLDocument(body, contentType) {
		return AuthProbeResult{
			PreTwfID:            preTwfID,
			RsaExponent:         defaultRSAExponent,
			SupportsPassword:    false,
			RequiresCASWebLogin: redirectedToCAS || looksLikeCASContent(body),
		}, nil
	}

	fields, xmlTags, err := parseXMLFieldsAndTags(body)
	if err != nil {
		if redirectedToCAS || looksLikeCASContent(body) {
			return AuthProbeResult{
				PreTwfID:            preTwfID,
				RsaExponent:         defaultRSAExponent,
				SupportsPassword:    false,
				RequiresCASWebLogin: true,
			}, nil
		}
		return AuthProbeResult{}, fmt.Errorf("failed to parse probe xml: %w", err)
	}

	if preTwfID == "" {
		preTwfID = firstNonEmptyField(fields, "twfid")
	}

	exponent, err := parseRSAExponent(firstNonEmptyField(fields, "rsa_encrypt_exp"))
	if err != nil {
		return AuthProbeResult{}, fmt.Errorf("invalid RSA_ENCRYPT_EXP in probe response: %w", err)
	}

	nextAuth := firstNonEmptyField(fields, "nextauth")
	modulusHex := strings.TrimSpace(firstNonEmptyField(fields, "rsa_encrypt_key"))
	rndImg := firstNonEmptyField(fields, "rndimg", "use_rand_code")
	csrfRandCode := firstNonEmptyField(fields, "csrf_rand_code")
	if csrfRandCode == "0" {
		csrfRandCode = ""
	}
	requiresCAS := redirectedToCAS || isCASIndicator(nextAuth)
	needsCaptcha := isSangforPositiveResult(rndImg) || isCaptchaIndicator(nextAuth)

	probe := AuthProbeResult{
		RawResult:           firstNonEmptyField(fields, "result", "errorcode"),
		NextAuth:            nextAuth,
		RsaModulusHex:       modulusHex,
		RsaExponent:         exponent,
		CSRFRandCode:        csrfRandCode,
		RndImg:              rndImg,
		PreTwfID:            preTwfID,
		SupportsPassword:    modulusHex != "" && !isCASOnlyNextAuth(nextAuth),
		RequiresCASWebLogin: requiresCAS,
		NeedsCaptcha:        needsCaptcha,
		XMLTags:             xmlTags,
	}

	return probe, nil
}

// FetchCaptcha 从网关 /por/rand_code.csp 拉取图形验证码图片及可能刷新的预认证 TWFID。
func (a *SangforAuthenticator) FetchCaptcha(
	ctx context.Context,
	gatewayURL string,
	preTwfID string,
) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	baseURL, err := parseGatewayBaseURL(gatewayURL)
	if err != nil {
		return nil, "", err
	}

	targetURL := buildGatewayURL(baseURL, authCaptchaPath, "rnd="+currentRndParam())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build captcha request: %w", err)
	}
	applyDefaultHeaders(req)
	req.Header.Set("Accept", "image/*, */*")

	normalizedPre := normalizeTwfIDCookieValue(preTwfID)
	if normalizedPre != "" {
		req.AddCookie(&http.Cookie{Name: "TWFID", Value: normalizedPre})
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("captcha request failed: %w", sanitizeHTTPError(err, "", normalizedPre))
	}
	defer resp.Body.Close()

	imgBytes, err := readLimitedBody(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read captcha response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, "", fmt.Errorf("captcha request failed with status %d", resp.StatusCode)
	}
	if len(imgBytes) == 0 {
		return nil, "", errors.New("gateway returned empty captcha image")
	}

	updatedTwfID := firstNonEmptyString(extractTwfIDFromCookies(resp.Cookies()), normalizedPre)
	return imgBytes, updatedTwfID, nil
}

// Authenticate 向目标 SSL VPN 网关发起探测与 RSA 加密账密登录，并返回完整的会话凭据。
func (a *SangforAuthenticator) Authenticate(
	ctx context.Context,
	profile model.ConnectionProfile,
	username string,
	password string,
) (model.SessionTicket, error) {
	return a.AuthenticateWithOptions(ctx, profile, username, password, AuthOptions{})
}

// AuthenticateWithOptions 支持携带图形验证码及预认证会话令牌执行 RSA 加密账密登录。
func (a *SangforAuthenticator) AuthenticateWithOptions(
	ctx context.Context,
	profile model.ConnectionProfile,
	username string,
	password string,
	opts AuthOptions,
) (model.SessionTicket, error) {
	if err := ctx.Err(); err != nil {
		return model.SessionTicket{}, err
	}
	if strings.TrimSpace(profile.GatewayURL) == "" {
		return model.SessionTicket{}, errors.New("gatewayUrl cannot be empty")
	}
	if strings.TrimSpace(username) == "" || password == "" {
		return model.SessionTicket{}, errors.New("username and password are required")
	}

	baseURL, err := parseGatewayBaseURL(profile.GatewayURL)
	if err != nil {
		return model.SessionTicket{}, err
	}

	probe, err := a.probeGatewayWithCookie(ctx, profile.GatewayURL, opts.PreTwfID)
	if err != nil {
		return model.SessionTicket{}, fmt.Errorf("gateway probe failed: %w", err)
	}

	effectivePreTwfID := firstNonEmptyString(normalizeTwfIDCookieValue(opts.PreTwfID), probe.PreTwfID)
	captchaCode := strings.TrimSpace(opts.CaptchaCode)

	if probe.RequiresCASWebLogin && !probe.SupportsPassword {
		return model.SessionTicket{}, errors.New("gateway requires CAS web login; obtain TWFID via WebView and call AuthenticateWithCookie")
	}
	if probe.RsaModulusHex == "" {
		return model.SessionTicket{}, errors.New("gateway probe response missing RSA_ENCRYPT_KEY")
	}
	if probe.NeedsCaptcha && captchaCode == "" {
		return model.SessionTicket{}, &SecondaryAuthRequiredError{
			AuthType: AuthTypeCaptcha,
			NextAuth: firstNonEmptyString(probe.NextAuth, "rand_code"),
			TwfID:    effectivePreTwfID,
			Message:  "gateway requires graphical captcha (/por/rand_code.csp)",
		}
	}

	encryptedPasswordHex, err := encryptPasswordPKCS1v15Hex(
		probe.RsaModulusHex,
		probe.RsaExponent,
		password,
		probe.CSRFRandCode,
	)
	if err != nil {
		return model.SessionTicket{}, fmt.Errorf("failed to encrypt password with gateway RSA key: %w", err)
	}

	submittedCaptcha := ""
	if captchaCode != "" {
		sum := md5.Sum([]byte(captchaCode))
		submittedCaptcha = hex.EncodeToString(sum[:])
	}

	form := url.Values{}
	form.Set("mitm_result", "")
	form.Set("svpn_req_randcode", probe.CSRFRandCode)
	form.Set("svpn_name", username)
	form.Set("svpn_password", encryptedPasswordHex)
	form.Set("svpn_rand_code", submittedCaptcha)

	loginQuery := "type=cs&language=zh_CN&encrypt=1"
	if probe.CSRFRandCode != "" {
		loginQuery = "anti_replay=1&encrypt=1&apiversion=1"
	}

	loginURL := buildGatewayURL(baseURL, authLoginPswPath, loginQuery)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return model.SessionTicket{}, fmt.Errorf("failed to build password login request: %w", err)
	}
	applyPortalHeaders(req, baseURL)
	req.Header.Set("Origin", baseURL.Scheme+"://"+baseURL.Host)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "language", Value: "zh_CN"})
	if effectivePreTwfID != "" {
		req.AddCookie(&http.Cookie{Name: "TWFID", Value: effectivePreTwfID})
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return model.SessionTicket{}, fmt.Errorf("password login request failed: %w", sanitizeHTTPError(err, password, effectivePreTwfID))
	}
	defer resp.Body.Close()

	body, err := readLimitedBody(resp.Body)
	if err != nil {
		return model.SessionTicket{}, fmt.Errorf("failed to read login response: %w", err)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return model.SessionTicket{}, fmt.Errorf("password login failed with status %d", resp.StatusCode)
	}

	cookieTwfID := extractTwfIDFromCookies(resp.Cookies())
	fields, parseErr := parseXMLFlatFields(body)
	if parseErr != nil {
		if looksLikeHTMLDocument(body, resp.Header.Get("Content-Type")) && looksLikeCASContent(body) {
			return model.SessionTicket{}, errors.New("gateway redirected login to CAS web authentication")
		}
		return model.SessionTicket{}, fmt.Errorf("failed to parse login xml response: %w", parseErr)
	}

	xmlTwfID := firstNonEmptyField(fields, "twfid")
	rawResult := firstNonEmptyField(fields, "result", "errorcode")
	nextAuth := firstNonEmptyField(fields, "nextauth")
	errMsg := firstNonEmptyField(fields, "message", "errmsg", "error")

	sessionTwfID := firstNonEmptyString(cookieTwfID, xmlTwfID)
	effectiveTwfID := firstNonEmptyString(sessionTwfID, effectivePreTwfID)

	if secType, isSecondary := classifySecondaryAuth(nextAuth); isSecondary {
		return model.SessionTicket{}, &SecondaryAuthRequiredError{
			AuthType: secType,
			NextAuth: nextAuth,
			TwfID:    effectiveTwfID,
			Message:  sanitizeSecrets(errMsg, password, effectiveTwfID, effectivePreTwfID),
		}
	}

	if !isLoginSucceeded(rawResult, sessionTwfID != "", errMsg) {
		safeMsg := sanitizeSecrets(errMsg, password, effectiveTwfID, effectivePreTwfID)
		if isCaptchaRejectionMessage(safeMsg) {
			return model.SessionTicket{}, &SecondaryAuthRequiredError{
				AuthType: AuthTypeCaptcha,
				NextAuth: firstNonEmptyString(nextAuth, "rand_code"),
				TwfID:    effectiveTwfID,
				Message:  safeMsg,
			}
		}
		if safeMsg != "" {
			return model.SessionTicket{}, fmt.Errorf("gateway authentication rejected (result=%s): %s", rawResult, safeMsg)
		}
		return model.SessionTicket{}, fmt.Errorf("gateway authentication rejected (result=%s)", rawResult)
	}

	if effectiveTwfID == "" {
		return model.SessionTicket{}, errors.New("authentication succeeded but gateway did not return TWFID")
	}

	return a.fetchSessionTicket(ctx, baseURL, effectiveTwfID)
}

// AuthenticateWithCookie 使用外部认证（如 CAS WebView）获得的 TWFID Cookie 拉取虚拟网络配置与路由表。
func (a *SangforAuthenticator) AuthenticateWithCookie(
	ctx context.Context,
	profile model.ConnectionProfile,
	twfID string,
) (model.SessionTicket, error) {
	if err := ctx.Err(); err != nil {
		return model.SessionTicket{}, err
	}
	if strings.TrimSpace(profile.GatewayURL) == "" {
		return model.SessionTicket{}, errors.New("gatewayUrl cannot be empty")
	}

	normalizedTwfID := normalizeTwfIDCookieValue(twfID)
	if normalizedTwfID == "" {
		return model.SessionTicket{}, errors.New("twfID cookie cannot be empty")
	}

	baseURL, err := parseGatewayBaseURL(profile.GatewayURL)
	if err != nil {
		return model.SessionTicket{}, err
	}

	return a.fetchSessionTicket(ctx, baseURL, normalizedTwfID)
}

// KeepAlive 向网关发送心跳包（/por/service.csp）以校验并延续当前会话有效性。
func (a *SangforAuthenticator) KeepAlive(
	ctx context.Context,
	profile model.ConnectionProfile,
	ticket model.SessionTicket,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(profile.GatewayURL) == "" {
		return errors.New("gatewayUrl cannot be empty")
	}
	twfID := normalizeTwfIDCookieValue(ticket.TwfID)
	if twfID == "" {
		return errors.New("session ticket TWFID cannot be empty")
	}

	baseURL, err := parseGatewayBaseURL(profile.GatewayURL)
	if err != nil {
		return err
	}

	targetURL := buildGatewayURL(baseURL, authKeepAlivePath, "twfid="+url.QueryEscape(twfID)+"&apiversion=1")
	statusCode, contentType, _, finalReq, body, err := a.executeGetWithRetry(ctx, func() (*http.Request, error) {
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if reqErr != nil {
			return nil, fmt.Errorf("failed to build keepalive request: %w", sanitizeHTTPError(reqErr, "", twfID))
		}
		applyPortalHeaders(req, baseURL)
		req.AddCookie(&http.Cookie{Name: "language", Value: "zh_CN"})
		req.AddCookie(&http.Cookie{Name: "TWFID", Value: twfID})
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("keepalive request failed: %w", sanitizeHTTPError(err, "", twfID))
	}

	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		return fmt.Errorf("keepalive rejected: session unauthorized (status=%d)", statusCode)
	}
	if statusCode >= http.StatusBadRequest {
		return fmt.Errorf("keepalive failed with status %d", statusCode)
	}

	if finalReq != nil && finalReq.URL != nil && !strings.HasSuffix(finalReq.URL.Path, authKeepAlivePath) {
		if looksLikeLoginRedirectPath(finalReq.URL.Path) {
			return errors.New("keepalive failed: session expired and redirected to login")
		}
	}

	if looksLikeHTMLDocument(body, contentType) {
		return errors.New("keepalive failed: session expired (gateway returned html login page)")
	}

	trimmedBody := bytes.TrimSpace(body)
	if len(trimmedBody) == 0 {
		return nil
	}

	if fields, parseErr := parseXMLFlatFields(trimmedBody); parseErr == nil {
		rawResult := firstNonEmptyField(fields, "result", "errorcode")
		errMsg := firstNonEmptyField(fields, "message", "errmsg", "error")
		if rawResult != "" && !isSangforPositiveResult(rawResult) {
			safeMsg := sanitizeSecrets(errMsg, "", twfID)
			if safeMsg != "" {
				return fmt.Errorf("keepalive failed (result=%s): %s", rawResult, safeMsg)
			}
			return fmt.Errorf("keepalive failed: session invalid (result=%s)", rawResult)
		}
		return nil
	}

	lowerText := strings.ToLower(string(trimmedBody))
	if strings.Contains(lowerText, "not login") ||
		strings.Contains(lowerText, "session expired") ||
		strings.Contains(lowerText, "invalid twfid") ||
		strings.Contains(lowerText, "unauthorized") {
		return errors.New("keepalive failed: gateway reported session expired")
	}

	return nil
}

// Logout 向网关发起优雅注销请求（/por/logout.csp）并清理服务端会话状态。
func (a *SangforAuthenticator) Logout(
	ctx context.Context,
	profile model.ConnectionProfile,
	ticket model.SessionTicket,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(profile.GatewayURL) == "" {
		return errors.New("gatewayUrl cannot be empty")
	}
	twfID := normalizeTwfIDCookieValue(ticket.TwfID)
	if twfID == "" {
		return errors.New("session ticket TWFID cannot be empty")
	}

	baseURL, err := parseGatewayBaseURL(profile.GatewayURL)
	if err != nil {
		return err
	}

	targetURL := buildGatewayURL(baseURL, authLogoutPath, "twfid="+url.QueryEscape(twfID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build logout request: %w", sanitizeHTTPError(err, "", twfID))
	}
	applyDefaultHeaders(req)
	req.AddCookie(&http.Cookie{Name: "TWFID", Value: twfID})

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("logout request failed: %w", sanitizeHTTPError(err, "", twfID))
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("logout failed with status %d", resp.StatusCode)
	}

	return nil
}

// CreateDiagnosticTicket 构造本地诊断与路由联调使用的占位会话凭据。
func CreateDiagnosticTicket() model.SessionTicket {
	return model.SessionTicket{
		TwfID:     "DIAGNOSTIC_PLACEHOLDER_TOKEN",
		VirtualIP: netip.MustParseAddr("10.255.0.2"),
		DNSServers: []netip.Addr{
			netip.MustParseAddr("10.0.0.2"),
		},
		IntranetSubnets: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
		},
		ExpiresAtUTC: time.Now().UTC().Add(8 * time.Hour),
	}
}

func (a *SangforAuthenticator) fetchSessionTicket(
	ctx context.Context,
	baseURL *url.URL,
	twfID string,
) (model.SessionTicket, error) {
	confBody, err := a.fetchAuthenticatedXML(ctx, baseURL, authConfPath, twfID)
	if err != nil {
		return model.SessionTicket{}, fmt.Errorf("failed to fetch virtual network configuration: %w", err)
	}

	rcBody, err := a.fetchAuthenticatedXML(ctx, baseURL, authRCListPath, twfID)
	if err != nil {
		return model.SessionTicket{}, fmt.Errorf("failed to fetch intranet resource list: %w", err)
	}

	ticket, err := parseSessionConfigDocuments(twfID, confBody, rcBody)
	if err != nil {
		return model.SessionTicket{}, err
	}

	if baseURL != nil {
		ticket.GatewayHost = strings.ToLower(baseURL.Hostname())
		port := DefaultGatewayPort
		if pStr := baseURL.Port(); pStr != "" {
			if p, convErr := strconv.Atoi(pStr); convErr == nil && p > 0 && p <= 65535 {
				port = p
			}
		}
		ticket.GatewayPort = port
		// 若 conf.csp 未下发 <Other sslctx>，对齐 zju-connect 从 TLS ServerHello.SessionId 构造 48B 令牌。
		if len(ticket.TunnelToken) != TunnelTokenSize && strings.EqualFold(baseURL.Scheme, "https") && len(a.fallbackClients) > 0 {
			if tok, tokErr := a.fetchServerSessionToken(ctx, baseURL, twfID); tokErr == nil && len(tok) == TunnelTokenSize {
				ticket.TunnelToken = tok
			}
		}
	}

	return ticket, nil
}

func (a *SangforAuthenticator) fetchAuthenticatedXML(
	ctx context.Context,
	baseURL *url.URL,
	path string,
	twfID string,
) ([]byte, error) {
	statusCode, contentType, _, finalReq, body, err := a.executeGetWithRetry(ctx, func() (*http.Request, error) {
		targetURL := buildGatewayURL(baseURL, path, "rnd="+currentRndParam())
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if reqErr != nil {
			return nil, fmt.Errorf("failed to build request for %s: %w", path, reqErr)
		}
		applyDefaultHeaders(req)
		req.AddCookie(&http.Cookie{Name: "TWFID", Value: twfID})
		return req, nil
	})
	if err != nil {
		return nil, sanitizeHTTPError(err, "", twfID)
	}

	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		return nil, fmt.Errorf("gateway rejected session cookie at %s (status=%d)", path, statusCode)
	}
	if statusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("gateway returned error status %d at %s", statusCode, path)
	}

	if finalReq != nil && finalReq.URL != nil && looksLikeLoginRedirectPath(finalReq.URL.Path) {
		return nil, fmt.Errorf("session cookie expired or invalid: %s redirected to login", path)
	}

	if looksLikeHTMLDocument(body, contentType) {
		return nil, fmt.Errorf("session cookie expired or invalid: %s returned html login page", path)
	}

	return body, nil
}

func (a *SangforAuthenticator) selectClient(fallbackIndex int) *http.Client {
	if fallbackIndex >= 0 && fallbackIndex < len(a.fallbackClients) && a.fallbackClients[fallbackIndex] != nil {
		return a.fallbackClients[fallbackIndex]
	}
	return a.httpClient
}

func (a *SangforAuthenticator) executeGetWithRetry(
	ctx context.Context,
	buildReq func() (*http.Request, error),
) (int, string, []*http.Cookie, *http.Request, []byte, error) {
	clients := []*http.Client{
		a.httpClient,
		a.selectClient(0),
		a.selectClient(1),
	}
	delays := []time.Duration{0, 250 * time.Millisecond, 600 * time.Millisecond}

	var lastErr error
	for i, client := range clients {
		if i > 0 {
			if err := sleepWithContext(ctx, delays[i]); err != nil {
				return 0, "", nil, nil, nil, err
			}
		}
		req, err := buildReq()
		if err != nil {
			return 0, "", nil, nil, nil, err
		}
		statusCode, contentType, cookies, finalReq, body, err := executeHTTPGet(client, req)
		if err == nil {
			return statusCode, contentType, cookies, finalReq, body, nil
		}
		lastErr = err
		if ctx.Err() != nil || !isRetryableTransportError(err) {
			break
		}
	}
	return 0, "", nil, nil, nil, lastErr
}

func executeHTTPGet(client *http.Client, req *http.Request) (int, string, []*http.Cookie, *http.Request, []byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, nil, nil, err
	}
	defer resp.Body.Close()

	body, err := readLimitedBody(resp.Body)
	if err != nil {
		return 0, "", nil, nil, nil, err
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), resp.Cookies(), resp.Request, body, nil
}

func (a *SangforAuthenticator) fetchServerSessionToken(
	ctx context.Context,
	baseURL *url.URL,
	twfID string,
) ([]byte, error) {
	host := baseURL.Hostname()
	port := DefaultGatewayPort
	if pStr := baseURL.Port(); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}
	serverAddr := net.JoinHostPort(host, strconv.Itoa(port))

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var rawConn net.Conn
	var err error
	if a.underlayDialer != nil {
		rawConn, err = a.underlayDialer.DialContext(dialCtx, "tcp", serverAddr)
	} else {
		rawConn, err = (&net.Dialer{Timeout: 10 * time.Second}).DialContext(dialCtx, "tcp", serverAddr)
	}
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	uConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}, utls.HelloGolang)
	defer uConn.Close()

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = uConn.SetDeadline(deadline)
	}
	if err := uConn.HandshakeContext(dialCtx); err != nil {
		return nil, err
	}

	reqPayload := "GET " + authConfPath + " HTTP/1.1\r\nHost: " + serverAddr +
		"\r\nCookie: TWFID=" + twfID +
		"\r\n\r\nGET " + authRCListPath + " HTTP/1.1\r\nHost: " + serverAddr +
		"\r\nCookie: TWFID=" + twfID + "\r\n\r\n"
	if _, err := io.WriteString(uConn, reqPayload); err != nil {
		return nil, err
	}

	var probeBuf [8]byte
	n, err := uConn.Read(probeBuf[:])
	if n == 0 || err != nil {
		return nil, fmt.Errorf("ecagent session token request failed: %w", err)
	}

	if uConn.HandshakeState.ServerHello == nil {
		return nil, errors.New("missing TLS ServerHello")
	}
	sidHex := hex.EncodeToString(uConn.HandshakeState.ServerHello.SessionId)
	if len(sidHex) < 31 {
		return nil, fmt.Errorf("unexpected TLS ServerHello session id length: %d", len(sidHex))
	}

	tok := make([]byte, TunnelTokenSize)
	copy(tok[:31], sidHex[:31])
	tok[31] = 0x00
	copy(tok[32:48], twfID)
	return tok, nil
}

func withExplicitDefaultPort(baseURL *url.URL) *url.URL {
	if baseURL == nil || baseURL.Port() != "" {
		return baseURL
	}
	cloned := *baseURL
	port := "443"
	if strings.EqualFold(cloned.Scheme, "http") {
		port = "80"
	}
	cloned.Host = net.JoinHostPort(cloned.Hostname(), port)
	return &cloned
}

func isRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "eof") ||
		strings.Contains(lower, "connection reset") ||
		strings.Contains(lower, "connection aborted") ||
		strings.Contains(lower, "broken pipe") ||
		strings.Contains(lower, "wsarecv") ||
		strings.Contains(lower, "wsasend") ||
		strings.Contains(lower, "tls:")
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func parseSessionConfigDocuments(twfID string, confBody []byte, rcBody []byte) (model.SessionTicket, error) {
	ticket := model.SessionTicket{
		TwfID:        twfID,
		ExpiresAtUTC: time.Now().UTC().Add(defaultSessionLifetime),
	}

	var dnsSeen = make(map[netip.Addr]struct{})
	var subnetSeen = make(map[netip.Prefix]struct{})
	var domainSeen = make(map[string]struct{})

	appendDNS := func(addr netip.Addr) {
		if !addr.IsValid() || addr.IsUnspecified() {
			return
		}
		if _, exists := dnsSeen[addr]; exists {
			return
		}
		dnsSeen[addr] = struct{}{}
		ticket.DNSServers = append(ticket.DNSServers, addr)
	}

	appendPrefix := func(prefix netip.Prefix) {
		if !prefix.IsValid() {
			return
		}
		normalized := prefix.Masked()
		if _, exists := subnetSeen[normalized]; exists {
			return
		}
		subnetSeen[normalized] = struct{}{}
		ticket.IntranetSubnets = append(ticket.IntranetSubnets, normalized)
	}

	appendDomain := func(pattern string) {
		normalized := normalizeDomainPattern(pattern)
		if normalized == "" {
			return
		}
		if _, exists := domainSeen[normalized]; exists {
			return
		}
		domainSeen[normalized] = struct{}{}
		ticket.IntranetDomains = append(ticket.IntranetDomains, normalized)
	}

	for _, doc := range []struct {
		name string
		data []byte
	}{
		{name: "conf.csp", data: confBody},
		{name: "rclist.csp", data: rcBody},
	} {
		parsed, err := parseConfigXMLDocument(doc.data)
		if err != nil {
			return model.SessionTicket{}, fmt.Errorf("failed to parse %s xml: %w", doc.name, err)
		}

		if parsed.result != "" && !isSangforPositiveResult(parsed.result) {
			safeMsg := sanitizeSecrets(parsed.errMsg, "", twfID)
			if safeMsg != "" {
				return model.SessionTicket{}, fmt.Errorf("gateway rejected session at %s (result=%s): %s", doc.name, parsed.result, safeMsg)
			}
			return model.SessionTicket{}, fmt.Errorf("gateway rejected session at %s (result=%s)", doc.name, parsed.result)
		}

		if !ticket.VirtualIP.IsValid() && parsed.virtualIP.IsValid() {
			ticket.VirtualIP = parsed.virtualIP
		}
		for _, dns := range parsed.dnsServers {
			appendDNS(dns)
		}
		for _, pfx := range parsed.subnets {
			appendPrefix(pfx)
		}
		for _, dom := range parsed.domains {
			appendDomain(dom)
		}
		if ticket.L3Eigenvalue == "" && parsed.l3Eigenvalue != "" {
			ticket.L3Eigenvalue = parsed.l3Eigenvalue
		}
		if ticket.TCPEigenvalue == "" && parsed.tcpEigenvalue != "" {
			ticket.TCPEigenvalue = parsed.tcpEigenvalue
		}
		if ticket.L3CipherSuite == "" && parsed.l3CipherSuite != "" {
			ticket.L3CipherSuite = parsed.l3CipherSuite
		}
		if ticket.TunnelMTU == 0 && parsed.tunnelMTU > 0 {
			ticket.TunnelMTU = parsed.tunnelMTU
		}
		if len(ticket.TunnelToken) == 0 && len(parsed.tunnelToken) > 0 {
			ticket.TunnelToken = parsed.tunnelToken
		}
		if parsed.timeoutSeconds > 0 {
			ticket.ExpiresAtUTC = time.Now().UTC().Add(time.Duration(parsed.timeoutSeconds) * time.Second)
		}
	}

	if !ticket.VirtualIP.IsValid() && len(ticket.DNSServers) == 0 && len(ticket.IntranetSubnets) == 0 && len(ticket.IntranetDomains) == 0 {
		return model.SessionTicket{}, errors.New("gateway returned empty virtual network configuration")
	}

	return ticket, nil
}

type parsedConfigDoc struct {
	result         string
	errMsg         string
	virtualIP      netip.Addr
	dnsServers     []netip.Addr
	subnets        []netip.Prefix
	domains        []string
	l3Eigenvalue   string
	tcpEigenvalue  string
	l3CipherSuite  string
	tunnelMTU      int
	tunnelToken    []byte
	timeoutSeconds int64
}

func parseConfigXMLDocument(data []byte) (parsedConfigDoc, error) {
	var out parsedConfigDoc
	dec := newTolerantXMLDecoder(data)

	type xmlElemState struct {
		name string
		text strings.Builder
	}

	var stack []*xmlElemState
	var parsedAnyElement bool

	hasParent := func(parentName string) bool {
		if len(stack) < 2 {
			return false
		}
		return stack[len(stack)-2].name == parentName
	}

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return parsedConfigDoc{}, err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			parsedAnyElement = true
			tagLower := strings.ToLower(t.Name.Local)
			stack = append(stack, &xmlElemState{name: tagLower})

			switch tagLower {
			case "vipaddress":
				for _, attr := range t.Attr {
					attrLower := strings.ToLower(attr.Name.Local)
					if attrLower == "ip" || attrLower == "addr" || attrLower == "address" || attrLower == "value" || attrLower == "vip" {
						if addr, ok := parseSingleOrCIDRIP(attr.Value); ok && !out.virtualIP.IsValid() {
							out.virtualIP = addr
						}
					}
				}
			case "l3vpn":
				for _, attr := range t.Attr {
					attrLower := strings.ToLower(attr.Name.Local)
					switch attrLower {
					case "iptundns", "iptundnsbak", "dns", "dnsserver":
						out.dnsServers = append(out.dnsServers, parseIPAddressTokens(attr.Value)...)
					case "vip", "ip", "vipaddress":
						if addr, ok := parseSingleOrCIDRIP(attr.Value); ok && !out.virtualIP.IsValid() {
							out.virtualIP = addr
						}
					}
				}
			case "htp":
				for _, attr := range t.Attr {
					if strings.EqualFold(attr.Name.Local, "mtu") {
						if mtu, convErr := strconv.Atoi(strings.TrimSpace(attr.Value)); convErr == nil && mtu >= 576 && mtu <= 9000 {
							out.tunnelMTU = mtu
						}
					}
				}
			case "other":
				for _, attr := range t.Attr {
					if strings.EqualFold(attr.Name.Local, "sslctx") {
						rawHex := strings.TrimSpace(attr.Value)
						if len(rawHex) >= TunnelTokenSize*2 {
							if decoded, decErr := hex.DecodeString(rawHex[:TunnelTokenSize*2]); decErr == nil && len(decoded) == TunnelTokenSize {
								out.tunnelToken = decoded
							}
						}
					}
				}
			case "autorule":
				for _, attr := range t.Attr {
					if strings.EqualFold(attr.Name.Local, "domain") {
						out.domains = append(out.domains, parseAutoruleDomainTokens(attr.Value)...)
					}
				}
			case "dns", "dnsserver":
				for _, attr := range t.Attr {
					attrLower := strings.ToLower(attr.Name.Local)
					if attrLower == "dnsserver" || attrLower == "dns" || attrLower == "server" || attrLower == "bak" || attrLower == "data" {
						out.dnsServers = append(out.dnsServers, parseIPAddressTokens(attr.Value)...)
					}
				}
			case "iplist", "rclist", "resource", "rc", "subnet", "cidr":
				for _, attr := range t.Attr {
					attrLower := strings.ToLower(attr.Name.Local)
					if attrLower == "iplist" || attrLower == "rclist" || attrLower == "ip" || attrLower == "ips" ||
						attrLower == "subnet" || attrLower == "subnets" || attrLower == "cidr" ||
						attrLower == "addr" || attrLower == "host" || attrLower == "value" {
						out.subnets = append(out.subnets, parseSubnetTokens(attr.Value)...)
						if attrLower == "host" || attrLower == "addr" || attrLower == "value" {
							out.domains = append(out.domains, parseResourceDomainTokens(attr.Value)...)
						}
					}
				}
			}

		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(t)
			}

		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			elem := stack[len(stack)-1]
			val := strings.TrimSpace(elem.text.String())
			if val == "" {
				stack = stack[:len(stack)-1]
				continue
			}

			switch elem.name {
			case "result":
				if out.result == "" {
					out.result = val
				}
			case "message", "errmsg", "error":
				if out.errMsg == "" {
					out.errMsg = val
				}
			case "vipaddress":
				if addr, ok := parseSingleOrCIDRIP(val); ok && !out.virtualIP.IsValid() {
					out.virtualIP = addr
				}
			case "dns", "dnsserver":
				out.dnsServers = append(out.dnsServers, parseIPAddressTokens(val)...)
			case "iplist", "rclist", "resource", "rc", "subnet", "cidr":
				out.subnets = append(out.subnets, parseSubnetTokens(val)...)
			case "l3vpn":
				if hasParent("ssleigenvalue") && out.l3Eigenvalue == "" {
					out.l3Eigenvalue = val
				} else if hasParent("sslciphersuite") && out.l3CipherSuite == "" {
					out.l3CipherSuite = val
				}
			case "tcp":
				if hasParent("ssleigenvalue") && out.tcpEigenvalue == "" {
					out.tcpEigenvalue = val
				}
			case "timeout", "sessiontimeout":
				if sec, convErr := strconv.ParseInt(val, 10, 64); convErr == nil && sec > 0 {
					out.timeoutSeconds = sec
				}
			}
			stack = stack[:len(stack)-1]
		}
	}

	if !parsedAnyElement {
		return parsedConfigDoc{}, errors.New("document contains no xml elements")
	}

	return out, nil
}

func parseAutoruleDomainTokens(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	var domains []string
	for _, part := range parts {
		token := normalizeDomainPattern(part)
		if token == "" || isHexMD5Hash(token) {
			continue
		}
		domains = append(domains, token)
	}
	return domains
}

func parseResourceDomainTokens(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ';' || r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	var domains []string
	for _, part := range parts {
		token := strings.TrimSpace(part)
		if token == "" || token == "*" {
			continue
		}
		host := token
		if strings.Contains(token, "://") {
			if parsedURL, err := url.Parse(token); err == nil && parsedURL.Hostname() != "" {
				host = parsedURL.Hostname()
			}
		} else {
			host = strings.SplitN(host, "/", 2)[0]
			if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
				host = h
			}
		}
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		if _, err := netip.ParsePrefix(host); err == nil {
			continue
		}
		if normalized := normalizeDomainPattern(host); normalized != "" {
			domains = append(domains, normalized)
		}
	}
	return domains
}

func normalizeDomainPattern(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimSuffix(s, ".")
	if s == "" || s == "*" || s == "*.*" {
		return ""
	}
	if strings.ContainsAny(s, ":/\\?#~") {
		return ""
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return ""
	}
	if !strings.Contains(s, ".") && !strings.Contains(s, "*") {
		return ""
	}
	return s
}

func isHexMD5Hash(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func parseXMLFlatFields(data []byte) (map[string]string, error) {
	fields, _, err := parseXMLFieldsAndTags(data)
	return fields, err
}

func parseXMLFieldsAndTags(data []byte) (map[string]string, []string, error) {
	dec := newTolerantXMLDecoder(data)
	fields := make(map[string]string)
	tagSet := make(map[string]struct{})

	type xmlElem struct {
		name string
		text strings.Builder
	}
	var stack []*xmlElem
	var parsedAnyElement bool

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}

		switch t := tok.(type) {
		case xml.StartElement:
			parsedAnyElement = true
			lowerName := strings.ToLower(t.Name.Local)
			tagSet[lowerName] = struct{}{}
			stack = append(stack, &xmlElem{name: lowerName})
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text.Write(t)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			elem := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			val := strings.TrimSpace(elem.text.String())
			if val != "" {
				if _, exists := fields[elem.name]; !exists {
					fields[elem.name] = val
				}
			}
		}
	}

	if !parsedAnyElement {
		return nil, nil, errors.New("response contains no xml elements")
	}

	tags := make([]string, 0, len(tagSet))
	for name := range tagSet {
		tags = append(tags, name)
	}
	sort.Strings(tags)

	return fields, tags, nil
}

func newTolerantXMLDecoder(data []byte) *xml.Decoder {
	clean := bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if !utf8.Valid(clean) {
		clean = bytes.ToValidUTF8(clean, []byte("?"))
	}
	dec := xml.NewDecoder(bytes.NewReader(clean))
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) {
		// 兼容声明为 GBK/GB2312/ISO-8859-1 的网关 XML 响应头。
		return input, nil
	}
	return dec
}

func encryptPasswordPKCS1v15Hex(modulusHex string, exponent int, password string, csrfRandCode string) (string, error) {
	cleanModulus := strings.TrimSpace(modulusHex)
	cleanModulus = strings.TrimPrefix(cleanModulus, "0x")
	cleanModulus = strings.TrimPrefix(cleanModulus, "0X")
	if cleanModulus == "" {
		return "", errors.New("empty RSA modulus")
	}
	if exponent < 2 {
		return "", fmt.Errorf("invalid RSA exponent %d", exponent)
	}

	modulus, ok := new(big.Int).SetString(cleanModulus, 16)
	if !ok || modulus.Sign() <= 0 {
		return "", errors.New("invalid hexadecimal RSA modulus")
	}

	pubKey := &rsa.PublicKey{
		N: modulus,
		E: exponent,
	}

	plaintext := password
	if csrfRandCode != "" {
		plaintext = password + "_" + csrfRandCode
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(plaintext))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(ciphertext), nil
}

func parseRSAExponent(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultRSAExponent, nil
	}

	base := 10
	numStr := trimmed
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		base = 16
		numStr = trimmed[2:]
	} else if containsHexAlpha(trimmed) || strings.EqualFold(trimmed, "10001") || (len(trimmed) > 1 && strings.HasPrefix(trimmed, "0")) {
		// Sangfor RSA_ENCRYPT_EXP 常为不带 0x 前缀的 16 进制字符串（如 10001 / 010001），但也兼容十进制 65537。
		base = 16
	}

	parsed, err := strconv.ParseInt(numStr, base, 32)
	if err != nil || parsed < 2 {
		return 0, fmt.Errorf("invalid rsa exponent %q", trimmed)
	}
	return int(parsed), nil
}

func containsHexAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			return true
		}
	}
	return false
}

func parseGatewayBaseURL(rawGatewayURL string) (*url.URL, error) {
	trimmed := strings.TrimSpace(rawGatewayURL)
	if trimmed == "" {
		return nil, errors.New("gatewayUrl cannot be empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid gatewayUrl: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported gatewayUrl scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, errors.New("gatewayUrl host cannot be empty")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed, nil
}

func buildGatewayURL(base *url.URL, endpointPath string, rawQuery string) string {
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + endpointPath
	u.RawQuery = rawQuery
	u.Fragment = ""
	return u.String()
}

func applyDefaultHeaders(req *http.Request) {
	req.Header.Set("User-Agent", sangforClientUserAgent)
	req.Header.Set("Accept", "application/xml, text/xml, */*")
}

func applyPortalHeaders(req *http.Request, baseURL *url.URL) {
	applyDefaultHeaders(req)
	if baseURL != nil {
		req.Header.Set("Referer", baseURL.Scheme+"://"+baseURL.Host+"/portal/")
	}
}

func extractTwfIDFromCookies(cookies []*http.Cookie) string {
	for _, c := range cookies {
		if c.Name == "TWFID" && isValidCookieCandidate(c) {
			return strings.TrimSpace(c.Value)
		}
	}
	for _, c := range cookies {
		if strings.EqualFold(c.Name, "TWFID") && isValidCookieCandidate(c) {
			return strings.TrimSpace(c.Value)
		}
	}
	return ""
}

func isValidCookieCandidate(c *http.Cookie) bool {
	if c == nil || c.MaxAge < 0 {
		return false
	}
	val := strings.TrimSpace(c.Value)
	return val != "" && !strings.EqualFold(val, "deleted")
}

func normalizeTwfIDCookieValue(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if idx := strings.IndexByte(trimmed, ';'); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[:idx])
	}
	if len(trimmed) >= 6 && strings.EqualFold(trimmed[:6], "TWFID=") {
		trimmed = strings.TrimSpace(trimmed[6:])
	}
	if strings.EqualFold(trimmed, "deleted") {
		return ""
	}
	return trimmed
}

func classifySecondaryAuth(nextAuth string) (AuthType, bool) {
	lower := strings.ToLower(strings.TrimSpace(nextAuth))
	switch lower {
	case "", "0", "1", "none", "ok", "success", "psw", "password", "auth":
		return "", false
	}

	switch {
	case strings.Contains(lower, "sms"):
		return AuthTypeSMS, true
	case strings.Contains(lower, "token"), strings.Contains(lower, "otp"):
		return AuthTypeToken, true
	case strings.Contains(lower, "radius"):
		return AuthTypeRadius, true
	case strings.Contains(lower, "rand"), strings.Contains(lower, "captcha"), strings.Contains(lower, "code"):
		return AuthTypeCaptcha, true
	case strings.Contains(lower, "cas"), strings.Contains(lower, "oauth"), strings.Contains(lower, "saml"):
		return AuthTypeCASCookie, true
	default:
		return AuthType(lower), true
	}
}

func isCASIndicator(nextAuth string) bool {
	lower := strings.ToLower(strings.TrimSpace(nextAuth))
	return strings.Contains(lower, "cas") ||
		strings.Contains(lower, "oauth") ||
		strings.Contains(lower, "saml") ||
		strings.Contains(lower, "webauth")
}

func isCaptchaIndicator(nextAuth string) bool {
	lower := strings.ToLower(strings.TrimSpace(nextAuth))
	return strings.Contains(lower, "rand") || strings.Contains(lower, "captcha")
}

func isCaptchaRejectionMessage(msg string) bool {
	lower := strings.ToLower(strings.TrimSpace(msg))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "captcha") ||
		strings.Contains(lower, "rand_code") ||
		strings.Contains(lower, "验证码")
}

func isCASOnlyNextAuth(nextAuth string) bool {
	lower := strings.ToLower(strings.TrimSpace(nextAuth))
	return lower == "cas" || lower == "cas_cookie" || lower == "oauth" || lower == "saml"
}

func isCASRedirectURL(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	lowerPath := strings.ToLower(req.URL.Path)
	lowerRaw := strings.ToLower(req.URL.String())
	if strings.HasSuffix(lowerPath, authProbePath) {
		return false
	}
	return strings.Contains(lowerRaw, "cas") ||
		strings.Contains(lowerPath, "authserver") ||
		strings.Contains(lowerPath, "sso") ||
		strings.Contains(lowerPath, "oauth")
}

func looksLikeLoginRedirectPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "login_auth") ||
		strings.Contains(lower, "login_psw") ||
		strings.Contains(lower, "/login") ||
		strings.Contains(lower, "authserver")
}

func looksLikeHTMLDocument(body []byte, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "text/html") {
		return true
	}
	sample := strings.ToLower(strings.TrimSpace(string(body)))
	if len(sample) > 512 {
		sample = sample[:512]
	}
	return strings.HasPrefix(sample, "<!doctype html") ||
		strings.HasPrefix(sample, "<html") ||
		strings.Contains(sample, "<html")
}

func looksLikeCASContent(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "cas") ||
		strings.Contains(lower, "authserver") ||
		strings.Contains(lower, "统一身份认证") ||
		strings.Contains(lower, "service=")
}

func isSangforPositiveResult(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "ok", "success":
		return true
	default:
		return false
	}
}

func isLoginSucceeded(rawResult string, hasSessionTwfID bool, errMsg string) bool {
	trimmed := strings.TrimSpace(rawResult)
	if trimmed != "" {
		return isSangforPositiveResult(trimmed)
	}
	return hasSessionTwfID && strings.TrimSpace(errMsg) == ""
}

func parseSingleOrCIDRIP(raw string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return netip.Addr{}, false
	}
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return addr.Unmap(), true
	}
	if prefix, err := netip.ParsePrefix(trimmed); err == nil {
		return prefix.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

func parseIPAddressTokens(raw string) []netip.Addr {
	tokens := splitResourceTokens(raw)
	out := make([]netip.Addr, 0, len(tokens))
	for _, tok := range tokens {
		cleaned := stripSchemeAndPort(tok)
		if addr, err := netip.ParseAddr(cleaned); err == nil {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

func parseSubnetTokens(raw string) []netip.Prefix {
	tokens := splitResourceTokens(raw)
	out := make([]netip.Prefix, 0, len(tokens))
	for _, tok := range tokens {
		cleaned := stripSchemeAndPort(tok)
		if cleaned == "" {
			continue
		}

		// 1. 标准 CIDR（如 10.0.0.0/8、2001:da8::/32）
		if prefix, err := netip.ParsePrefix(cleaned); err == nil {
			out = append(out, prefix.Masked())
			continue
		}

		// 2. IP/子网掩码形式（如 172.16.0.0/255.240.0.0）
		if strings.Contains(cleaned, "/") {
			parts := strings.SplitN(cleaned, "/", 2)
			if ip, err1 := netip.ParseAddr(strings.TrimSpace(parts[0])); err1 == nil {
				if mask, err2 := netip.ParseAddr(strings.TrimSpace(parts[1])); err2 == nil {
					if prefixLen, ok := ipv4MaskToPrefixLen(mask); ok && ip.Is4() {
						out = append(out, netip.PrefixFrom(ip, prefixLen).Masked())
						continue
					}
				}
			}
		}

		// 3. IP 范围（如 10.10.0.1-10.10.0.10 或 Sangfor rclist 的 10.10.0.1~10.10.0.10）或 IP-掩码形式
		if sep := rangeSeparator(cleaned); sep != "" {
			parts := strings.SplitN(cleaned, sep, 2)
			startIP, err1 := netip.ParseAddr(strings.TrimSpace(parts[0]))
			endIP, err2 := netip.ParseAddr(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && startIP.Is4() && endIP.Is4() {
				if sep == "-" {
					if prefixLen, ok := ipv4MaskToPrefixLen(endIP); ok && isMaskedNetworkAddress(startIP, endIP) && endIP != netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
						out = append(out, netip.PrefixFrom(startIP, prefixLen).Masked())
						continue
					}
				}
				startNum := ipv4ToUint32(startIP)
				endNum := ipv4ToUint32(endIP)
				out = append(out, ipv4RangeToPrefixes(startNum, endNum)...)
				continue
			}
		}

		// 4. 单个主机 IPv4/IPv6 地址
		if addr, err := netip.ParseAddr(cleaned); err == nil {
			unmapped := addr.Unmap()
			out = append(out, netip.PrefixFrom(unmapped, unmapped.BitLen()))
		}
	}
	return out
}

func rangeSeparator(s string) string {
	switch {
	case strings.Contains(s, "~"):
		return "~"
	case strings.Contains(s, "-"):
		return "-"
	default:
		return ""
	}
}

func splitResourceTokens(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', ';', '|', ' ', '\t', '\r', '\n':
			return true
		default:
			return false
		}
	})
}

func stripSchemeAndPort(token string) string {
	s := strings.TrimSpace(token)
	if s == "" {
		return ""
	}
	hasScheme := false
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
		hasScheme = true
	}
	if hasScheme {
		if slashIdx := strings.IndexByte(s, '/'); slashIdx >= 0 {
			s = s[:slashIdx]
		}
	}

	// 处理 [IPv6]:port 或 [IPv6]/prefix
	if strings.HasPrefix(s, "[") {
		if endBracket := strings.IndexByte(s, ']'); endBracket > 0 {
			rest := s[endBracket+1:]
			if strings.HasPrefix(rest, "/") {
				return s[1:endBracket] + rest
			}
			return s[1:endBracket]
		}
	}

	// 仅在冒号唯一（排除裸 IPv6 地址）时剥离 :port 或 :port1-port2
	if strings.Count(s, ":") == 1 {
		colonIdx := strings.IndexByte(s, ':')
		s = s[:colonIdx]
	}
	return strings.TrimSpace(s)
}

func ipv4MaskToPrefixLen(mask netip.Addr) (int, bool) {
	if !mask.Is4() {
		return 0, false
	}
	b := mask.As4()
	m := binary.BigEndian.Uint32(b[:])
	if m == 0 {
		return 0, true
	}
	inv := ^m
	// 连续子网掩码的按位取反加 1 必为 2 的幂。
	if inv&(inv+1) != 0 {
		return 0, false
	}
	return bits.LeadingZeros32(inv), true
}

func ipv4ToUint32(ip netip.Addr) uint32 {
	b := ip.As4()
	return binary.BigEndian.Uint32(b[:])
}

func isMaskedNetworkAddress(ip netip.Addr, mask netip.Addr) bool {
	ipVal := ipv4ToUint32(ip)
	maskVal := ipv4ToUint32(mask)
	return (ipVal & maskVal) == ipVal
}

func ipv4RangeToPrefixes(start, end uint32) []netip.Prefix {
	if start > end {
		return nil
	}
	var out []netip.Prefix
	for start <= end {
		maxPow := bits.TrailingZeros32(start)
		if start == 0 {
			maxPow = 32
		}
		rem := uint64(end) - uint64(start) + 1
		for maxPow > 0 && (uint64(1)<<maxPow) > rem {
			maxPow--
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], start)
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), 32-maxPow))

		block := uint64(1) << maxPow
		if uint64(start)+block > math.MaxUint32 {
			break
		}
		start += uint32(block)
	}
	return out
}

func sanitizeHTTPError(err error, password string, twfIDs ...string) error {
	if err == nil {
		return nil
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		cleanURL := sanitizeURLString(urlErr.URL, password, twfIDs...)
		innerErr := urlErr.Err
		if innerErr != nil {
			innerMsg := innerErr.Error()
			sanitizedInner := sanitizeSecrets(innerMsg, password, twfIDs...)
			if sanitizedInner != innerMsg {
				innerErr = errors.New(sanitizedInner)
			}
		}
		return &url.Error{
			Op:  urlErr.Op,
			URL: cleanURL,
			Err: innerErr,
		}
	}

	msg := err.Error()
	sanitized := sanitizeSecrets(msg, password, twfIDs...)
	if sanitized != msg {
		return errors.New(sanitized)
	}
	return err
}

func sanitizeURLString(rawURL string, password string, twfIDs ...string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return sanitizeSecrets(rawURL, password, twfIDs...)
	}
	if parsed.RawQuery != "" {
		q := parsed.Query()
		changed := false
		for key, vals := range q {
			switch strings.ToLower(key) {
			case "twfid":
				for i, v := range vals {
					q[key][i] = MaskCredential(v)
				}
				changed = true
			case "password", "svpn_password":
				for i := range vals {
					q[key][i] = "[REDACTED]"
				}
				changed = true
			}
		}
		if changed {
			parsed.RawQuery = q.Encode()
		}
	}
	return sanitizeSecrets(parsed.String(), password, twfIDs...)
}

func sanitizeSecrets(text string, password string, twfIDs ...string) string {
	cleaned := strings.TrimSpace(text)
	if cleaned == "" {
		return ""
	}
	if password != "" {
		cleaned = strings.ReplaceAll(cleaned, password, "[REDACTED]")
	}
	for _, token := range twfIDs {
		if token != "" {
			cleaned = strings.ReplaceAll(cleaned, token, MaskCredential(token))
		}
	}
	return cleaned
}

func firstNonEmptyField(fields map[string]string, keys ...string) string {
	for _, k := range keys {
		if val := strings.TrimSpace(fields[strings.ToLower(k)]); val != "" {
			return val
		}
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func readLimitedBody(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxGatewayResponseBytes))
}

func currentRndParam() string {
	return strconv.FormatInt(time.Now().UnixMilli(), 10)
}
