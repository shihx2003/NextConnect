package protocol

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nextconnect/core/pkg/model"
)

const (
	testSyntheticUsername    = "test_student_20260001"
	testSyntheticPassword    = "Synthetic!Test#Pass99"
	testSyntheticPreTwfID    = "11223344556677889900aabbccddeeff"
	testSyntheticSessionTwf  = "ffeeddccbbaa00998877665544332211"
	testSyntheticCASTwfID    = "aa11bb22cc33dd44ee55ff6677889900"
	testSyntheticSecondTwfID = "99887766554433221100ffeeddccbbaa"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA test key: %v", err)
	}
	return key
}

func decryptSubmittedHexPassword(t *testing.T, priv *rsa.PrivateKey, hexCipher string) string {
	t.Helper()
	if hexCipher != strings.ToLower(hexCipher) {
		t.Fatalf("expected lowercase hex ciphertext, got uppercase characters")
	}
	cipherBytes, err := hex.DecodeString(hexCipher)
	if err != nil {
		t.Fatalf("expected valid hex ciphertext: %v", err)
	}
	plainBytes, err := rsa.DecryptPKCS1v15(rand.Reader, priv, cipherBytes)
	if err != nil {
		t.Fatalf("failed to decrypt RSA PKCS#1 v1.5 payload: %v", err)
	}
	return string(plainBytes)
}

func TestAuthenticateSuccessSetCookieAndXMLToken(t *testing.T) {
	privKey := generateTestRSAKey(t)
	modulusHex := strings.ToUpper(fmt.Sprintf("%x", privKey.PublicKey.N))
	const csrfCode = "748392"

	cases := []struct {
		name          string
		exponentXML   string
		csrfXML       string
		tokenInCookie bool
		expectedPlain string
		expectedTwfID string
	}{
		{
			name:          "SetCookie_TWFID_HexExponent_WithCSRF",
			exponentXML:   "10001",
			csrfXML:       csrfCode,
			tokenInCookie: true,
			expectedPlain: testSyntheticPassword + "_" + csrfCode,
			expectedTwfID: testSyntheticSessionTwf,
		},
		{
			name:          "XML_TwfId_DecimalExponent_NoCSRF",
			exponentXML:   "65537",
			csrfXML:       "",
			tokenInCookie: false,
			expectedPlain: testSyntheticPassword,
			expectedTwfID: testSyntheticSessionTwf,
		},
		{
			name:          "DefaultExponent_WhenEmpty",
			exponentXML:   "",
			csrfXML:       csrfCode,
			tokenInCookie: true,
			expectedPlain: testSyntheticPassword + "_" + csrfCode,
			expectedTwfID: testSyntheticSessionTwf,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sawProbe, sawLogin, sawConf, sawRCList bool

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case authProbePath:
					sawProbe = true
					q := r.URL.Query()
					if q.Get("apiversion") != "1" {
						t.Errorf("unexpected probe query params: %s", r.URL.RawQuery)
					}
					http.SetCookie(w, &http.Cookie{Name: "TWFID", Value: testSyntheticPreTwfID, Path: "/"})
					w.Header().Set("Content-Type", "application/xml; charset=utf-8")
					_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<Auth>
  <ErrorCode>1</ErrorCode>
  <TwfID>%s</TwfID>
  <NextAuth></NextAuth>
  <RSA_ENCRYPT_KEY>%s</RSA_ENCRYPT_KEY>
  <RSA_ENCRYPT_EXP>%s</RSA_ENCRYPT_EXP>
  <CSRF_RAND_CODE>%s</CSRF_RAND_CODE>
</Auth>`, testSyntheticPreTwfID, modulusHex, tc.exponentXML, tc.csrfXML)

				case authLoginPswPath:
					sawLogin = true
					if r.Method != http.MethodPost {
						t.Errorf("expected POST for login_psw.csp, got %s", r.Method)
					}
					q := r.URL.Query()
					if tc.csrfXML != "" {
						if q.Get("anti_replay") != "1" || q.Get("encrypt") != "1" || q.Get("apiversion") != "1" {
							t.Errorf("unexpected login query params with CSRF: %s", r.URL.RawQuery)
						}
					} else {
						if q.Get("anti_replay") != "" || q.Get("encrypt") != "1" || q.Get("type") != "cs" || q.Get("language") != "zh_CN" {
							t.Errorf("unexpected login query params without CSRF: %s", r.URL.RawQuery)
						}
					}
					if c, err := r.Cookie("TWFID"); err != nil || c.Value != testSyntheticPreTwfID {
						t.Errorf("expected pre-auth TWFID cookie %q, got err=%v", testSyntheticPreTwfID, err)
					}
					if err := r.ParseForm(); err != nil {
						t.Fatalf("failed to parse login form: %v", err)
					}
					if !r.PostForm.Has("mitm_result") || r.PostForm.Get("mitm_result") != "" {
						t.Errorf("expected empty mitm_result field, got %q (present=%v)", r.PostForm.Get("mitm_result"), r.PostForm.Has("mitm_result"))
					}
					if r.PostForm.Get("svpn_req_randcode") != tc.csrfXML {
						t.Errorf("unexpected svpn_req_randcode: got %q, want %q", r.PostForm.Get("svpn_req_randcode"), tc.csrfXML)
					}
					if r.PostForm.Get("svpn_name") != testSyntheticUsername {
						t.Errorf("unexpected username: %q", r.PostForm.Get("svpn_name"))
					}
					if r.PostForm.Get("svpn_rand_code") != "" {
						t.Errorf("expected empty svpn_rand_code when no captcha, got %q", r.PostForm.Get("svpn_rand_code"))
					}

					decrypted := decryptSubmittedHexPassword(t, privKey, r.PostForm.Get("svpn_password"))
					if decrypted != tc.expectedPlain {
						t.Errorf("decrypted password mismatch: got %q, want %q", decrypted, tc.expectedPlain)
					}

					w.Header().Set("Content-Type", "application/xml; charset=utf-8")
					if tc.tokenInCookie {
						http.SetCookie(w, &http.Cookie{Name: "TWFID", Value: tc.expectedTwfID, Path: "/"})
						_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><Auth><Result>1</Result></Auth>`)
					} else {
						_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><Auth><Result>1</Result><TwfId>%s</TwfId></Auth>`, tc.expectedTwfID)
					}

				case authConfPath:
					sawConf = true
					if c, err := r.Cookie("TWFID"); err != nil || c.Value != tc.expectedTwfID {
						t.Errorf("conf.csp missing expected TWFID cookie: err=%v", err)
					}
					w.Header().Set("Content-Type", "application/xml; charset=utf-8")
					_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>
<Conf>
  <Result>1</Result>
  <VipAddress>10.255.12.34</VipAddress>
  <L3VPN iptunDns="10.0.0.2" iptunDnsBak="10.0.0.3"/>
  <Dns dnsserver="10.0.0.3;198.51.100.1" data="example.edu" filter="1"/>
  <iplist iplist="10.0.0.0/8,172.16.0.0/255.240.0.0"/>
</Conf>`)

				case authRCListPath:
					sawRCList = true
					if c, err := r.Cookie("TWFID"); err != nil || c.Value != tc.expectedTwfID {
						t.Errorf("rclist.csp missing expected TWFID cookie: err=%v", err)
					}
					w.Header().Set("Content-Type", "application/xml; charset=utf-8")
					_, _ = fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>
<Rclist>
  <Result>1</Result>
  <rclist rclist="198.51.100.0/24;192.168.100.0/24;10.10.0.0-10.10.0.255;https://portal.example.edu:443"/>
</Rclist>`)

				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			auth := NewSangforAuthenticator(srv.Client())
			profile := model.ConnectionProfile{
				ProfileName: "Campus-VPN-Test",
				GatewayURL:  srv.URL,
			}

			ticket, err := auth.Authenticate(context.Background(), profile, testSyntheticUsername, testSyntheticPassword)
			if err != nil {
				t.Fatalf("Authenticate failed: %v", err)
			}

			if !sawProbe || !sawLogin || !sawConf || !sawRCList {
				t.Fatalf("expected all endpoints to be called (probe=%v login=%v conf=%v rclist=%v)", sawProbe, sawLogin, sawConf, sawRCList)
			}

			if ticket.TwfID != tc.expectedTwfID {
				t.Errorf("unexpected TwfID: got %q", MaskCredential(ticket.TwfID))
			}
			if ticket.VirtualIP != netip.MustParseAddr("10.255.12.34") {
				t.Errorf("unexpected VirtualIP: %v", ticket.VirtualIP)
			}

			wantDNS := []netip.Addr{
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("198.51.100.1"),
			}
			if len(ticket.DNSServers) != len(wantDNS) {
				t.Fatalf("unexpected DNSServers count: got %v, want %v", ticket.DNSServers, wantDNS)
			}
			for i := range wantDNS {
				if ticket.DNSServers[i] != wantDNS[i] {
					t.Errorf("DNSServers[%d] = %v, want %v", i, ticket.DNSServers[i], wantDNS[i])
				}
			}

			wantSubnets := []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("172.16.0.0/12"),
				netip.MustParsePrefix("198.51.100.0/24"),
				netip.MustParsePrefix("192.168.100.0/24"),
				netip.MustParsePrefix("10.10.0.0/24"),
			}
			if len(ticket.IntranetSubnets) != len(wantSubnets) {
				t.Fatalf("unexpected IntranetSubnets: got %v, want %v", ticket.IntranetSubnets, wantSubnets)
			}
			for i := range wantSubnets {
				if ticket.IntranetSubnets[i] != wantSubnets[i] {
					t.Errorf("IntranetSubnets[%d] = %v, want %v", i, ticket.IntranetSubnets[i], wantSubnets[i])
				}
			}
		})
	}
}

func TestAuthenticateWrongPasswordRedactsSecrets(t *testing.T) {
	privKey := generateTestRSAKey(t)
	modulusHex := fmt.Sprintf("%x", privKey.PublicKey.N)
	var sawProbe, sawLogin bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case authProbePath:
			sawProbe = true
			http.SetCookie(w, &http.Cookie{Name: "TWFID", Value: testSyntheticPreTwfID, Path: "/"})
			_, _ = fmt.Fprintf(w, `<Auth><Result>1</Result><RSA_ENCRYPT_KEY>%s</RSA_ENCRYPT_KEY><RSA_ENCRYPT_EXP>10001</RSA_ENCRYPT_EXP><CSRF_RAND_CODE>123456</CSRF_RAND_CODE></Auth>`, modulusHex)
		case authLoginPswPath:
			sawLogin = true
			// 故意在异常服务端回显中包含敏感值，验证错误路径会严格脱敏
			_, _ = fmt.Fprintf(w, `<Auth><Result>0</Result><Message>invalid password %s for token %s</Message></Auth>`, testSyntheticPassword, testSyntheticPreTwfID)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	auth := NewSangforAuthenticator(srv.Client())
	profile := model.ConnectionProfile{GatewayURL: srv.URL}

	_, err := auth.Authenticate(context.Background(), profile, testSyntheticUsername, testSyntheticPassword)
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if !sawProbe || !sawLogin {
		t.Fatalf("expected probe and login endpoints to be hit (probe=%v login=%v); err=%v", sawProbe, sawLogin, err)
	}

	errText := err.Error()
	if strings.Contains(errText, testSyntheticPassword) {
		t.Fatalf("error leaked plaintext password: %s", errText)
	}
	if strings.Contains(errText, testSyntheticPreTwfID) {
		t.Fatalf("error leaked raw TWFID: %s", errText)
	}
	if !strings.Contains(errText, "[REDACTED]") {
		t.Fatalf("expected redacted placeholder in error: %s", errText)
	}
	if !strings.Contains(errText, MaskCredential(testSyntheticPreTwfID)) {
		t.Fatalf("expected masked TWFID in error: %s", errText)
	}
}

func TestAuthenticateWithCASCookieAndProbeDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case authProbePath:
			http.Redirect(w, r, "/authserver/login?service=https://vpn.example.edu", http.StatusFound)
		case "/authserver/login":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, `<!DOCTYPE html><html><body><form id="casLoginForm">CAS</form></body></html>`)
		case authConfPath:
			c, err := r.Cookie("TWFID")
			if err != nil || c.Value != testSyntheticCASTwfID {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = fmt.Fprint(w, `<Conf><Result>1</Result><VipAddress>10.255.88.9</VipAddress><L3VPN iptunDns="10.0.0.2" iptunDnsBak=""/></Conf>`)
		case authRCListPath:
			c, err := r.Cookie("TWFID")
			if err != nil || c.Value != testSyntheticCASTwfID {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = fmt.Fprint(w, `<Rclist><Result>1</Result><rclist rclist="10.0.0.0/8"/></Rclist>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	auth := NewSangforAuthenticator(srv.Client())
	profile := model.ConnectionProfile{GatewayURL: srv.URL}

	probe, err := auth.ProbeGateway(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("ProbeGateway failed on CAS redirect: %v", err)
	}
	if !probe.RequiresCASWebLogin {
		t.Errorf("expected RequiresCASWebLogin=true")
	}
	if probe.SupportsPassword {
		t.Errorf("expected SupportsPassword=false on HTML CAS page")
	}

	if _, err := auth.Authenticate(context.Background(), profile, testSyntheticUsername, testSyntheticPassword); err == nil {
		t.Fatal("expected password Authenticate to fail when gateway requires CAS web login")
	} else if !strings.Contains(err.Error(), "CAS") {
		t.Fatalf("expected CAS guidance in error, got: %s", err.Error())
	}

	ticket, err := auth.AuthenticateWithCookie(context.Background(), profile, "TWFID="+testSyntheticCASTwfID+"; Path=/")
	if err != nil {
		t.Fatalf("AuthenticateWithCookie failed: %v", err)
	}
	if ticket.TwfID != testSyntheticCASTwfID {
		t.Errorf("expected normalized TWFID %s, got %s", MaskCredential(testSyntheticCASTwfID), MaskCredential(ticket.TwfID))
	}
	if ticket.VirtualIP != netip.MustParseAddr("10.255.88.9") {
		t.Errorf("unexpected VirtualIP: %v", ticket.VirtualIP)
	}
	if len(ticket.IntranetSubnets) != 1 || ticket.IntranetSubnets[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("unexpected IntranetSubnets: %v", ticket.IntranetSubnets)
	}

	if _, err := auth.AuthenticateWithCookie(context.Background(), profile, "wrong_cookie_token_001122"); err == nil {
		t.Fatal("expected error for invalid CAS cookie, got nil")
	} else if strings.Contains(err.Error(), "wrong_cookie_token_001122") {
		t.Fatalf("error leaked raw cookie token: %s", err.Error())
	}
}

func TestAuthenticateSecondaryAuthRequiredMasksTwfID(t *testing.T) {
	privKey := generateTestRSAKey(t)
	modulusHex := fmt.Sprintf("%x", privKey.PublicKey.N)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case authProbePath:
			_, _ = fmt.Fprintf(w, `<Auth><Result>1</Result><RSA_ENCRYPT_KEY>%s</RSA_ENCRYPT_KEY><RSA_ENCRYPT_EXP>10001</RSA_ENCRYPT_EXP><CSRF_RAND_CODE>654321</CSRF_RAND_CODE></Auth>`, modulusHex)
		case authLoginPswPath:
			http.SetCookie(w, &http.Cookie{Name: "TWFID", Value: testSyntheticSecondTwfID, Path: "/"})
			_, _ = fmt.Fprint(w, `<Auth><Result>1</Result><NextAuth>sms</NextAuth><Message>sms verification code sent</Message></Auth>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	auth := NewSangforAuthenticator(srv.Client())
	profile := model.ConnectionProfile{GatewayURL: srv.URL}

	_, err := auth.Authenticate(context.Background(), profile, testSyntheticUsername, testSyntheticPassword)
	if err == nil {
		t.Fatal("expected SecondaryAuthRequiredError, got nil")
	}

	var secErr *SecondaryAuthRequiredError
	if !errors.As(err, &secErr) {
		t.Fatalf("expected *SecondaryAuthRequiredError, got %T (%v)", err, err)
	}
	if secErr.AuthType != AuthTypeSMS {
		t.Errorf("expected AuthType=%s, got %s", AuthTypeSMS, secErr.AuthType)
	}
	if secErr.NextAuth != "sms" {
		t.Errorf("expected NextAuth=sms, got %q", secErr.NextAuth)
	}

	errMsg := secErr.Error()
	if strings.Contains(errMsg, testSyntheticSecondTwfID) {
		t.Fatalf("SecondaryAuthRequiredError.Error() leaked raw TWFID: %s", errMsg)
	}
	if !strings.Contains(errMsg, MaskCredential(testSyntheticSecondTwfID)) {
		t.Fatalf("expected masked TWFID %q in error message, got %s", MaskCredential(testSyntheticSecondTwfID), errMsg)
	}
}

func TestKeepAliveAndLogout(t *testing.T) {
	mode := "ok"
	var logoutCalled bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case authKeepAlivePath:
			if r.URL.Query().Get("apiversion") != "1" || r.URL.Query().Get("twfid") == "" {
				t.Errorf("keepalive missing expected apiversion/twfid query params: %s", r.URL.RawQuery)
			}
			c, err := r.Cookie("TWFID")
			if err != nil || c.Value != testSyntheticSessionTwf || r.URL.Query().Get("twfid") != testSyntheticSessionTwf {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			switch mode {
			case "ok":
				_, _ = fmt.Fprint(w, `<Auth><ErrorCode>1</ErrorCode><Message>success</Message></Auth>`)
			case "expired_xml":
				_, _ = fmt.Fprint(w, `<Auth><ErrorCode>0</ErrorCode><Message>session expired</Message></Auth>`)
			case "redirect_login":
				http.Redirect(w, r, authProbePath, http.StatusFound)
			}

		case authProbePath:
			_, _ = fmt.Fprint(w, `<Auth><Result>1</Result></Auth>`)

		case authLogoutPath:
			logoutCalled = true
			if r.URL.Query().Get("twfid") != testSyntheticSessionTwf {
				t.Errorf("logout query twfid mismatch")
			}
			if c, err := r.Cookie("TWFID"); err != nil || c.Value != testSyntheticSessionTwf {
				t.Errorf("logout missing expected TWFID cookie: err=%v", err)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, `<Logout><Result>1</Result></Logout>`)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	auth := NewSangforAuthenticator(srv.Client())
	profile := model.ConnectionProfile{GatewayURL: srv.URL}
	ticket := model.SessionTicket{TwfID: testSyntheticSessionTwf}

	if err := auth.KeepAlive(context.Background(), profile, ticket); err != nil {
		t.Fatalf("expected KeepAlive to succeed, got: %v", err)
	}

	for _, failMode := range []string{"expired_xml", "redirect_login"} {
		mode = failMode
		err := auth.KeepAlive(context.Background(), profile, ticket)
		if err == nil {
			t.Fatalf("expected KeepAlive error in mode %s", failMode)
		}
		if strings.Contains(err.Error(), testSyntheticSessionTwf) {
			t.Fatalf("KeepAlive error leaked raw TWFID in mode %s: %s", failMode, err.Error())
		}
	}

	if err := auth.KeepAlive(context.Background(), profile, model.SessionTicket{TwfID: "invalid_expired_token_9988"}); err == nil {
		t.Fatal("expected KeepAlive HTTP 401 error for unknown TWFID")
	} else if strings.Contains(err.Error(), "invalid_expired_token_9988") {
		t.Fatalf("KeepAlive 401 error leaked raw TWFID: %s", err.Error())
	}

	if err := auth.Logout(context.Background(), profile, ticket); err != nil {
		t.Fatalf("expected Logout to succeed, got: %v", err)
	}
	if !logoutCalled {
		t.Fatal("expected Logout to invoke /por/logout.csp")
	}

	// 验证 Logout 在发生网络错误时，*url.Error 不会泄露 query 中的明文 twfid
	failingClient := &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp: connection refused")
		}),
	}
	failingAuth := NewSangforAuthenticator(failingClient)
	logoutErr := failingAuth.Logout(context.Background(), profile, ticket)
	if logoutErr == nil {
		t.Fatal("expected Logout transport error, got nil")
	}
	if strings.Contains(logoutErr.Error(), testSyntheticSessionTwf) {
		t.Fatalf("Logout transport error leaked raw TWFID in URL: %s", logoutErr.Error())
	}
}

func TestMaskCredentialAndSessionTicketJSONRedaction(t *testing.T) {
	if got := MaskCredential(""); got != "" {
		t.Errorf("MaskCredential empty = %q, want empty", got)
	}
	if got := MaskCredential("abc"); got != "****" {
		t.Errorf("MaskCredential short = %q, want ****", got)
	}
	if got := MaskCredential("12345678"); got != "****" {
		t.Errorf("MaskCredential 8-char = %q, want ****", got)
	}
	if got := MaskCredential("1234567890"); got != "12****90" {
		t.Errorf("MaskCredential 10-char = %q, want 12****90", got)
	}

	masked := MaskCredential(testSyntheticSessionTwf)
	if masked == testSyntheticSessionTwf || strings.Contains(masked, testSyntheticSessionTwf) {
		t.Fatalf("MaskCredential did not mask 32-char token: %s", masked)
	}
	if masked != "ffee****2211" {
		t.Errorf("MaskCredential 32-char = %q, want ffee****2211", masked)
	}

	ticket := model.SessionTicket{
		TwfID:     testSyntheticSessionTwf,
		VirtualIP: netip.MustParseAddr("10.255.0.2"),
		DNSServers: []netip.Addr{
			netip.MustParseAddr("10.0.0.2"),
		},
		IntranetSubnets: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
		},
	}

	rawJSON, err := json.Marshal(ticket)
	if err != nil {
		t.Fatalf("json.Marshal(ticket) failed: %v", err)
	}
	jsonStr := string(rawJSON)
	if strings.Contains(jsonStr, testSyntheticSessionTwf) {
		t.Fatalf("SessionTicket JSON leaked raw TwfID: %s", jsonStr)
	}
	if strings.Contains(strings.ToLower(jsonStr), "twfid") {
		t.Fatalf("SessionTicket JSON exposed twfid key: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, `"virtualIp":"10.255.0.2"`) {
		t.Fatalf("SessionTicket JSON missing expected virtualIp: %s", jsonStr)
	}
}

func TestAuthenticateWithCaptcha(t *testing.T) {
	privKey := generateTestRSAKey(t)
	modulusHex := fmt.Sprintf("%x", privKey.PublicKey.N)
	const expectedCaptcha = "ABCD"
	captchaPNG := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case authProbePath:
			_, _ = fmt.Fprintf(w, `<Auth><Result>1</Result><RSA_ENCRYPT_KEY>%s</RSA_ENCRYPT_KEY><RSA_ENCRYPT_EXP>10001</RSA_ENCRYPT_EXP><RndImg>1</RndImg></Auth>`, modulusHex)
		case authCaptchaPath:
			http.SetCookie(w, &http.Cookie{Name: "TWFID", Value: testSyntheticPreTwfID, Path: "/"})
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(captchaPNG)
		case authLoginPswPath:
			if c, err := r.Cookie("TWFID"); err != nil || c.Value != testSyntheticPreTwfID {
				t.Errorf("expected captcha TWFID cookie, got err=%v", err)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm failed: %v", err)
			}
			expectedSum := md5.Sum([]byte(expectedCaptcha))
			expectedMD5 := hex.EncodeToString(expectedSum[:])
			if r.PostForm.Get("svpn_rand_code") != expectedMD5 {
				_, _ = fmt.Fprint(w, `<Auth><Result>0</Result><Message>CAPTCHA incorrect</Message></Auth>`)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "TWFID", Value: testSyntheticSessionTwf, Path: "/"})
			_, _ = fmt.Fprint(w, `<Auth><Result>1</Result></Auth>`)
		case authConfPath:
			_, _ = fmt.Fprint(w, `<Conf><Result>1</Result><VipAddress>10.255.9.9</VipAddress></Conf>`)
		case authRCListPath:
			_, _ = fmt.Fprint(w, `<Rclist><Result>1</Result><rclist rclist="10.0.0.0/8"/></Rclist>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	auth := NewSangforAuthenticator(srv.Client())
	profile := model.ConnectionProfile{GatewayURL: srv.URL}

	probe, err := auth.ProbeGateway(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("ProbeGateway failed: %v", err)
	}
	if !probe.NeedsCaptcha {
		t.Fatalf("expected NeedsCaptcha=true when RndImg=1")
	}

	_, err = auth.Authenticate(context.Background(), profile, testSyntheticUsername, testSyntheticPassword)
	var secErr *SecondaryAuthRequiredError
	if !errors.As(err, &secErr) || secErr.AuthType != AuthTypeCaptcha {
		t.Fatalf("expected AuthTypeCaptcha error when captcha missing, got %v", err)
	}

	imgBytes, updatedTwf, err := auth.FetchCaptcha(context.Background(), srv.URL, probe.PreTwfID)
	if err != nil {
		t.Fatalf("FetchCaptcha failed: %v", err)
	}
	if len(imgBytes) != len(captchaPNG) {
		t.Fatalf("unexpected captcha image size: %d", len(imgBytes))
	}
	if updatedTwf != testSyntheticPreTwfID {
		t.Fatalf("expected updated pre-auth TWFID from captcha response")
	}

	ticket, err := auth.AuthenticateWithOptions(
		context.Background(),
		profile,
		testSyntheticUsername,
		testSyntheticPassword,
		AuthOptions{
			CaptchaCode: expectedCaptcha,
			PreTwfID:    updatedTwf,
		},
	)
	if err != nil {
		t.Fatalf("AuthenticateWithOptions with captcha failed: %v", err)
	}
	if ticket.TwfID != testSyntheticSessionTwf {
		t.Errorf("unexpected session TWFID: %s", MaskCredential(ticket.TwfID))
	}
}

func TestParseSessionConfigDomainsEigenvalueAndMTU(t *testing.T) {
	// 31-char lowercase hex token + NUL (0x00) + 16-char TWFID + 16-byte tail = 64 bytes (128 hex chars).
	syntheticAgent := "0123456789abcdef0123456789abcde"
	syntheticRawCtx := append([]byte(syntheticAgent), 0x00)
	syntheticRawCtx = append(syntheticRawCtx, []byte(testSyntheticSessionTwf[:16])...)
	syntheticRawCtx = append(syntheticRawCtx, make([]byte, 16)...)
	syntheticSslCtxHex := hex.EncodeToString(syntheticRawCtx)

	confXML := fmt.Sprintf(`<Conf>
		<Htp enable="0" port="443" mtu="1400"/>
		<L3VPN iptunDns="0.0.0.0" iptunDnsBak="0.0.0.0"/>
		<Other sslctx="%s"/>
		<Autorule enable="1" domain="*,3389dae361af79b04c9c8e7057f60cc6,acad.cnki.net,695228b9026651a2bba9832764932ef9,*.cnki.net,0a37ab8c7bd316179c960bb52d29e2df,*.ieeexplore.ieee.org,cd7b72b09e1b9550c6a09250e72f7790"/>
		<SSLCipherSuite><EC>AES128-SHA</EC><TCP>RC4-SHA</TCP><L3VPN>RC4-SHA</L3VPN></SSLCipherSuite>
		<SSLEigenvalue><TCP>TCPP</TCP><L3VPN>L3IP</L3VPN></SSLEigenvalue>
	</Conf>`, syntheticSslCtxHex)
	rcXML := `<Resource>
		<Rcs>
			<Rc type="0" svc="WebApp:HTTPS" host="https://lib.example.edu/wisdom/views/index" port="0"/>
			<Rc type="1" svc="HTTP" host="http://198.51.100.70;http://portal.example.org/" port="8088~8088;80~80"/>
		</Rcs>
	</Resource>`

	ticket, err := parseSessionConfigDocuments(testSyntheticSessionTwf, []byte(confXML), []byte(rcXML))
	if err != nil {
		t.Fatalf("parseSessionConfigDocuments failed: %v", err)
	}
	if ticket.L3Eigenvalue != "L3IP" || ticket.TCPEigenvalue != "TCPP" || ticket.L3CipherSuite != "RC4-SHA" {
		t.Fatalf("unexpected eigenvalue/cipher metadata: %+v", ticket)
	}
	if ticket.TunnelMTU != 1400 {
		t.Fatalf("expected TunnelMTU=1400, got %d", ticket.TunnelMTU)
	}
	if len(ticket.TunnelToken) != TunnelTokenSize {
		t.Fatalf("expected 48-byte TunnelToken from sslctx, got %d", len(ticket.TunnelToken))
	}
	if len(ticket.DNSServers) != 0 {
		t.Fatalf("expected 0.0.0.0 placeholder DNS skipped, got %v", ticket.DNSServers)
	}
	if len(ticket.IntranetSubnets) != 1 || ticket.IntranetSubnets[0].String() != "198.51.100.70/32" {
		t.Fatalf("unexpected IntranetSubnets: %v", ticket.IntranetSubnets)
	}
	joined := strings.Join(ticket.IntranetDomains, ",")
	for _, want := range []string{"acad.cnki.net", "*.cnki.net", "*.ieeexplore.ieee.org", "lib.example.edu", "portal.example.org"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected domain %q in IntranetDomains (%s)", want, joined)
		}
	}
	if strings.Contains(joined, "3389dae361af79b04c9c8e7057f60cc6") {
		t.Errorf("MD5 token leaked into IntranetDomains: %s", joined)
	}
}

func TestProbeGatewayRetriesTransientEOF(t *testing.T) {
	privKey := generateTestRSAKey(t)
	modulusHex := fmt.Sprintf("%x", privKey.PublicKey.N)
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			// 模拟网关侧主动断开 TCP 连接触发客户端 EOF。
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
		}
		http.SetCookie(w, &http.Cookie{Name: "TWFID", Value: testSyntheticPreTwfID, Path: "/"})
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		_, _ = fmt.Fprintf(w, `<Auth><ErrorCode>1</ErrorCode><RSA_ENCRYPT_KEY>%s</RSA_ENCRYPT_KEY><RSA_ENCRYPT_EXP>65537</RSA_ENCRYPT_EXP><CSRF_RAND_CODE>998877</CSRF_RAND_CODE></Auth>`, modulusHex)
	}))
	defer srv.Close()

	auth := NewSangforAuthenticator(srv.Client())
	res, err := auth.ProbeGateway(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("expected ProbeGateway to recover from transient EOF, got: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("expected 3 probe attempts, got %d", attempts.Load())
	}
	if !res.SupportsPassword || res.CSRFRandCode != "998877" || res.PreTwfID != testSyntheticPreTwfID {
		t.Fatalf("unexpected probe result after retry: %+v", res)
	}
}

func TestDefaultSangforAuthenticatorTransportDirectHTTP11(t *testing.T) {
	auth := NewSangforAuthenticator(nil)
	tr, ok := auth.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", auth.httpClient.Transport)
	}
	if tr.Proxy != nil {
		t.Errorf("expected Proxy=nil to bypass environment proxy")
	}
	if !tr.DisableKeepAlives {
		t.Errorf("expected DisableKeepAlives=true to avoid stale keep-alive EOF")
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Errorf("expected TLSClientConfig.InsecureSkipVerify=true")
	}
	if len(auth.fallbackClients) < 2 {
		t.Errorf("expected fallback TLS/uTLS clients to be configured, got %d", len(auth.fallbackClients))
	}
}

func TestParseTildeIPRangesInRCList(t *testing.T) {
	confXML := `<Conf><Result>1</Result><L3VPN iptunDns="10.84.1.1" iptunDnsBak="8.8.8.8"/></Conf>`
	rcXML := `<Resource>
		<Rcs>
			<Rc type="1" svc="IP" host="10.20.4.0~10.20.4.255;198.51.96.0~198.51.111.255;jwxt.example.edu" port="0~65535;0~65535;443~443"/>
		</Rcs>
	</Resource>`

	ticket, err := parseSessionConfigDocuments(testSyntheticSessionTwf, []byte(confXML), []byte(rcXML))
	if err != nil {
		t.Fatalf("parseSessionConfigDocuments failed: %v", err)
	}

	var hasPrivateRange, hasPublicRange bool
	for _, pfx := range ticket.IntranetSubnets {
		switch pfx.String() {
		case "10.20.4.0/24":
			hasPrivateRange = true
		case "198.51.96.0/20":
			hasPublicRange = true
		}
	}
	if !hasPrivateRange || !hasPublicRange {
		t.Fatalf("expected ~ IP ranges parsed into CIDR subnets, got: %v", ticket.IntranetSubnets)
	}

	for _, dom := range ticket.IntranetDomains {
		if strings.Contains(dom, "~") {
			t.Fatalf("IP range leaked into IntranetDomains: %q", dom)
		}
	}
	if len(ticket.IntranetDomains) != 1 || ticket.IntranetDomains[0] != "jwxt.example.edu" {
		t.Fatalf("expected only jwxt.example.edu in IntranetDomains, got: %v", ticket.IntranetDomains)
	}
}
