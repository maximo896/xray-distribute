package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func newUTLSForwardClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	h1Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DialTLSContext:      dialTLSWithUTLSH1,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	h2Transport := &http2.Transport{
		DialTLSContext: dialTLSWithUTLSH2Auto,
	}
	h2CompatTransport := &http2.Transport{
		DialTLSContext: dialTLSWithUTLSH2Chrome120,
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &chromeForwardTransport{h2: h2Transport, h2Compat: h2CompatTransport, h1: h1Transport},
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

type chromeForwardTransport struct {
	h2       http.RoundTripper
	h2Compat http.RoundTripper
	h1       http.RoundTripper
}

func (t *chromeForwardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	applyChromeHeaders(req)

	if req.URL.Scheme != "https" {
		return t.h1.RoundTrip(req)
	}

	resp, err := t.h2.RoundTrip(req)
	if err == nil {
		return resp, nil
	}

	if canRetry(req) && t.h2Compat != nil {
		retryReq, retryErr := cloneRequestForRetry(req)
		if retryErr != nil {
			return nil, err
		}
		resp, compatErr := t.h2Compat.RoundTrip(retryReq)
		if compatErr == nil {
			return resp, nil
		}
		err = compatErr
	}

	if canRetry(req) {
		retryReq, retryErr := cloneRequestForRetry(req)
		if retryErr != nil {
			return nil, err
		}
		return t.h1.RoundTrip(retryReq)
	}
	return nil, err
}

func applyChromeHeaders(req *http.Request) {
	ua := req.Header.Get("User-Agent")
	if ua == "" || strings.HasPrefix(ua, "Go-http-client/") {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	}
	if req.Header.Get("Sec-Ch-Ua") == "" {
		req.Header.Set("Sec-Ch-Ua", `"Chromium";v="133", "Google Chrome";v="133", "Not(A:Brand";v="99"`)
	}
	if req.Header.Get("Sec-Ch-Ua-Mobile") == "" {
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	}
	if req.Header.Get("Sec-Ch-Ua-Platform") == "" {
		req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	}
}

func canRetry(req *http.Request) bool {
	return req.Body == nil || req.GetBody != nil
}

func cloneRequestForRetry(req *http.Request) (*http.Request, error) {
	retryReq := req.Clone(req.Context())
	if req.Body != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		retryReq.Body = body
	}
	return retryReq, nil
}

type utlsConn struct {
	*utls.UConn
}

func (c *utlsConn) Close() error {
	return c.UConn.Close()
}

func (c *utlsConn) ConnectionState() tls.ConnectionState {
	cs := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		CipherSuite:                 cs.CipherSuite,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		TLSUnique:                   cs.TLSUnique,
	}
}

func dialTLSWithUTLSH2Auto(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	conn, err := dialTLSWithUTLS(ctx, network, addr, []string{"h2", "http/1.1"}, utls.HelloChrome_Auto)
	return requireH2(conn, err)
}

func dialTLSWithUTLSH2Chrome120(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	conn, err := dialTLSWithUTLS(ctx, network, addr, []string{"h2", "http/1.1"}, utls.HelloChrome_120)
	return requireH2(conn, err)
}

func requireH2(conn *utlsConn, err error) (net.Conn, error) {
	if err != nil {
		return nil, err
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		conn.Close()
		return nil, fmt.Errorf("unexpected ALPN protocol %q", conn.ConnectionState().NegotiatedProtocol)
	}
	return conn, nil
}

func dialTLSWithUTLSH1(ctx context.Context, network, addr string) (net.Conn, error) {
	return dialTLSWithUTLS(ctx, network, addr, []string{"http/1.1"}, utls.HelloChrome_120)
}

func dialTLSWithUTLS(ctx context.Context, network, addr string, alpn []string, helloID utls.ClientHelloID) (*utlsConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host port: %w", err)
	}

	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}

	uconn := utls.UClient(tcpConn, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         alpn,
	}, helloID)

	if len(alpn) == 1 && alpn[0] == "http/1.1" {
		if err := forceHTTP1ALPN(uconn); err != nil {
			tcpConn.Close()
			return nil, err
		}
	}

	if err := uconn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	return &utlsConn{UConn: uconn}, nil
}

func forceHTTP1ALPN(uconn *utls.UConn) error {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_120)
	if err != nil {
		return fmt.Errorf("chrome spec: %w", err)
	}
	for _, ext := range spec.Extensions {
		if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
			alpnExt.AlpnProtocols = []string{"http/1.1"}
		}
		if appSettingsExt, ok := ext.(*utls.ApplicationSettingsExtension); ok {
			appSettingsExt.SupportedProtocols = nil
		}
	}
	if err := uconn.ApplyPreset(&spec); err != nil {
		return fmt.Errorf("apply chrome h1 preset: %w", err)
	}
	return nil
}
