package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/xray-distribute/internal/cert"
	"github.com/xray-distribute/internal/mirror"
)

// 创建测试用的mirror.Sender（不真正发送）
func newTestSender(logger *slog.Logger) *mirror.Sender {
	return mirror.NewSender("http://127.0.0.1:1", "test-token", logger)
}

// 测试HTTP代理（非CONNECT）
func TestHTTPProxy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 启动一个目标HTTP服务器
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from target"))
	}))
	defer targetServer.Close()

	// 启动代理
	certMgr, err := cert.NewCertManager(t.TempDir(), logger)
	if err != nil {
		t.Fatalf("create cert manager: %v", err)
	}

	sender := newTestSender(logger)
	p, err := New("127.0.0.1:0", sender, certMgr, logger)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}

	// 手动启动监听
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p.ln = ln
	proxyAddr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()

	// 通过代理发送HTTP请求
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL("http://" + proxyAddr)),
		},
	}

	resp, err := client.Get(targetServer.URL)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from target" {
		t.Errorf("unexpected body: %s", body)
	}
	if resp.Header.Get("X-Test") != "ok" {
		t.Errorf("missing X-Test header")
	}

	t.Logf("HTTP proxy test passed! Body: %s", body)
}

// 测试HTTPS代理（CONNECT + MITM）
func TestHTTPSProxy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 启动一个目标HTTPS服务器
	targetServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "secure-ok")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from tls target"))
	}))
	defer targetServer.Close()

	// 启动代理
	certMgr, err := cert.NewCertManager(t.TempDir(), logger)
	if err != nil {
		t.Fatalf("create cert manager: %v", err)
	}

	sender := newTestSender(logger)
	p, err := New("127.0.0.1:0", sender, certMgr, logger)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p.ln = ln
	proxyAddr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()

	// 获取CA证书
	caCertPEM := certMgr.GetCACertPEM()
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	// 通过代理发送HTTPS请求（信任代理CA）
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL("http://" + proxyAddr)),
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	resp, err := client.Get(targetServer.URL)
	if err != nil {
		t.Fatalf("proxy HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from tls target" {
		t.Errorf("unexpected body: %s", body)
	}
	if resp.Header.Get("X-Test") != "secure-ok" {
		t.Errorf("missing X-Test header")
	}

	t.Logf("HTTPS proxy test passed! Body: %s", body)
}

// 测试原始TCP连接（模拟curl -x）
func TestRawHTTPProxy(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 启动目标HTTP服务器
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
	}))
	defer targetServer.Close()

	// 启动代理
	certMgr, err := cert.NewCertManager(t.TempDir(), logger)
	if err != nil {
		t.Fatalf("create cert manager: %v", err)
	}

	sender := newTestSender(logger)
	p, err := New("127.0.0.1:0", sender, certMgr, logger)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p.ln = ln
	proxyAddr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(conn)
		}
	}()

	// 模拟curl -x发送原始HTTP代理请求
	targetURL := targetServer.URL
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	defer conn.Close()

	// 发送代理请求
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL, "127.0.0.1")
	conn.Write([]byte(req))
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// 读取响应
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	t.Logf("Raw proxy response: status=%d, body=%s", resp.StatusCode, body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

func TestCleanForwardHeadersRemovesHopByHopHeaders(t *testing.T) {
	header := http.Header{}
	header.Set("Connection", "Upgrade, X-Debug-Hop")
	header.Set("Proxy-Connection", "keep-alive")
	header.Set("Keep-Alive", "timeout=5")
	header.Set("Proxy-Authorization", "secret")
	header.Set("Te", "trailers")
	header.Set("Upgrade", "websocket")
	header.Set("X-Debug-Hop", "remove-me")
	header.Set("X-Normal", "keep-me")

	cleanForwardHeaders(header)

	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authorization", "Te", "Upgrade", "X-Debug-Hop"} {
		if header.Get(key) != "" {
			t.Fatalf("expected %s to be removed, got %q", key, header.Get(key))
		}
	}
	if header.Get("X-Normal") != "keep-me" {
		t.Fatalf("expected ordinary headers to be preserved")
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
