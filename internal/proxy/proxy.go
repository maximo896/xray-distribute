package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/xray-distribute/internal/cert"
	"github.com/xray-distribute/internal/mirror"
)

// MirrorProxy 流量镜像代理
type MirrorProxy struct {
	listenAddr string
	mirror     *mirror.Sender
	certMgr    *cert.CertManager
	logger     *slog.Logger
	h2Server   *http2.Server
	ln         net.Listener
	// 共享的http.Client用于转发，自带连接池和H1/H2自动协商
	forwardClient *http.Client
}

// New 创建新的镜像代理
func New(listenAddr string, mirrorSender *mirror.Sender, certMgr *cert.CertManager, logger *slog.Logger) (*MirrorProxy, error) {
	// 创建使用uTLS的转发客户端，模拟Chrome TLS指纹
	forwardClient, err := newUTLSForwardClient()
	if err != nil {
		return nil, fmt.Errorf("create utls client: %w", err)
	}

	return &MirrorProxy{
		listenAddr:    listenAddr,
		mirror:        mirrorSender,
		certMgr:       certMgr,
		logger:        logger,
		h2Server:      &http2.Server{},
		forwardClient: forwardClient,
	}, nil
}

// Start 启动代理
func (p *MirrorProxy) Start() error {
	p.logger.Info("mirror proxy starting", "listen", p.listenAddr)

	ln, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return err
	}
	p.ln = ln

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "closed") {
					p.logger.Error("accept error", "error", err)
				}
				return
			}
			go p.handleConn(conn)
		}
	}()

	return nil
}

// Stop 停止代理
func (p *MirrorProxy) Stop(ctx context.Context) error {
	if p.ln != nil {
		p.ln.Close()
	}
	p.forwardClient.CloseIdleConnections()
	return nil
}

// bufferedConn 包装net.Conn使其可被bufio.Reader读取
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// handleConn 处理每个入站连接
func (p *MirrorProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		conn.SetDeadline(time.Now().Add(30 * time.Second))

		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.logger.Debug("read request failed", "error", err)
			}
			return
		}

		if req.Method == "CONNECT" {
			p.handleConnect(req, reader, conn)
			return
		}

		p.handleHTTPRequest(req, conn)

		if req.Close {
			return
		}
	}
}

// handleConnect 处理CONNECT隧道（HTTPS代理）
func (p *MirrorProxy) handleConnect(req *http.Request, reader *bufio.Reader, conn net.Conn) {
	hostPort := req.URL.Host
	if hostPort == "" {
		hostPort = req.Host
	}
	if !strings.Contains(hostPort, ":") {
		hostPort = hostPort + ":443"
	}

	// 先回复200，让客户端知道隧道已建立
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// 提取域名
	domain := hostPort
	if idx := strings.LastIndex(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}

	// MITM：与客户端建立TLS
	tlsCert, err := p.certMgr.GetCertForHost(domain)
	if err != nil {
		p.logger.Error("get cert failed", "domain", domain, "error", err)
		// 无法MITM，需要直接连目标做TCP中继
		targetConn, err := net.DialTimeout("tcp", hostPort, 10*time.Second)
		if err != nil {
			return
		}
		defer targetConn.Close()
		bConn := &bufferedConn{Conn: conn, reader: reader}
		relayBidirectional(bConn, targetConn)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	bConn := &bufferedConn{Conn: conn, reader: reader}
	tlsClientConn := tls.Server(bConn, tlsConfig)
	tlsClientConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsClientConn.Handshake(); err != nil {
		p.logger.Debug("tls handshake with client failed", "domain", domain, "error", err)
		return
	}
	tlsClientConn.SetDeadline(time.Time{})
	defer tlsClientConn.Close()

	// 根据客户端ALPN协商结果处理
	connState := tlsClientConn.ConnectionState()
	switch connState.NegotiatedProtocol {
	case "h2":
		p.handleH2MITM(tlsClientConn, hostPort)
	default:
		p.handleH1MITM(tlsClientConn, hostPort)
	}
}

// handleHTTPRequest 处理普通HTTP代理请求
func (p *MirrorProxy) handleHTTPRequest(req *http.Request, conn net.Conn) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	// 确保URL包含scheme和host，否则镜像和转发都会失败
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	// 异步镜像
	go p.mirror.Send(req, bodyBytes)

	// 用http.Client转发
	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewBuffer(bodyBytes)
	}

	forwardReq, err := http.NewRequest(req.Method, req.URL.String(), bodyReader)
	if err != nil {
		p.logger.Error("create forward request failed", "error", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	for key, values := range req.Header {
		for _, value := range values {
			forwardReq.Header.Add(key, value)
		}
	}
	cleanForwardHeaders(forwardReq.Header)
	forwardReq.Host = req.Host

	resp, err := p.forwardClient.Do(forwardReq)
	if err != nil {
		p.logger.Debug("forward request failed", "url", req.URL.String(), "error", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()

	resp.Header.Del("Alt-Svc")
	resp.Write(conn)
}

// handleH1MITM MITM模式HTTP/1.x
func (p *MirrorProxy) handleH1MITM(clientConn net.Conn, hostPort string) {
	reader := bufio.NewReader(clientConn)

	for {
		clientConn.SetDeadline(time.Now().Add(5 * time.Minute))

		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.logger.Debug("read http1 request failed", "host", hostPort, "error", err)
			}
			return
		}

		var bodyBytes []byte
		if req.Body != nil {
			bodyBytes, _ = io.ReadAll(req.Body)
			req.Body.Close()
		}

		req.URL.Scheme = "https"
		req.URL.Host = hostPort

		// 异步镜像
		go p.mirror.Send(req, bodyBytes)

		// 用http.Client转发
		var bodyReader io.Reader
		if len(bodyBytes) > 0 {
			bodyReader = bytes.NewBuffer(bodyBytes)
		}

		forwardReq, err := http.NewRequest(req.Method, "https://"+hostPort+req.URL.RequestURI(), bodyReader)
		if err != nil {
			return
		}

		for key, values := range req.Header {
			for _, value := range values {
				forwardReq.Header.Add(key, value)
			}
		}
		cleanForwardHeaders(forwardReq.Header)
		forwardReq.Host = req.Host

		resp, err := p.forwardClient.Do(forwardReq)
		if err != nil {
			p.logger.Debug("h1 mitm forward failed", "host", hostPort, "error", err)
			errResp := &http.Response{
				StatusCode: http.StatusBadGateway,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Body:       io.NopCloser(strings.NewReader("502 Bad Gateway")),
			}
			errResp.Write(clientConn)
			return
		}

		resp.Header.Del("Alt-Svc")
		resp.Write(clientConn)
		resp.Body.Close()

		if req.Close {
			return
		}
	}
}

// handleH2MITM MITM模式HTTP/2
func (p *MirrorProxy) handleH2MITM(clientConn net.Conn, hostPort string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body.Close()
		}

		// HTTP/2的r.URL只有path（来自:path伪头部），需要补全scheme和host
		r.URL.Scheme = "https"
		r.URL.Host = hostPort

		// 异步镜像
		go p.mirror.Send(r, bodyBytes)

		// 用http.Client转发
		var bodyReader io.Reader
		if len(bodyBytes) > 0 {
			bodyReader = bytes.NewBuffer(bodyBytes)
		}

		targetURL := "https://" + hostPort + r.URL.RequestURI()
		forwardReq, err := http.NewRequest(r.Method, targetURL, bodyReader)
		if err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}

		for key, values := range r.Header {
			for _, value := range values {
				forwardReq.Header.Add(key, value)
			}
		}
		cleanForwardHeaders(forwardReq.Header)
		forwardReq.Host = r.Host

		resp, err := p.forwardClient.Do(forwardReq)
		if err != nil {
			p.logger.Debug("h2 mitm forward failed", "host", hostPort, "url", targetURL, "error", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		resp.Header.Del("Alt-Svc")

		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})

	p.h2Server.ServeConn(clientConn, &http2.ServeConnOpts{
		Handler: handler,
	})
}

func cleanForwardHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, field := range strings.Split(value, ",") {
			if key := strings.TrimSpace(field); key != "" {
				header.Del(key)
			}
		}
	}
	for _, key := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(key)
	}
}

// relayBidirectional 双向中继
func relayBidirectional(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copy(left, right)
	go copy(right, left)
	wg.Wait()
}
