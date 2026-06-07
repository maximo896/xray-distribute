package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/xray-distribute/internal/cert"
	"github.com/xray-distribute/internal/mirror"
)

// MirrorProxy 流量镜像代理
// 作为标准HTTP代理工作，同时异步镜像流量到Server
type MirrorProxy struct {
	listenAddr string
	mirror     *mirror.Sender
	certMgr    *cert.CertManager
	logger     *slog.Logger
	h2Server   *http2.Server
	ln         net.Listener
}

// New 创建新的镜像代理
func New(listenAddr string, mirrorSender *mirror.Sender, certMgr *cert.CertManager, logger *slog.Logger) (*MirrorProxy, error) {
	return &MirrorProxy{
		listenAddr: listenAddr,
		mirror:     mirrorSender,
		certMgr:    certMgr,
		logger:     logger,
		h2Server:   &http2.Server{},
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
	return nil
}

// bufferedConn 包装net.Conn使其可被bufio.Reader读取
// 确保TLS握手时不会丢失已缓冲的数据
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

		// 直接用 http.ReadRequest 解析，避免手动解析请求行
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.logger.Debug("read request failed", "error", err)
			}
			return
		}

		if req.Method == "CONNECT" {
			p.handleConnect(req, reader, conn)
			return // CONNECT接管连接后不再循环
		}

		p.handleHTTPRequest(req, reader, conn)

		// 如果请求要求关闭连接则退出
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

	// 连接目标
	targetConn, err := net.DialTimeout("tcp", hostPort, 10*time.Second)
	if err != nil {
		p.logger.Error("connect to target failed", "host", hostPort, "error", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer targetConn.Close()

	// 回复200
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
		// 降级为纯隧道（不MITM，只做TCP中继）
		bConn := &bufferedConn{Conn: conn, reader: reader}
		relayBidirectional(bConn, targetConn)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	// 用bufferedConn包装，确保TLS握手能读到已缓冲的数据
	bConn := &bufferedConn{Conn: conn, reader: reader}
	tlsClientConn := tls.Server(bConn, tlsConfig)
	tlsClientConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsClientConn.Handshake(); err != nil {
		p.logger.Debug("tls handshake with client failed", "domain", domain, "error", err)
		return
	}
	tlsClientConn.SetDeadline(time.Time{})
	defer tlsClientConn.Close()

	// 与目标建立TLS（强制HTTP/1.1简化处理）
	tlsTargetConn := tls.Client(targetConn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsTargetConn.Handshake(); err != nil {
		p.logger.Debug("tls handshake with target failed", "domain", domain, "error", err)
		return
	}
	defer tlsTargetConn.Close()

	// 根据客户端ALPN协商结果
	connState := tlsClientConn.ConnectionState()
	switch connState.NegotiatedProtocol {
	case "h2":
		p.handleH2MITM(tlsClientConn, tlsTargetConn, domain)
	default:
		p.handleH1MITM(tlsClientConn, tlsTargetConn, domain)
	}
}

// handleHTTPRequest 处理普通HTTP代理请求
func (p *MirrorProxy) handleHTTPRequest(req *http.Request, reader *bufio.Reader, conn net.Conn) {
	// 读取请求体
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	// 异步镜像（不阻塞代理）
	go p.mirror.Send(req, bodyBytes)

	// 转发请求到目标
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

	// 复制请求头
	for key, values := range req.Header {
		for _, value := range values {
			forwardReq.Header.Add(key, value)
		}
	}
	forwardReq.Host = req.Host

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(forwardReq)
	if err != nil {
		p.logger.Error("forward request failed", "url", req.URL.String(), "error", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()

	resp.Header.Del("Alt-Svc")

	// 写回完整响应
	resp.Write(conn)
}

// handleH1MITM MITM模式HTTP/1.x
func (p *MirrorProxy) handleH1MITM(clientConn, targetConn net.Conn, domain string) {
	clientReader := bufio.NewReader(clientConn)
	targetReader := bufio.NewReader(targetConn)

	for {
		clientConn.SetDeadline(time.Now().Add(5 * time.Minute))
		targetConn.SetDeadline(time.Now().Add(5 * time.Minute))

		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err != io.EOF {
				p.logger.Debug("read http1 request failed", "domain", domain, "error", err)
			}
			return
		}

		var bodyBytes []byte
		if req.Body != nil {
			bodyBytes, _ = io.ReadAll(req.Body)
			req.Body.Close()
		}

		req.URL.Scheme = "https"
		req.URL.Host = domain

		// 异步镜像
		go p.mirror.Send(req, bodyBytes)

		// WebSocket升级
		if isWebSocketUpgrade(req.Header) {
			if len(bodyBytes) > 0 {
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
			req.Write(targetConn)
			resp, err := http.ReadResponse(targetReader, req)
			if err != nil {
				return
			}
			resp.Write(clientConn)
			go relayBytes(targetConn, clientConn)
			relayBytes(clientConn, targetConn)
			return
		}

		// 重建请求体并转发到目标
		if len(bodyBytes) > 0 {
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}

		if err := req.Write(targetConn); err != nil {
			return
		}

		// 读取目标响应（复用同一个targetReader，不会丢失缓冲数据）
		resp, err := http.ReadResponse(targetReader, req)
		if err != nil {
			return
		}

		resp.Header.Del("Alt-Svc")

		// 读取响应体
		var respBody []byte
		if resp.Body != nil {
			respBody, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		if len(respBody) > 0 {
			resp.Body = io.NopCloser(bytes.NewBuffer(respBody))
			resp.ContentLength = int64(len(respBody))
		}

		resp.Write(clientConn)

		if req.Close {
			return
		}
	}
}

// handleH2MITM MITM模式HTTP/2
func (p *MirrorProxy) handleH2MITM(clientConn, targetConn net.Conn, domain string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body.Close()
		}

		// 异步镜像
		go p.mirror.Send(r, bodyBytes)

		// 转发
		p.forwardH2(w, r, bodyBytes, domain)
	})

	p.h2Server.ServeConn(clientConn, &http2.ServeConnOpts{
		Handler: handler,
	})
}

// forwardH2 转发HTTP/2请求
func (p *MirrorProxy) forwardH2(w http.ResponseWriter, r *http.Request, bodyBytes []byte, domain string) {
	forwardURL := url.URL{
		Scheme:   "https",
		Host:     domain,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewBuffer(bodyBytes)
	}

	forwardReq, err := http.NewRequest(r.Method, forwardURL.String(), bodyReader)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	for key, values := range r.Header {
		for _, value := range values {
			forwardReq.Header.Add(key, value)
		}
	}

	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return net.DialTimeout(network, addr, 10*time.Second)
		},
	}

	resp, err := transport.RoundTrip(forwardReq)
	if err != nil {
		p.logger.Error("h2 forward failed", "error", err)
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
}

// isWebSocketUpgrade 检测WebSocket升级
func isWebSocketUpgrade(h http.Header) bool {
	return strings.ToLower(h.Get("Upgrade")) == "websocket"
}

// relayBytes 单向字节中继
func relayBytes(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
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
