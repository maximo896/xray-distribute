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

// MirrorProxy 全协议流量镜像代理
// 支持 HTTP/0.9, HTTP/1.0, HTTP/1.1, HTTP/2, WebSocket
// HTTP/3(QUIC)通过剥离Alt-Svc响应头强制降级到HTTP/2
type MirrorProxy struct {
	listenAddr string
	targetURL  *url.URL
	mirror     *mirror.Sender
	certMgr    *cert.CertManager
	logger     *slog.Logger
	server     *http.Server
	h2Server   *http2.Server
}

// New 创建新的镜像代理
func New(listenAddr string, target string, mirrorSender *mirror.Sender, certMgr *cert.CertManager, logger *slog.Logger) (*MirrorProxy, error) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	p := &MirrorProxy{
		listenAddr: listenAddr,
		targetURL:  targetURL,
		mirror:     mirrorSender,
		certMgr:    certMgr,
		logger:     logger,
		h2Server:   &http2.Server{},
	}

	return p, nil
}

// Start 启动代理
func (p *MirrorProxy) Start() error {
	p.logger.Info("mirror proxy starting", "listen", p.listenAddr, "target", p.targetURL.String())

	ln, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return err
	}

	// 接受连接，手动处理协议嗅探
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
	if p.server != nil {
		return p.server.Shutdown(ctx)
	}
	return nil
}

// handleConn 处理每个入站连接
// 嗅探第一个字节判断是HTTP还是TLS（HTTPS代理模式）
func (p *MirrorProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 读取前几个字节嗅探协议
	reader := bufio.NewReader(conn)
	firstBytes, err := reader.Peek(5)
	if err != nil {
		p.logger.Debug("peek failed", "error", err)
		return
	}

	// TLS ClientHello 以 0x16 开头
	if len(firstBytes) > 0 && firstBytes[0] == 0x16 {
		p.handleTLSConn(reader, conn)
		return
	}

	// 非TLS：读取第一行判断是CONNECT还是普通HTTP
	p.handlePlainConn(reader, conn)
}

// handlePlainConn 处理明文连接（HTTP/0.9-1.1代理请求）
func (p *MirrorProxy) handlePlainConn(reader *bufio.Reader, conn net.Conn) {
	// 读取第一行
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		p.logger.Debug("read first line failed", "error", err)
		return
	}
	firstLine = strings.TrimRight(firstLine, "\r\n")

	// 判断是否为CONNECT方法
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) >= 2 && strings.ToUpper(parts[0]) == "CONNECT" {
		p.handleConnectFromLine(reader, parts[1], conn)
		return
	}

	// 普通HTTP请求：用http.ReadRequest解析剩余部分
	// 把第一行放回去
	remaining, _ := reader.ReadString(0) // 读取剩余缓冲
	fullRequest := firstLine + "\r\n" + remaining

	reqReader := bufio.NewReader(strings.NewReader(fullRequest))
	req, err := http.ReadRequest(reqReader)
	if err != nil {
		p.logger.Debug("parse http request failed", "error", err, "line", firstLine)
		return
	}

	// 读取请求体
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	// 镜像
	go p.mirror.Send(req, bodyBytes)

	// 转发到目标
	p.forwardHTTPRequest(req, bodyBytes, nil)
}

// handleConnectFromLine 处理CONNECT请求（从已读取的第一行开始）
func (p *MirrorProxy) handleConnectFromLine(reader *bufio.Reader, hostPort string, conn net.Conn) {
	// 读取剩余的请求头（直到空行）
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
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

	// 返回200
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// MITM：与客户端建立TLS
	domain := hostPort
	if idx := strings.LastIndex(domain, ":"); idx > 0 {
		domain = domain[:idx]
	}

	p.mitmConnect(conn, targetConn, domain)
}

// handleTLSConn 处理TLS连接（直接TLS接入，非CONNECT模式）
func (p *MirrorProxy) handleTLSConn(reader *bufio.Reader, conn net.Conn) {

	// TLS握手
	tlsConfig := p.certMgr.GetTLSConfig()
	// 支持HTTP/2 ALPN
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	tlsConn := tls.Server(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Debug("tls handshake failed", "error", err)
		return
	}
	tlsConn.SetDeadline(time.Time{})

	// 根据ALPN协商结果决定协议
	connState := tlsConn.ConnectionState()
	switch connState.NegotiatedProtocol {
	case "h2":
		p.handleHTTP2Conn(tlsConn)
	default:
		// http/1.1 或未协商
		p.handleHTTP1Conn(tlsConn)
	}
}

// handleHTTP1Conn 处理HTTP/1.x连接（含0.9/1.0/1.1 + WebSocket）
func (p *MirrorProxy) handleHTTP1Conn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		conn.SetDeadline(time.Now().Add(5 * time.Minute))

		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.logger.Debug("read http1 request failed", "error", err)
			}
			return
		}

		// 读取请求体
		var bodyBytes []byte
		if req.Body != nil {
			bodyBytes, _ = io.ReadAll(req.Body)
			req.Body.Close()
		}

		// 构建完整URL
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}

		// 镜像
		go p.mirror.Send(req, bodyBytes)

		// 检查WebSocket升级
		if isWebSocketUpgrade(req.Header) {
			p.handleWebSocket(conn, req, bodyBytes, reader)
			return
		}

		// 转发请求
		p.forwardHTTPRequest(req, bodyBytes, conn)
	}
}

// handleHTTP2Conn 处理HTTP/2连接
func (p *MirrorProxy) handleHTTP2Conn(conn net.Conn) {
	defer conn.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 读取请求体
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body.Close()
		}

		// 镜像
		go p.mirror.Send(r, bodyBytes)

		// 检查WebSocket（HTTP/2中通过CONNECT扩展实现）
		if isWebSocketUpgrade(r.Header) {
			p.handleH2WebSocket(w, r, bodyBytes)
			return
		}

		// 转发请求
		p.forwardH2Request(w, r, bodyBytes)
	})

	p.h2Server.ServeConn(conn, &http2.ServeConnOpts{
		Handler: handler,
	})
}

// handleWebSocket 处理HTTP/1.1 WebSocket升级
func (p *MirrorProxy) handleWebSocket(clientConn net.Conn, req *http.Request, bodyBytes []byte, reader *bufio.Reader) {
	// 连接目标WebSocket
	targetURL := *p.targetURL
	targetURL.Scheme = strings.Replace(targetURL.Scheme, "http", "ws", 1)
	targetURL.Path = req.URL.Path
	targetURL.RawQuery = req.URL.RawQuery

	// 建立到目标的TCP连接
	targetHost := p.targetURL.Host
	if !strings.Contains(targetHost, ":") {
		targetHost = targetHost + ":80"
	}

	targetConn, err := net.DialTimeout("tcp", targetHost, 10*time.Second)
	if err != nil {
		p.logger.Error("connect to ws target failed", "error", err)
		return
	}
	defer targetConn.Close()

	// 如果目标是wss，建立TLS
	if strings.HasPrefix(targetURL.Scheme, "wss") {
		tlsTarget := tls.Client(targetConn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsTarget.Handshake(); err != nil {
			return
		}
		defer tlsTarget.Close()
		targetConn = tlsTarget
	}

	// 转发WebSocket升级请求到目标
	req.URL = &targetURL
	if err := req.Write(targetConn); err != nil {
		p.logger.Error("write ws upgrade to target failed", "error", err)
		return
	}

	// 读取目标响应
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		p.logger.Error("read ws upgrade response failed", "error", err)
		return
	}

	// 将响应写回客户端
	resp.Write(clientConn)

	// 双向中继WebSocket帧
	go p.relayWSFrames(targetConn, clientConn, req, "response")
	p.relayWSFrames(clientConn, targetConn, req, "request")
}

// handleH2WebSocket 处理HTTP/2 WebSocket（RFC 8441）
func (p *MirrorProxy) handleH2WebSocket(w http.ResponseWriter, r *http.Request, bodyBytes []byte) {
	// HTTP/2 WebSocket比较少见，降级为普通请求处理
	p.forwardH2Request(w, r, bodyBytes)
}

// relayWSFrames 中继WebSocket帧，同时镜像
func (p *MirrorProxy) relayWSFrames(src, dst net.Conn, req *http.Request, direction string) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			// 镜像WebSocket帧数据
			go p.mirror.SendRaw(req.URL.String(), direction, buf[:n])

			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}
}

// mitmConnect MITM处理CONNECT隧道
func (p *MirrorProxy) mitmConnect(clientConn, targetConn net.Conn, domain string) {
	// 与客户端TLS握手
	tlsCert, err := p.certMgr.GetCertForHost(domain)
	if err != nil {
		p.logger.Error("get cert for host failed", "domain", domain, "error", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	tlsClientConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsClientConn.Handshake(); err != nil {
		p.logger.Debug("tls handshake with client failed", "domain", domain, "error", err)
		return
	}
	tlsClientConn.SetDeadline(time.Time{})
	defer tlsClientConn.Close()

	// 与目标建立TLS
	tlsTargetConn := tls.Client(targetConn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsTargetConn.Handshake(); err != nil {
		p.logger.Debug("tls handshake with target failed", "domain", domain, "error", err)
		return
	}
	defer tlsTargetConn.Close()

	// 根据ALPN协商结果
	connState := tlsClientConn.ConnectionState()
	switch connState.NegotiatedProtocol {
	case "h2":
		p.handleHTTP2MITM(tlsClientConn, tlsTargetConn, domain)
	default:
		p.handleHTTP1MITM(tlsClientConn, tlsTargetConn, domain)
	}
}

// handleHTTP1MITM MITM模式下的HTTP/1.x流量处理
func (p *MirrorProxy) handleHTTP1MITM(clientConn, targetConn net.Conn, domain string) {
	reader := bufio.NewReader(clientConn)
	for {
		clientConn.SetDeadline(time.Now().Add(5 * time.Minute))

		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.logger.Debug("read mitm http1 request failed", "domain", domain, "error", err)
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

		// 镜像
		go p.mirror.Send(req, bodyBytes)

		// WebSocket升级检测
		if isWebSocketUpgrade(req.Header) {
			// 转发升级请求
			if len(bodyBytes) > 0 {
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
			req.Write(targetConn)

			// 读取目标响应
			targetReader := bufio.NewReader(targetConn)
			resp, err := http.ReadResponse(targetReader, req)
			if err != nil {
				return
			}
			resp.Write(clientConn)

			// 双向中继
			go p.relayWSFrames(targetConn, clientConn, req, "response")
			p.relayWSFrames(clientConn, targetConn, req, "request")
			return
		}

		// 重建请求体并转发
		if len(bodyBytes) > 0 {
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}

		if err := req.Write(targetConn); err != nil {
			return
		}

		// 读取并转发响应
		targetReader := bufio.NewReader(targetConn)
		resp, err := http.ReadResponse(targetReader, req)
		if err != nil {
			return
		}

		// 剥离Alt-Svc头（防止HTTP/3升级）
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
	}
}

// handleHTTP2MITM MITM模式下的HTTP/2流量处理
func (p *MirrorProxy) handleHTTP2MITM(clientConn, targetConn net.Conn, domain string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body.Close()
		}

		// 镜像
		go p.mirror.Send(r, bodyBytes)

		// 转发
		p.forwardH2Request(w, r, bodyBytes)
	})

	p.h2Server.ServeConn(clientConn, &http2.ServeConnOpts{
		Handler: handler,
	})
}

// forwardHTTPRequest 转发HTTP/1.x请求到目标并回写响应
func (p *MirrorProxy) forwardHTTPRequest(req *http.Request, bodyBytes []byte, clientConn net.Conn) {
	forwardURL := *p.targetURL
	forwardURL.Path = req.URL.Path
	forwardURL.RawQuery = req.URL.RawQuery
	forwardURL.Fragment = req.URL.Fragment

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewBuffer(bodyBytes)
	}

	forwardReq, err := http.NewRequest(req.Method, forwardURL.String(), bodyReader)
	if err != nil {
		p.logger.Error("create forward request failed", "error", err)
		return
	}

	for key, values := range req.Header {
		for _, value := range values {
			forwardReq.Header.Add(key, value)
		}
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(forwardReq)
	if err != nil {
		p.logger.Error("forward request failed", "error", err)
		return
	}
	defer resp.Body.Close()

	// 剥离Alt-Svc
	resp.Header.Del("Alt-Svc")

	if clientConn != nil {
		// 直接写回连接
		for key, values := range resp.Header {
			for _, value := range values {
				w := bytes.NewBuffer(nil)
				w.WriteString(key + ": " + value + "\r\n")
				clientConn.Write(w.Bytes())
			}
		}
	}
}

// forwardH2Request 转发HTTP/2请求
func (p *MirrorProxy) forwardH2Request(w http.ResponseWriter, r *http.Request, bodyBytes []byte) {
	forwardURL := *p.targetURL
	forwardURL.Path = r.URL.Path
	forwardURL.RawQuery = r.URL.RawQuery

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

	// 使用HTTP/2 transport
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

	// 剥离Alt-Svc
	resp.Header.Del("Alt-Svc")

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// isWebSocketUpgrade 检测WebSocket升级请求
func isWebSocketUpgrade(h http.Header) bool {
	return strings.ToLower(h.Get("Upgrade")) == "websocket" ||
		strings.ToLower(h.Get("Connection")) == "upgrade" && strings.Contains(strings.ToLower(h.Get("Upgrade")), "websocket")
}

// bufferedConn 包装net.Conn使其可被bufio.Reader读取
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// relayBidirectional 双向中继（用于非HTTP协议的原始TCP流量）
func relayBidirectional(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		// 写端关闭后，通知读端
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copy(left, right)
	go copy(right, left)
	wg.Wait()
}
