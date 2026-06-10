package recordproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xray-distribute/internal/cert"
	"github.com/xray-distribute/internal/trafficdb"
)

const recordQueueSize = 65536

type Proxy struct {
	addr     string
	db       *trafficdb.DB
	certMgr  *cert.CertManager
	logger   *slog.Logger
	server   *http.Server
	client   *http.Client
	recordCh chan recordJob
	once     sync.Once
}

type recordJob struct {
	method   string
	url      string
	headers  map[string][]string
	body     []byte
	status   int
	response string
}

func New(addr string, db *trafficdb.DB, certMgr *cert.CertManager, logger *slog.Logger) *Proxy {
	return &Proxy{
		addr:     addr,
		db:       db,
		certMgr:  certMgr,
		logger:   logger,
		client:   newForwardClient(),
		recordCh: make(chan recordJob, recordQueueSize),
	}
}

func newForwardClient() *http.Client {
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil,
			MaxIdleConns:          2048,
			MaxIdleConnsPerHost:   256,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func (p *Proxy) Start() error {
	p.once.Do(func() {
		go p.recordWorker()
	})
	p.server = &http.Server{
		Handler:      p,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return err
	}
	go func() {
		if err := p.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			p.logger.Error("recording proxy error", "error", err)
		}
	}()
	p.logger.Info("recording proxy started", "addr", p.addr)
	return nil
}

func (p *Proxy) recordWorker() {
	for job := range p.recordCh {
		if p.db == nil {
			continue
		}
		if _, err := p.db.RecordXRayRequest(job.method, job.url, job.headers, job.body, job.status, job.response); err != nil {
			p.logger.Warn("record xray request failed", "error", err, "url", job.url)
		}
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()

	targetURL := r.URL.String()
	if !r.URL.IsAbs() {
		scheme := "http"
		targetURL = scheme + "://" + r.Host + r.URL.RequestURI()
	}

	headers := cloneHeader(r.Header)
	p.enqueueRecord(recordJob{method: r.Method, url: targetURL, headers: headers, body: body})

	outReq, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	outReq.Header = cloneHeader(r.Header)
	cleanForwardHeaders(outReq.Header)

	resp, err := p.client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	hostPort := r.Host
	if hostPort == "" && r.URL != nil {
		hostPort = r.URL.Host
	}
	if !strings.Contains(hostPort, ":") {
		hostPort += ":443"
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}

	if p.certMgr == nil {
		p.logger.Warn("recording proxy MITM disabled: no cert manager", "host", hostPort)
		clientConn.Close()
		return
	}
	tlsCert, err := p.certMgr.GetCertForHost(host)
	if err != nil {
		p.logger.Warn("recording proxy MITM cert failed", "host", host, "error", err)
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		clientConn.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	buffered := &bufferedConn{Conn: clientConn, reader: rw.Reader}
	tlsConn := tls.Server(buffered, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Warn("recording proxy MITM handshake failed", "host", hostPort, "error", err)
		tlsConn.Close()
		return
	}
	tlsConn.SetDeadline(time.Time{})
	p.handleTLSHTTP(tlsConn, hostPort)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (p *Proxy) handleTLSHTTP(conn net.Conn, hostPort string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		conn.SetDeadline(time.Now().Add(5 * time.Minute))
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.logger.Debug("recording proxy read MITM request failed", "host", hostPort, "error", err)
			}
			return
		}
		if err := p.forwardMITMRequest(conn, req, hostPort); err != nil {
			p.logger.Debug("recording proxy forward MITM request failed", "host", hostPort, "error", err)
			return
		}
		if req.Close {
			return
		}
	}
}

func (p *Proxy) forwardMITMRequest(clientConn net.Conn, req *http.Request, hostPort string) error {
	body, _ := io.ReadAll(req.Body)
	req.Body.Close()

	targetURL := "https://" + hostPort + req.URL.RequestURI()
	headers := cloneHeader(req.Header)
	if req.Host != "" && !hasHeader(headers, "Host") {
		headers["Host"] = []string{req.Host}
	}
	p.enqueueRecord(recordJob{method: req.Method, url: targetURL, headers: headers, body: body})

	outReq, err := http.NewRequest(req.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	outReq.Header = cloneHeader(req.Header)
	cleanForwardHeaders(outReq.Header)
	outReq.Host = req.Host

	resp, err := p.client.Do(outReq)
	if err != nil {
		errResp := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       io.NopCloser(strings.NewReader("502 Bad Gateway")),
		}
		_ = errResp.Write(clientConn)
		return err
	}
	defer resp.Body.Close()
	resp.Header.Del("Alt-Svc")
	return resp.Write(clientConn)
}

func (p *Proxy) enqueueRecord(job recordJob) {
	if p.db == nil {
		return
	}
	select {
	case p.recordCh <- job:
	default:
		p.logger.Warn("recording proxy queue full, dropping request record", "method", job.method, "url", job.url)
	}
}

func transfer(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
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

func cloneHeader(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vals := range h {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}

func hasHeader(h map[string][]string, name string) bool {
	for key := range h {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}
