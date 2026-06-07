package recordproxy

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/xray-distribute/internal/trafficdb"
)

type Proxy struct {
	addr   string
	db     *trafficdb.DB
	logger *slog.Logger
	server *http.Server
}

func New(addr string, db *trafficdb.DB, logger *slog.Logger) *Proxy {
	return &Proxy{addr: addr, db: db, logger: logger}
}

func (p *Proxy) Start() error {
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
	status := 0
	var respPreview string
	if p.db != nil {
		if _, err := p.db.RecordXRayRequest(r.Method, targetURL, headers, body, status, respPreview); err != nil {
			p.logger.Warn("record xray request failed", "error", err, "url", targetURL)
		}
	}

	outReq, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	outReq.Header = cloneHeader(r.Header)
	outReq.Header.Del("Proxy-Connection")

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	status = resp.StatusCode

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	preview := &limitedBuffer{limit: 4096}
	_, _ = io.Copy(w, io.TeeReader(resp.Body, preview))
	respPreview = preview.String()
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if p.db != nil {
		_, _ = p.db.RecordXRayRequest(r.Method, r.Host, cloneHeader(r.Header), nil, 0, "")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	target := r.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}
	serverConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		clientConn.Close()
		return
	}
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go transfer(serverConn, clientConn)
	go transfer(clientConn, serverConn)
}

func transfer(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
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

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len() < b.limit {
		remain := b.limit - b.buf.Len()
		if len(p) > remain {
			_, _ = b.buf.Write(p[:remain])
		} else {
			_, _ = b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}
