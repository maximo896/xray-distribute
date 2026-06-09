package recordproxy

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xray-distribute/internal/trafficdb"
)

const recordQueueSize = 65536

type Proxy struct {
	addr     string
	db       *trafficdb.DB
	logger   *slog.Logger
	server   *http.Server
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

func New(addr string, db *trafficdb.DB, logger *slog.Logger) *Proxy {
	return &Proxy{
		addr:     addr,
		db:       db,
		logger:   logger,
		recordCh: make(chan recordJob, recordQueueSize),
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
	outReq.Header.Del("Proxy-Connection")

	resp, err := http.DefaultTransport.RoundTrip(outReq)
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
	p.enqueueRecord(recordJob{method: r.Method, url: r.Host, headers: cloneHeader(r.Header)})

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

func cloneHeader(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, vals := range h {
		cp := make([]string, len(vals))
		copy(cp, vals)
		out[k] = cp
	}
	return out
}
