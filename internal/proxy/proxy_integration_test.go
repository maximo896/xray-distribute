package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xray-distribute/internal/cert"
	"github.com/xray-distribute/internal/mirror"
)

// 20个真实域名，覆盖H2、H1、大站、小站、国内、国外
var testDomains = []struct {
	domain  string
	comment string
}{
	{"httpbin.org", "HTTP测试站"},
	{"www.baidu.com", "百度H2"},
	{"www.google.com", "Google H2"},
	{"github.com", "GitHub H2"},
	{"www.cloudflare.com", "Cloudflare"},
	{"www.bing.com", "Bing"},
	{"www.apple.com", "Apple"},
	{"www.microsoft.com", "Microsoft"},
	{"www.amazon.com", "Amazon"},
	{"www.wikipedia.org", "Wikipedia"},
	{"www.reddit.com", "Reddit"},
	{"www.youtube.com", "YouTube"},
	{"www.twitter.com", "Twitter/X"},
	{"www.netflix.com", "Netflix"},
	{"www.stackoverflow.com", "StackOverflow"},
	{"www.bilibili.com", "B站"},
	{"www.zhihu.com", "知乎"},
	{"www.taobao.com", "淘宝"},
	{"example.com", "IETF示例站"},
	{"www.golang.org", "Go语言站"},
}

// TestRealDomainsIntegration 对20个真实域名进行完整代理测试
func TestRealDomainsIntegration(t *testing.T) {
	if os.Getenv("XRAY_RUN_REAL_DOMAINS") != "1" {
		t.Skip("set XRAY_RUN_REAL_DOMAINS=1 to run real-domain proxy integration test")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))

	certMgr, err := cert.NewCertManager(t.TempDir(), logger)
	if err != nil {
		t.Fatalf("create cert manager: %v", err)
	}

	sender := mirror.NewSender("http://127.0.0.1:1", "test-token", logger)
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

	// HTTPS客户端（通过代理，信任代理CA）
	httpsClient := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL("http://" + proxyAddr)),
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 先直接测试每个域名是否可达（不走代理），排除DNS问题
	var reachable []struct {
		domain  string
		comment string
	}
	directClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, tc := range testDomains {
		resp, err := directClient.Get("https://" + tc.domain)
		if err != nil {
			t.Logf("SKIP %s (%s): direct unreachable - %v", tc.domain, tc.comment, err)
			continue
		}
		resp.Body.Close()
		reachable = append(reachable, tc)
	}
	t.Logf("可达域名: %d/%d", len(reachable), len(testDomains))

	if len(reachable) == 0 {
		t.Skip("no reachable domains, skip integration test")
	}

	// 通过代理测试
	var successCount atomic.Int32
	var failCount atomic.Int32

	var wg sync.WaitGroup
	for _, tc := range reachable {
		wg.Add(1)
		go func(domain, comment string) {
			defer wg.Done()

			resp, err := httpsClient.Get("https://" + domain)
			if err != nil {
				t.Logf("FAIL %s (%s): %v", domain, comment, err)
				failCount.Add(1)
				return
			}
			defer resp.Body.Close()

			// 读取部分body
			io.ReadAll(io.LimitReader(resp.Body, 512))

			// 2xx和3xx都算代理工作正常
			// 403也算代理工作正常（目标站拒绝，不是代理问题）
			if resp.StatusCode < 500 {
				t.Logf("OK   %s (%s): status=%d", domain, comment, resp.StatusCode)
				successCount.Add(1)
			} else {
				t.Logf("FAIL %s (%s): status=%d", domain, comment, resp.StatusCode)
				failCount.Add(1)
			}
		}(tc.domain, tc.comment)
	}

	wg.Wait()

	s := successCount.Load()
	f := failCount.Load()
	t.Logf("结果: %d 成功, %d 失败 (共 %d 个可达域名)", s, f, len(reachable))

	// 至少80%的可达域名要通过
	if s < int32(len(reachable)*80/100) {
		t.Errorf("成功率过低: %d/%d (%.0f%%), 要求至少80%%", s, len(reachable), float64(s)/float64(len(reachable))*100)
	}
}
