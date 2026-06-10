package recordproxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xray-distribute/internal/cert"
	"github.com/xray-distribute/internal/model"
	"github.com/xray-distribute/internal/trafficdb"
)

func TestProxyMITMRecordsHTTPSRequest(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	db, err := trafficdb.Open(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	certMgr, err := cert.NewCertManager(t.TempDir(), logger)
	if err != nil {
		t.Fatal(err)
	}

	oobDomain := "i-adb175-6zdq-r5pb.d8k7rr2aikaevhsch1mgo7ragtx84dq49.ukukk.uk"
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	proxyAddr := freeAddr(t)
	proxy := New(proxyAddr, db, certMgr, logger)
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}

	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certMgr.GetCACertPEM()) {
		t.Fatal("append ca cert failed")
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
		},
	}

	resp, err := client.Post(target.URL+"/vuln?callback="+url.QueryEscape("https://"+oobDomain+"/cb"), "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	var match *trafficdb.Match
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		match, err = db.RecordOOB(model.OOBInteraction{
			Protocol:      "dns",
			FullID:        oobDomain + ".",
			RawRequest:    ";; QUESTION SECTION:\n;" + oobDomain + ".\tIN\tA\n",
			RemoteAddress: "127.0.0.1",
			Timestamp:     time.Now(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if match != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if match == nil {
		t.Fatal("expected OOB interaction to match MITM-recorded HTTPS request")
	}
	if match.Source != "xray" || match.Method != http.MethodPost {
		t.Fatalf("unexpected match: %#v", match)
	}
	if !strings.HasPrefix(match.URL, "https://") {
		t.Fatalf("expected recorded HTTPS URL, got %q", match.URL)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}
