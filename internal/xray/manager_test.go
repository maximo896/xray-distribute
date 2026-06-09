package xray

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xray-distribute/internal/model"
)

func TestBuildXRayRequestSetsHostFromMirrorRequest(t *testing.T) {
	req, err := buildXRayRequest(&model.MirrorRequest{
		Method: "GET",
		URL:    "https://10.0.0.1:8443/path",
		Host:   "app.example.com",
		Headers: map[string][]string{
			"Host":       {"ignored.example.com"},
			"User-Agent": {"test"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if req.Host != "app.example.com" {
		t.Fatalf("expected Host to come from mirror request, got %q", req.Host)
	}
	if req.Header.Get("Host") != "" {
		t.Fatalf("Host must be set on Request.Host, not ordinary headers: %q", req.Header.Get("Host"))
	}
	if req.Header.Get("User-Agent") != "test" {
		t.Fatalf("missing copied header")
	}
}

func TestBuildXRayRequestFallsBackToHeaderHostForOldMirrorData(t *testing.T) {
	req, err := buildXRayRequest(&model.MirrorRequest{
		Method: "POST",
		URL:    "https://10.0.0.1:8443/path",
		Headers: map[string][]string{
			"host": {"legacy.example.com"},
		},
		Body: []byte("hello"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if req.Host != "legacy.example.com" {
		t.Fatalf("expected Host to come from legacy header, got %q", req.Host)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Fatalf("unexpected body %q", body)
	}
}

func TestBuildXRayRequestFallsBackToURLHost(t *testing.T) {
	req, err := buildXRayRequest(&model.MirrorRequest{
		Method:  "GET",
		URL:     "https://fallback.example.com/path",
		Headers: map[string][]string{},
	})
	if err != nil {
		t.Fatal(err)
	}

	if req.Host != "fallback.example.com" {
		t.Fatalf("expected Host to fall back to URL host, got %q", req.Host)
	}
}

func TestParseVulnFromRawSupportsXRayReportFormat(t *testing.T) {
	m := NewManager("", "", "", "", "", "", "", nil)
	raw := json.RawMessage(`{
		"create_time": 1780965158360,
		"detail": {
			"addr": "https://httpbin.org:443/get",
			"payload": "",
			"snapshot": [[
				"GET /get HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n",
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
			]]
		},
		"plugin": "baseline/cors/any-origin-with-credential",
		"target": {"url": "https://httpbin.org:443/get"}
	}`)

	v := m.parseVulnFromRaw(raw)
	if v == nil {
		t.Fatal("expected xray report item to parse as vulnerability")
	}
	if v.Title != "baseline/cors/any-origin-with-credential" {
		t.Fatalf("unexpected title %q", v.Title)
	}
	if v.URL != "https://httpbin.org:443/get" {
		t.Fatalf("unexpected url %q", v.URL)
	}
	if v.Severity != "info" {
		t.Fatalf("unexpected severity %q", v.Severity)
	}
	if !strings.Contains(v.Request, "GET /get") || !strings.Contains(v.Response, "200 OK") {
		t.Fatalf("snapshot was not copied into request/response: %#v", v)
	}
	wantTime := time.UnixMilli(1780965158360)
	if !v.CreatedAt.Equal(wantTime) {
		t.Fatalf("unexpected created_at %s, want %s", v.CreatedAt, wantTime)
	}
}

func TestParseVulnsFromRawSupportsArrays(t *testing.T) {
	m := NewManager("", "", "", "", "", "", "", nil)
	vulns := m.parseVulnsFromRaw(json.RawMessage(`[
		{"plugin":"p1","target":{"url":"https://one.example"},"detail":{}},
		{"plugin":"p2","target":{"url":"https://two.example"},"detail":{}}
	]`))
	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulns, got %d", len(vulns))
	}
	if vulns[0].Title != "p1" || vulns[1].URL != "https://two.example" {
		t.Fatalf("unexpected parsed vulns: %#v", vulns)
	}
}

func TestParseVulnFromRawIgnoresNonVulnEvents(t *testing.T) {
	m := NewManager("", "", "", "", "", "", "", nil)
	v := m.parseVulnFromRaw(json.RawMessage(`{"type":"status","message":"started"}`))
	if v != nil {
		t.Fatalf("expected non-vuln event to be ignored: %#v", v)
	}
}
