package xray

import (
	"io"
	"testing"

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
