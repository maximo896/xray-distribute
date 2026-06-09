package proxy

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestApplyChromeHeadersReplacesGoUserAgent(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", "Go-http-client/1.1")

	applyChromeHeaders(req)

	if ua := req.Header.Get("User-Agent"); !strings.Contains(ua, "Chrome/133") {
		t.Fatalf("expected Chrome user-agent, got %q", ua)
	}
	for _, key := range []string{"Accept", "Accept-Language", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform"} {
		if req.Header.Get(key) == "" {
			t.Fatalf("expected %s to be set", key)
		}
	}
}

func TestChromeForwardTransportFallsBackToHTTP1WhenH2Unsupported(t *testing.T) {
	var h1Called bool
	transport := &chromeForwardTransport{
		h2: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New(`unexpected ALPN protocol "http/1.1"`)
		}),
		h2Compat: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New(`unexpected ALPN protocol "http/1.1"`)
		}),
		h1: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			h1Called = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()

	if !h1Called {
		t.Fatal("expected HTTP/1 fallback to be called")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestChromeForwardTransportDoesNotFallbackForNonReplayableRequests(t *testing.T) {
	wantErr := errors.New("remote EOF after request")
	transport := &chromeForwardTransport{
		h2: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, wantErr
		}),
		h2Compat: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatal("HTTP/2 compat fallback should not run for non-replayable requests")
			return nil, nil
		}),
		h1: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatal("HTTP/1 fallback should not run for non-replayable requests")
			return nil, nil
		}),
		standard: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatal("standard fallback should not run for non-replayable requests")
			return nil, nil
		}),
	}

	req, err := http.NewRequest(http.MethodPost, "https://example.com/", io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	req.GetBody = nil
	if _, err := transport.RoundTrip(req); !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
}

func TestChromeForwardTransportTriesCompatH2BeforeHTTP1(t *testing.T) {
	var h2CompatCalled bool
	var h1Called bool
	transport := &chromeForwardTransport{
		h2: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("stream reset")
		}),
		h2Compat: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			h2CompatCalled = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
		h1: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			h1Called = true
			return nil, errors.New("should not call h1")
		}),
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()

	if !h2CompatCalled {
		t.Fatal("expected compat HTTP/2 fallback")
	}
	if h1Called {
		t.Fatal("did not expect HTTP/1 fallback after compat HTTP/2 succeeds")
	}
}

func TestChromeForwardTransportUsesStandardFallback(t *testing.T) {
	var standardCalled bool
	transport := &chromeForwardTransport{
		h2: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("h2 failed")
		}),
		h2Compat: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("h2 compat failed")
		}),
		h1: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("h1 failed")
		}),
		standard: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			standardCalled = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("ok")),
				Request:    req,
			}, nil
		}),
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()

	if !standardCalled {
		t.Fatal("expected standard fallback to be called")
	}
}
