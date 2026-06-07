package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDistFileServerIndexHTML(t *testing.T) {
	handler := DistFileServer()

	// 请求根路径应该返回 index.html
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("root path: expected 200, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("root path: expected text/html, got %s", ct)
	}

	body := w.Body.String()
	if body == "" {
		t.Error("root path: empty body")
	}
	t.Logf("root path body length: %d", len(body))
}

func TestDistFileServerAssets(t *testing.T) {
	handler := DistFileServer()

	// 请求 assets 下的 JS 文件
	req := httptest.NewRequest("GET", "/assets/index-B-WIXLSq.js", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("assets js: expected 200, got %d, body: %s", w.Code, w.Body.String()[:min(200, w.Body.Len())])
	}

	ct := w.Header().Get("Content-Type")
	t.Logf("assets js content-type: %s", ct)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
