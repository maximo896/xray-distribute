package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDistFileServerIndexHTML(t *testing.T) {
	handler := DistFileServer()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("root path: expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("root path: expected text/html, got %s", ct)
	}
	if body := w.Body.String(); body == "" {
		t.Error("root path: empty body")
	}
}

func TestDistFileServerAssets(t *testing.T) {
	handler := DistFileServer()

	req := httptest.NewRequest(http.MethodGet, findEmbeddedAsset(t, ".js"), nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("assets js: expected 200, got %d, body: %s", w.Code, w.Body.String()[:min(200, w.Body.Len())])
	}
}

func TestPanelHandlerServesSPARoutes(t *testing.T) {
	handler := PanelHandler(nil)

	for _, path := range []string{"/", "/agents", "/vulns", "/xray", "/webhooks"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, w.Code)
		}
		if !strings.Contains(w.Body.String(), `<div id="app"></div>`) {
			t.Fatalf("%s: expected SPA index.html", path)
		}
	}
}

func TestPanelHandlerKeepsAPIAndAssetsSeparate(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	handler := PanelHandler(api)

	apiReq := httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil)
	apiResp := httptest.NewRecorder()
	handler.ServeHTTP(apiResp, apiReq)
	if apiResp.Code != http.StatusOK || !strings.Contains(apiResp.Body.String(), `"ok":true`) {
		t.Fatalf("api route was not handled by api handler: code=%d body=%q", apiResp.Code, apiResp.Body.String())
	}

	assetReq := httptest.NewRequest(http.MethodGet, findEmbeddedAsset(t, ".js"), nil)
	assetResp := httptest.NewRecorder()
	handler.ServeHTTP(assetResp, assetReq)
	if assetResp.Code != http.StatusOK {
		t.Fatalf("asset route expected 200, got %d", assetResp.Code)
	}
	if strings.Contains(assetResp.Body.String(), `<div id="app"></div>`) {
		t.Fatal("asset route unexpectedly returned SPA index")
	}
}

func findEmbeddedAsset(t *testing.T, suffix string) string {
	t.Helper()
	entries, err := distFS.ReadDir("dist/assets")
	if err != nil {
		t.Fatalf("read embedded assets: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), suffix) {
			return "/assets/" + entry.Name()
		}
	}
	t.Fatalf("no embedded asset with suffix %s", suffix)
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
