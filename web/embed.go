package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
)

//go:embed dist/* dist/**/*
var distFS embed.FS

// DistFileServer 返回前端静态文件Handler
func DistFileServer() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(sub))
}

// PanelHandler serves the embedded SPA and falls back to index.html for client routes.
func PanelHandler(apiHandler http.Handler) http.Handler {
	fileServer := DistFileServer()
	mux := http.NewServeMux()
	if apiHandler != nil {
		mux.Handle("/api/", apiHandler)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isClientRoute(r.URL.Path) {
			serveIndex(w)
			return
		}
		fileServer.ServeHTTP(w, r)
	}))
	return mux
}

func serveIndex(w http.ResponseWriter) {
	body, err := distFS.ReadFile("dist/index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func isClientRoute(path string) bool {
	if path == "/" || path == "" {
		return true
	}
	if strings.HasPrefix(path, "/assets/") {
		return false
	}
	ext := filepath.Ext(path)
	return ext == ""
}
