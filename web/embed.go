package web

import (
	"embed"
	"io/fs"
	"net/http"
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
