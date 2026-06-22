// Package web embeds the Jōei admin console (浄衛 — The Purification Gate) and
// serves it as static assets. The console is a self-contained React single-page
// app (React + Babel loaded in the browser) driven by client-side mock data; it
// is baked into the binary via go:embed so it ships inside the distroless image
// with no extra files at runtime.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:generate go run github.com/ggwpLab/Jo-ei/internal/uibuild
//go:embed all:console
var consoleFiles embed.FS

// ConsoleHandler returns an http.Handler that serves the embedded console.
// Mount it under the "/console/" path prefix; requests are stripped of the
// "/console" prefix before hitting the embedded file server, so "/console/"
// serves index.html and "/console/styles.css" serves the stylesheet.
func ConsoleHandler() http.Handler {
	sub, err := fs.Sub(consoleFiles, "console")
	if err != nil {
		// The embed directive guarantees the "console" subtree exists, so this
		// can only fail on a programmer error (renamed dir without updating the
		// directive). Panic at construction time rather than serving 500s.
		panic("web: embedded console subtree missing: " + err.Error())
	}
	return http.StripPrefix("/console", http.FileServer(http.FS(sub)))
}

// faviconPath is the embedded icon served at the site-root /favicon.ico. The
// 32×32 PNG is the size browsers pick for a tab icon; modern browsers render a
// PNG served at /favicon.ico without needing a legacy ICO container.
const faviconPath = "console/favicon-32.png"

// FaviconHandler returns an http.Handler that serves /favicon.ico from the
// embedded console assets. Mount it at the exact root path "/favicon.ico" so
// browser auto-probes get a real icon instead of a 404 — no auth, since the
// icon is public. The file is read once at construction.
func FaviconHandler() http.Handler {
	data, err := consoleFiles.ReadFile(faviconPath)
	if err != nil {
		// Guaranteed present by the embed directive; a failure here is a
		// programmer error (renamed/removed asset), so fail loudly at startup.
		panic("web: embedded favicon missing: " + err.Error())
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if _, err := w.Write(data); err != nil {
			return
		}
	})
}
