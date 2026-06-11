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
