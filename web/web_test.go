package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConsoleHandlerServesIndex(t *testing.T) {
	srv := http.NewServeMux()
	srv.Handle("/console/", ConsoleHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/console/", nil)
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /console/ status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Jōei") {
		t.Errorf("index.html does not contain brand title; got %d bytes", len(body))
	}
	if !strings.Contains(body, `id="root"`) {
		t.Errorf("index.html missing React mount point")
	}
}

func TestConsoleHandlerServesAssets(t *testing.T) {
	srv := http.NewServeMux()
	srv.Handle("/console/", ConsoleHandler())

	for _, asset := range []string{"styles.css", "screens.css", "app.bundle.js", "favicon-32.png", "favicon-180.png"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/console/"+asset, nil)
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET /console/%s status = %d, want 200", asset, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET /console/%s returned empty body", asset)
		}
	}
}

func TestConsoleIndexIsPrebuilt(t *testing.T) {
	srv := http.NewServeMux()
	srv.Handle("/console/", ConsoleHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/console/", nil)
	srv.ServeHTTP(rec, req)
	body := rec.Body.String()

	// No CDN, no in-browser compilation.
	for _, banned := range []string{"unpkg.com", "text/babel", "babel"} {
		if strings.Contains(body, banned) {
			t.Errorf("index.html still references %q; console must be prebuilt and self-hosted", banned)
		}
	}
	// Loads the prebuilt bundle and the vendored React.
	for _, want := range []string{"app.bundle.js", "vendor/react.production.min.js", "vendor/react-dom.production.min.js"} {
		if !strings.Contains(body, want) {
			t.Errorf("index.html does not reference %q", want)
		}
	}
}

func TestFaviconHandlerServesPNG(t *testing.T) {
	srv := http.NewServeMux()
	srv.Handle("/favicon.ico", FaviconHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /favicon.ico status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	// PNG magic number: \x89PNG.
	if body := rec.Body.Bytes(); len(body) < 4 || string(body[1:4]) != "PNG" {
		t.Errorf("body is not a PNG; got %d bytes", len(body))
	}
}

func TestConsoleHandlerRedirectsBareConsole(t *testing.T) {
	srv := http.NewServeMux()
	srv.Handle("/console/", ConsoleHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	srv.ServeHTTP(rec, req)

	if rec.Code < 300 || rec.Code >= 400 {
		t.Fatalf("GET /console status = %d, want a 3xx redirect", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/console/" {
		t.Errorf("redirect Location = %q, want /console/", loc)
	}
}

func TestConsoleServesVendoredReact(t *testing.T) {
	srv := http.NewServeMux()
	srv.Handle("/console/", ConsoleHandler())

	for _, asset := range []string{
		"vendor/react.production.min.js",
		"vendor/react-dom.production.min.js",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/console/"+asset, nil)
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET /console/%s status = %d, want 200", asset, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET /console/%s returned empty body", asset)
		}
	}
}
