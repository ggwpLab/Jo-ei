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

	for _, asset := range []string{"styles.css", "screens.css", "data.js", "app.jsx"} {
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
