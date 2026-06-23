package dockerproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/proxy"
)

func TestNewAssemblesHandler(t *testing.T) {
	srvURL, repo, ref := newGateTestServer(t)
	h := New(HandlerDeps{
		Upstreams:     []string{srvURL},
		Scanner:       stubScanner{},
		AV:            stubAV{},
		Filter:        allowFilter{},
		Policy:        findingPolicy{},
		Cache:         newFakeCache(),
		MaxLayerBytes: 0,
		Recorder:      &recspy{},
		Logger:        zerolog.Nop(),
	})
	req := httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("assembled handler status = %d", w.Code)
	}
}

type recspy struct{ events []proxy.Event }

func (r *recspy) Record(e proxy.Event) { r.events = append(r.events, e) }

func newTestHandler(t *testing.T, sc ImageScanner, av proxy.AVScanner, rec proxy.Recorder) (*Handler, string, string) {
	srvURL, repo, ref := newGateTestServer(t)
	adapter := NewAdapter([]string{srvURL})
	store := newVerdictStore(newFakeCache())
	gate := newManifestGate(gateDeps{
		adapter: adapter, scanner: sc, av: av,
		filter: allowFilter{}, policy: findingPolicy{},
		store: store, logger: zerolog.Nop(),
	})
	h := NewHandler(Config{Adapter: adapter, Gate: gate, Store: store, Recorder: rec, Logger: zerolog.Nop()})
	return h, repo, ref
}

func TestHandlerPing(t *testing.T) {
	h, _, _ := newTestHandler(t, stubScanner{}, stubAV{}, &recspy{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ping status = %d", w.Code)
	}
	if w.Header().Get("Docker-Distribution-API-Version") != "registry/2.0" {
		t.Error("missing API version header")
	}
}

func TestHandlerManifestCleanServes(t *testing.T) {
	rec := &recspy{}
	h, repo, ref := newTestHandler(t, stubScanner{}, stubAV{}, rec)
	req := httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("manifest status = %d, body=%s", w.Code, w.Body.String())
	}
	if len(rec.events) != 1 || rec.events[0].Verdict != proxy.VerdictPass {
		t.Errorf("events = %+v", rec.events)
	}
}

func TestHandlerManifestCVEBlocked403(t *testing.T) {
	rec := &recspy{}
	h, repo, ref := newTestHandler(t,
		stubScanner{findings: []proxy.CVEFinding{{ID: "CVE-1", Severity: proxy.SeverityHigh}}},
		stubAV{}, rec)
	req := httptest.NewRequest(http.MethodGet, "/"+repo+"/manifests/"+ref, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "DENIED") {
		t.Errorf("body = %s", w.Body.String())
	}
	if len(rec.events) != 1 || rec.events[0].Verdict != proxy.VerdictBlock {
		t.Errorf("events = %+v", rec.events)
	}
}
