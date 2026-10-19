package proxy_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/config"
	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/logx"
	"github.com/ggwpLab/Jo-ei/internal/proxy"
	"github.com/ggwpLab/Jo-ei/internal/proxy/adapters"
	"github.com/ggwpLab/Jo-ei/internal/supplychain"
)

func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m), line)
		out = append(out, m)
	}
	return out
}

// requireCommonFields asserts every line carries the request's ID and the
// writing component, so any one line can be traced back to its request.
func requireCommonFields(t *testing.T, lines []map[string]any, requestID, component string) {
	t.Helper()
	require.NotEmpty(t, lines, "expected log output")
	for _, l := range lines {
		assert.Equal(t, requestID, l["request_id"], "line %v", l)
		assert.Equal(t, component, l["component"], "line %v", l)
	}
}

func withRequestID(r *http.Request, id string) *http.Request {
	return r.WithContext(logx.WithRequestID(r.Context(), id))
}

func TestLogging_DownloadEndsWithOneOutcomeLine(t *testing.T) {
	upstream := makeUpstream(t, "requests", "2.31.0", 48)
	defer upstream.Close()

	var buf bytes.Buffer
	rec := &fakeRecorder{}
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:  adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:   supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:    newFakeCache(),
		Logger:   zerolog.New(&buf).Level(zerolog.DebugLevel),
		Recorder: rec,
	})

	req := withRequestID(httptest.NewRequest(http.MethodGet, "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl", nil), "rid-dl")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	lines := logLines(t, &buf)
	requireCommonFields(t, lines, "rid-dl", "proxy")

	var outcomes []map[string]any
	for _, l := range lines {
		if l["message"] == logx.MsgOutcome {
			outcomes = append(outcomes, l)
		}
	}
	require.Len(t, outcomes, 1, "one outcome line per gated request; log:\n%s", buf.String())
	o := outcomes[0]
	assert.Equal(t, "info", o["level"])
	assert.Equal(t, gate.VerdictPass, o["verdict"])
	assert.Equal(t, "pypi", o["ecosystem"])
	assert.Equal(t, "requests", o["package"])
	assert.Equal(t, "2.31.0", o["version"])
	assert.EqualValues(t, http.StatusOK, o["status"])

	assert.Equal(t, "rid-dl", rec.last(t).RequestID, "telemetry and logs share the request ID")
}

func TestLogging_BlockedDownloadLogsAtWarn(t *testing.T) {
	upstream := makeUpstream(t, "requests", "2.31.0", 1)
	defer upstream.Close()

	var buf bytes.Buffer
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewPyPIAdapter([]string{upstream.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newFakeCache(),
		Logger:  zerolog.New(&buf),
	})

	req := withRequestID(httptest.NewRequest(http.MethodGet, "/packages/py3/r/requests/requests-2.31.0-py3-none-any.whl", nil), "rid-block")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusLocked, w.Code)
	assert.Contains(t, w.Body.String(), `"request_id":"rid-block"`, "error body reuses the request ID")

	lines := logLines(t, &buf)
	requireCommonFields(t, lines, "rid-block", "proxy")
	last := lines[len(lines)-1]
	assert.Equal(t, logx.MsgOutcome, last["message"])
	assert.Equal(t, "warn", last["level"])
	assert.Equal(t, gate.VerdictBlock, last["verdict"])
	assert.Equal(t, gate.GateSupply, last["gate"])
	assert.NotEmpty(t, last["block_until"])
}

func TestLogging_MetadataFilterCarriesRequestID(t *testing.T) {
	fresh := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	old := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":      "left-pad",
			"dist-tags": map[string]string{"latest": "1.3.0"},
			"time":      map[string]string{"1.2.0": old, "1.3.0": fresh},
			"versions": map[string]any{
				"1.2.0": map[string]any{"name": "left-pad", "version": "1.2.0"},
				"1.3.0": map[string]any{"name": "left-pad", "version": "1.3.0"},
			},
		})
	}))
	defer upstream.Close()

	var buf bytes.Buffer
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter:             adapters.NewNPMAdapter([]string{upstream.URL}),
		Filter:              supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:               newFakeCache(),
		Logger:              zerolog.New(&buf),
		MetadataFilterMaxMB: 1,
	})

	req := withRequestID(httptest.NewRequest(http.MethodGet, "/left-pad", nil), "rid-meta")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	lines := logLines(t, &buf)
	requireCommonFields(t, lines, "rid-meta", "metadata_filter")
	assert.Equal(t, "npm", lines[0]["ecosystem"])
	assert.Equal(t, "left-pad", lines[0]["package"])
}

func TestLogging_TransparentFailureCarriesRequestIDAndPath(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer broken.Close()

	var buf bytes.Buffer
	h := proxy.NewHandler(proxy.HandlerConfig{
		Adapter: adapters.NewNPMAdapter([]string{broken.URL}),
		Filter:  supplychain.NewFilter(config.SupplyChainConfig{MinAgeHours: 24, Mode: "enforce"}, nil),
		Cache:   newFakeCache(),
		Logger:  zerolog.New(&buf),
	})

	req := withRequestID(httptest.NewRequest(http.MethodGet, "/left-pad", nil), "rid-tp")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadGateway, w.Code)

	lines := logLines(t, &buf)
	requireCommonFields(t, lines, "rid-tp", "proxy")
	assert.Equal(t, "/left-pad", lines[0]["path"])
}

func TestLogging_MuxUnknownPrefixCarriesRequestID(t *testing.T) {
	var buf bytes.Buffer
	m := proxy.NewMux(nil, nil, zerolog.New(&buf))

	w := httptest.NewRecorder()
	m.ServeHTTP(w, withRequestID(httptest.NewRequest(http.MethodGet, "/nope/x", nil), "rid-mux"))
	require.Equal(t, http.StatusNotFound, w.Code)

	requireCommonFields(t, logLines(t, &buf), "rid-mux", "proxy")
}
