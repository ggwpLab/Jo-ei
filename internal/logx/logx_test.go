package logx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/logx"
)

func decodeLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
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

func TestMiddleware_ExposesOneIDToHandlerAndClient(t *testing.T) {
	var seen string
	h := logx.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = logx.RequestID(r.Context())
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	require.NotEmpty(t, seen)
	assert.Equal(t, seen, w.Header().Get(logx.HeaderRequestID))
}

func TestMiddleware_MintsDistinctIDs(t *testing.T) {
	h := logx.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ids := map[string]bool{}
	for range 3 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		ids[w.Header().Get(logx.HeaderRequestID)] = true
	}
	assert.Len(t, ids, 3)
}

func TestEnsure_KeepsExistingID(t *testing.T) {
	r, id := logx.Ensure(httptest.NewRequest(http.MethodGet, "/", nil))
	require.NotEmpty(t, id)
	_, again := logx.Ensure(r)
	assert.Equal(t, id, again, "a request that already has an ID keeps it")
}

func TestLogger_AddsRequestIDWhenPresent(t *testing.T) {
	var buf bytes.Buffer
	base := zerolog.New(&buf)

	with := logx.Logger(logx.WithRequestID(context.Background(), "req-1"), base)
	with.Info().Msg("with")
	without := logx.Logger(context.Background(), base)
	without.Info().Msg("without")

	lines := decodeLines(t, &buf)
	require.Len(t, lines, 2)
	assert.Equal(t, "req-1", lines[0]["request_id"])
	assert.NotContains(t, lines[1], "request_id")
}

func TestOutcome_LevelFollowsVerdict(t *testing.T) {
	cases := []struct {
		verdict string
		status  int
		level   string
	}{
		{gate.VerdictPass, 200, "info"},
		{gate.VerdictCache, 200, "info"},
		{gate.VerdictBlock, 403, "warn"},
		{gate.VerdictError, 404, "warn"},
		{gate.VerdictError, 502, "error"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		logx.Outcome(zerolog.New(&buf), gate.Event{Verdict: c.verdict, HTTPStatus: c.status})
		lines := decodeLines(t, &buf)
		require.Len(t, lines, 1)
		assert.Equal(t, c.level, lines[0]["level"], "%s/%d", c.verdict, c.status)
		assert.Equal(t, logx.MsgOutcome, lines[0]["message"])
	}
}

func TestOutcome_CarriesEventDetails(t *testing.T) {
	var buf bytes.Buffer
	published := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	logx.Outcome(zerolog.New(&buf), gate.Event{
		Verdict: gate.VerdictBlock, Gate: gate.GateMalware, Reason: "malware_found",
		HTTPStatus: 403, LatencyMS: 12, BlockedBy: []string{"malware"},
		MalwareEngine: "clamav", MalwareSignature: "Eicar",
		CVEs:        []gate.CVEFinding{{ID: "CVE-1"}, {ID: "CVE-2"}},
		PublishedAt: published,
	})
	l := decodeLines(t, &buf)[0]
	assert.Equal(t, "BLOCK", l["verdict"])
	assert.Equal(t, "malware", l["gate"])
	assert.Equal(t, "malware_found", l["reason"])
	assert.EqualValues(t, 403, l["status"])
	assert.EqualValues(t, 12, l["duration_ms"])
	assert.Equal(t, []any{"malware"}, l["blocked_by"])
	assert.Equal(t, []any{"CVE-1", "CVE-2"}, l["cves"])
	assert.Equal(t, "clamav", l["engine"])
	assert.Equal(t, "Eicar", l["signature"])
	assert.Equal(t, published.Format(time.RFC3339), l["published_at"])
	assert.NotContains(t, l, "block_until", "zero times are omitted")
}
