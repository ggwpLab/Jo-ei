package upstream_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ggwpLab/Jo-ei/internal/httpx"
	"github.com/ggwpLab/Jo-ei/internal/upstream"
)

func TestAttempts_AllNotFound(t *testing.T) {
	tests := []struct {
		name     string
		statuses []int
		want     bool
	}{
		{"every mirror 404", []int{http.StatusNotFound, http.StatusNotFound}, true},
		{"404 and 410 both count as absent", []int{http.StatusNotFound, http.StatusGone}, true},
		{"a transport error is not an absence", []int{0, http.StatusNotFound}, false},
		{"a server error is not an absence", []int{http.StatusInternalServerError}, false},
		{"no attempts at all", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var atts upstream.Attempts
			for _, s := range tc.statuses {
				atts.Add("https://mirror", s, fmt.Errorf("boom"), time.Millisecond)
			}
			if got := atts.AllNotFound(); got != tc.want {
				t.Fatalf("AllNotFound() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAttempts_ErrorMentionsEveryMirror(t *testing.T) {
	var atts upstream.Attempts
	atts.Add("https://mirror-a", 0, errors.New("x509: certificate signed by unknown authority"), 11*time.Millisecond)
	atts.Add("https://mirror-b", http.StatusNotFound, errors.New("upstream returned HTTP 404"), 92*time.Millisecond)

	msg := upstream.Attempts(atts).Error()
	for _, want := range []string{"all 2 upstreams failed", "mirror-a", "x509", "mirror-b", "HTTP 404"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("Error() = %q, missing %q", msg, want)
		}
	}
}

func TestAttempts_UnwrapReachesIndividualErrors(t *testing.T) {
	sentinel := errors.New("sentinel")
	var atts upstream.Attempts
	atts.Add("https://mirror-a", 0, fmt.Errorf("dialing: %w", sentinel), time.Millisecond)
	atts.Add("https://mirror-b", http.StatusNotFound, errors.New("HTTP 404"), time.Millisecond)

	var err error = atts
	if !errors.Is(err, sentinel) {
		t.Fatal("errors.Is did not reach the wrapped sentinel through Unwrap")
	}
}

func TestAttemptsFrom_RecoversThroughWrapping(t *testing.T) {
	var atts upstream.Attempts
	atts.Add("https://mirror-a", http.StatusNotFound, errors.New("HTTP 404"), time.Millisecond)

	wrapped := fmt.Errorf("resolving manifest lib/nginx:1.25: %w", error(atts))
	got, ok := upstream.AttemptsFrom(wrapped)
	if !ok {
		t.Fatal("AttemptsFrom did not recover Attempts through a wrapping error")
	}
	if len(got) != 1 || got[0].Status != http.StatusNotFound {
		t.Fatalf("recovered %+v, want the single 404 attempt", got)
	}
	if _, ok := upstream.AttemptsFrom(errors.New("unrelated")); ok {
		t.Fatal("AttemptsFrom reported success on an unrelated error")
	}
}

func TestAttempts_MarshalZerologArray(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	var atts upstream.Attempts
	atts.Add("https://mirror-a", 0, errors.New("tls handshake failed"), 11*time.Millisecond)
	atts.Add("https://mirror-b", http.StatusNotFound, errors.New("upstream returned HTTP 404"), 92*time.Millisecond)
	logger.Warn().Array("upstream_attempts", atts).Msg("all upstreams failed")

	var entry struct {
		Attempts []struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
			Error  string `json:"error"`
			MS     int64  `json:"ms"`
		} `json:"upstream_attempts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("log line is not valid JSON: %v (%s)", err, buf.String())
	}
	if len(entry.Attempts) != 2 {
		t.Fatalf("logged %d attempts, want 2: %s", len(entry.Attempts), buf.String())
	}
	if entry.Attempts[0].Status != 0 || entry.Attempts[0].Error != "tls handshake failed" {
		t.Fatalf("first attempt = %+v, want status 0 with the TLS error", entry.Attempts[0])
	}
	if entry.Attempts[1].Status != http.StatusNotFound || entry.Attempts[1].MS != 92 {
		t.Fatalf("second attempt = %+v, want status 404 and ms 92", entry.Attempts[1])
	}
}

func TestAdd_StripsCredentialsFromURL(t *testing.T) {
	var atts upstream.Attempts
	atts.Add("https://bob:hunter2@mirror.corp/repo", http.StatusNotFound, errors.New("HTTP 404"), time.Millisecond)

	if got := atts[0].URL; got != "https://mirror.corp/repo" {
		t.Fatalf("URL = %q, want credentials stripped", got)
	}
}

func TestAttempts_EmptyErrorText(t *testing.T) {
	var atts upstream.Attempts
	if msg := atts.Error(); msg != "no upstream attempts were made" {
		t.Fatalf("Error() = %q on an empty Attempts", msg)
	}
}

// fakeThrottles maps host → (status that opened its circuit, time left).
type fakeThrottles map[string]struct {
	status  int
	retryIn time.Duration
}

func (f fakeThrottles) Throttle(host string) (int, time.Duration, bool) {
	t, ok := f[host]
	return t.status, t.retryIn, ok
}

func TestAttempts_Throttled(t *testing.T) {
	circuitOpen := fmt.Errorf("b.example: %w", httpx.ErrCircuitOpen)
	type att struct {
		url    string
		status int
		err    error
	}
	lookup := fakeThrottles{
		"a.example":      {http.StatusTooManyRequests, 9 * time.Second},
		"b.example":      {http.StatusServiceUnavailable, 4 * time.Second},
		"c.example:8443": {http.StatusTooManyRequests, 2 * time.Second},
	}
	tests := []struct {
		name       string
		atts       []att
		lookup     upstream.ThrottleLookup
		wantOK     bool
		wantStatus int
		wantRetry  time.Duration
	}{
		{"404 plus 429 is a throttle", []att{{"https://x.example/p", 404, nil}, {"https://a.example/p", 429, nil}}, lookup, true, 429, 9 * time.Second},
		{"404 plus 503 answers 503", []att{{"https://x.example/p", 404, nil}, {"https://b.example/p", 503, nil}}, lookup, true, 503, 4 * time.Second},
		{"410 counts as absent", []att{{"https://x.example/p", 410, nil}, {"https://a.example/p", 429, nil}}, lookup, true, 429, 9 * time.Second},
		{"any 429 wins over 503; shortest retry", []att{{"https://a.example/p", 429, nil}, {"https://b.example/p", 503, nil}}, lookup, true, 429, 4 * time.Second},
		{"breaker fast-fail takes the status that opened it", []att{{"https://x.example/p", 404, nil}, {"https://b.example/p", 0, circuitOpen}}, lookup, true, 503, 4 * time.Second},
		{"breaker fast-fail without a lookup reads as 429", []att{{"https://x.example/p", 404, nil}, {"https://b.example/p", 0, circuitOpen}}, nil, true, 429, 0},
		{"host with a port, credentials stripped", []att{{"https://u:p@c.example:8443/p", 429, nil}}, lookup, true, 429, 2 * time.Second},
		{"throttled host unknown to the lookup: no retry hint", []att{{"https://z.example/p", 429, nil}}, lookup, true, 429, 0},
		{"a real 5xx keeps it a 502", []att{{"https://x.example/p", 502, nil}, {"https://a.example/p", 429, nil}}, lookup, false, 0, 0},
		{"a connection error keeps it a 502", []att{{"https://x.example/p", 0, errors.New("dial tcp: refused")}, {"https://a.example/p", 429, nil}}, lookup, false, 0, 0},
		{"every mirror 404 is not a throttle", []att{{"https://x.example/p", 404, nil}}, lookup, false, 0, 0},
		{"no attempts", nil, lookup, false, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a upstream.Attempts
			for _, at := range tt.atts {
				a.Add(at.url, at.status, at.err, time.Millisecond)
			}
			status, retry, ok := a.Throttled(tt.lookup)
			if ok != tt.wantOK || status != tt.wantStatus || retry != tt.wantRetry {
				t.Fatalf("Throttled = (%d, %v, %v), want (%d, %v, %v)", status, retry, ok, tt.wantStatus, tt.wantRetry, tt.wantOK)
			}
		})
	}
}
