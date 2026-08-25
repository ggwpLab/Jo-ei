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
