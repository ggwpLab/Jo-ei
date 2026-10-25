package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthcheckURL(t *testing.T) {
	for _, tc := range []struct {
		listen string
		ready  bool
		want   string
	}{
		{":8080", false, "http://127.0.0.1:8080/health"},
		{"0.0.0.0:9000", true, "http://127.0.0.1:9000/ready"},
		{"[::]:8080", false, "http://127.0.0.1:8080/health"},
		{"10.0.0.5:8080", false, "http://10.0.0.5:8080/health"},
	} {
		got, err := healthcheckURL(tc.listen, tc.ready)
		require.NoError(t, err, tc.listen)
		assert.Equal(t, tc.want, got, tc.listen)
	}
	_, err := healthcheckURL("bad", false)
	assert.Error(t, err)
}

func TestProbe(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ok.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()

	assert.NoError(t, probe(context.Background(), ok.URL))
	err := probe(context.Background(), down.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
}
