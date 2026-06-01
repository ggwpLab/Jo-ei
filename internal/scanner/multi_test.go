package scanner_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/sca-proxy/sca-proxy/internal/proxy"
	"github.com/sca-proxy/sca-proxy/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubScanner struct {
	result *proxy.AVResult
	err    error
	calls  *int
}

func (s stubScanner) Scan(_ context.Context, _ string) (*proxy.AVResult, error) {
	if s.calls != nil {
		*s.calls++
	}
	return s.result, s.err
}

func clean(engine string) stubScanner {
	return stubScanner{result: &proxy.AVResult{Clean: true, Engine: engine}}
}

func TestMultiScanner_AllClean(t *testing.T) {
	m := scanner.NewMultiScanner(clean("clamav"), clean("icap"))
	res, err := m.Scan(context.Background(), "/tmp/x")
	require.NoError(t, err)
	assert.True(t, res.Clean)
}

func TestMultiScanner_OneDetects(t *testing.T) {
	infected := stubScanner{result: &proxy.AVResult{Clean: false, Signature: "EICAR", Engine: "icap"}}
	m := scanner.NewMultiScanner(clean("clamav"), infected)
	res, err := m.Scan(context.Background(), "/tmp/x")
	require.NoError(t, err)
	assert.False(t, res.Clean)
	assert.Equal(t, "EICAR", res.Signature)
	assert.Equal(t, "icap", res.Engine)
}

func TestMultiScanner_ErrorFailsClosed(t *testing.T) {
	failing := stubScanner{err: fmt.Errorf("clamd down")}
	m := scanner.NewMultiScanner(failing, clean("icap"))
	_, err := m.Scan(context.Background(), "/tmp/x")
	assert.Error(t, err)
}

func TestMultiScanner_ShortCircuitsOnDetection(t *testing.T) {
	var secondCalls int
	infected := stubScanner{result: &proxy.AVResult{Clean: false, Signature: "EICAR", Engine: "clamav"}}
	second := stubScanner{result: &proxy.AVResult{Clean: true}, calls: &secondCalls}
	m := scanner.NewMultiScanner(infected, second)
	_, err := m.Scan(context.Background(), "/tmp/x")
	require.NoError(t, err)
	assert.Equal(t, 0, secondCalls, "later scanner must not run after a detection")
}

func TestMultiScanner_Empty(t *testing.T) {
	m := scanner.NewMultiScanner()
	res, err := m.Scan(context.Background(), "/tmp/x")
	require.NoError(t, err)
	assert.True(t, res.Clean)
}
