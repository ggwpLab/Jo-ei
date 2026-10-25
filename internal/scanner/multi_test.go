package scanner_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ggwpLab/Jo-ei/internal/gate"
	"github.com/ggwpLab/Jo-ei/internal/scanner"
)

type stubScanner struct {
	result *gate.AVResult
	err    error
}

func (s stubScanner) Scan(_ context.Context, _ string) (*gate.AVResult, error) {
	return s.result, s.err
}

func clean(engine string) stubScanner {
	return stubScanner{result: &gate.AVResult{Clean: true, Engine: engine}}
}

func TestMultiScanner_AllClean(t *testing.T) {
	m := scanner.NewMultiScanner(clean("clamav"), clean("icap"))
	res, err := m.Scan(context.Background(), "/tmp/x")
	require.NoError(t, err)
	assert.True(t, res.Clean)
}

func TestMultiScanner_OneDetects(t *testing.T) {
	infected := stubScanner{result: &gate.AVResult{Clean: false, Signature: "EICAR", Engine: "icap"}}
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

// funcScanner adapts a function to gate.AVScanner.
type funcScanner func(ctx context.Context) (*gate.AVResult, error)

func (f funcScanner) Scan(ctx context.Context, _ string) (*gate.AVResult, error) { return f(ctx) }

// Each engine blocks until every engine has started: only a concurrent run
// can finish.
func TestMultiScanner_RunsEnginesConcurrently(t *testing.T) {
	const n = 3
	var started sync.WaitGroup
	started.Add(n)
	engines := make([]gate.AVScanner, n)
	for i := range engines {
		engines[i] = funcScanner(func(ctx context.Context) (*gate.AVResult, error) {
			started.Done()
			started.Wait()
			return &gate.AVResult{Clean: true}, nil
		})
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		res, err := scanner.NewMultiScanner(engines...).Scan(context.Background(), "/tmp/x")
		assert.NoError(t, err)
		assert.True(t, res.Clean)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("engines ran sequentially")
	}
}

// A detection cancels the engines still running, and Scan returns only after
// they have stopped.
func TestMultiScanner_DetectionCancelsOthersAndWaits(t *testing.T) {
	var slowReturned atomic.Bool
	slow := funcScanner(func(ctx context.Context) (*gate.AVResult, error) {
		<-ctx.Done()
		slowReturned.Store(true)
		return nil, ctx.Err()
	})
	infected := stubScanner{result: &gate.AVResult{Clean: false, Signature: "EICAR", Engine: "kaspersky"}}
	res, err := scanner.NewMultiScanner(slow, infected).Scan(context.Background(), "/tmp/x")
	require.NoError(t, err, "the detection outranks the canceled engine's error")
	assert.False(t, res.Clean)
	assert.Equal(t, "kaspersky", res.Engine)
	assert.True(t, slowReturned.Load(), "Scan must wait for every engine")
}

func TestMultiScanner_DetectionOutranksError(t *testing.T) {
	failing := stubScanner{err: fmt.Errorf("clamd down")}
	infected := stubScanner{result: &gate.AVResult{Clean: false, Signature: "EICAR", Engine: "icap"}}
	res, err := scanner.NewMultiScanner(failing, infected).Scan(context.Background(), "/tmp/x")
	require.NoError(t, err)
	assert.Equal(t, "icap", res.Engine)
}

// When several engines detect (or fail), engine order picks the report, not
// which one finished first.
func TestMultiScanner_ReportsInEngineOrder(t *testing.T) {
	late := funcScanner(func(context.Context) (*gate.AVResult, error) {
		time.Sleep(20 * time.Millisecond)
		return &gate.AVResult{Clean: false, Signature: "A", Engine: "first"}, nil
	})
	early := stubScanner{result: &gate.AVResult{Clean: false, Signature: "B", Engine: "second"}}
	res, err := scanner.NewMultiScanner(late, early).Scan(context.Background(), "/tmp/x")
	require.NoError(t, err)
	assert.Equal(t, "first", res.Engine)

	slowErr := funcScanner(func(context.Context) (*gate.AVResult, error) {
		time.Sleep(20 * time.Millisecond)
		return nil, errors.New("first")
	})
	_, err = scanner.NewMultiScanner(slowErr, stubScanner{err: errors.New("second")}).Scan(context.Background(), "/tmp/x")
	assert.EqualError(t, err, "first")
}

func TestMultiScanner_NilResultIsClean(t *testing.T) {
	res, err := scanner.NewMultiScanner(stubScanner{}, clean("icap")).Scan(context.Background(), "/tmp/x")
	require.NoError(t, err)
	assert.True(t, res.Clean)
}

func TestMultiScanner_Empty(t *testing.T) {
	m := scanner.NewMultiScanner()
	res, err := m.Scan(context.Background(), "/tmp/x")
	require.NoError(t, err)
	assert.True(t, res.Clean)
}
