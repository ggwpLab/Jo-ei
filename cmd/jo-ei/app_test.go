package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApp_CloseRunsInReverseOrder(t *testing.T) {
	var got []string
	a := &app{}
	for _, name := range []string{"a", "b", "c"} {
		a.onClose(func() error { got = append(got, name); return nil })
	}
	a.close()
	assert.Equal(t, []string{"c", "b", "a"}, got)
}

func TestApp_CloseContinuesAfterError(t *testing.T) {
	var got []string
	a := &app{}
	a.onClose(func() error { got = append(got, "a"); return nil })
	a.onClose(func() error { return errors.New("boom") })
	a.onClose(func() error { got = append(got, "c"); return nil })
	a.close()
	assert.Equal(t, []string{"c", "a"}, got)
}

func TestApp_CloseTwiceIsNoop(t *testing.T) {
	calls := 0
	a := &app{}
	a.onClose(func() error { calls++; return nil })
	a.close()
	a.close()
	assert.Equal(t, 1, calls)
}
