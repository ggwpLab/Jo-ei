package main

// app owns the resources run opens and releases them in reverse order, so a
// startup failure halfway through still closes everything opened before it.
type app struct {
	closers []func() error
}

// onClose registers fn to run on close, after every closer registered later.
func (a *app) onClose(fn func() error) {
	a.closers = append(a.closers, fn)
}

// close runs the registered closers last-in first-out. Every closer runs even
// when an earlier one fails; their errors are dropped, as shutdown has nowhere
// useful to report them. Calling close again is a no-op.
func (a *app) close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		_ = a.closers[i]()
	}
	a.closers = nil
}
