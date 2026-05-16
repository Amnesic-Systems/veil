package backoff

import (
	"context"
	"time"
)

const (
	minSleep = 100 * time.Millisecond
	maxSleep = 10 * time.Second
)

type Timer struct {
	cur, max   time.Duration
	resetAfter time.Duration
	lastFail   time.Time
	sleepFn    func(context.Context, time.Duration)
}

func NewTimer(opts ...Opts) *Timer {
	t := &Timer{
		max:        maxSleep,
		resetAfter: 10 * time.Second,
		sleepFn: func(ctx context.Context, d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		},
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

func (t *Timer) Sleep(ctx context.Context) {
	now := time.Now().UTC()
	// Has enough time passed to reset the backoff duration?
	if !t.lastFail.IsZero() && now.Sub(t.lastFail) >= t.resetAfter {
		t.cur = minSleep
	}
	if t.cur <= minSleep {
		t.cur = minSleep
	}

	d := t.cur
	t.cur = min(t.max, t.cur*2)
	t.lastFail = now

	t.sleepFn(ctx, d)
}

func (t *Timer) Reset() {
	t.cur = minSleep
	t.lastFail = time.Time{}
}
