package backoff

import (
	"context"
	"time"
)

type Opts func(t *Timer)

func WithMaxBackoff(max time.Duration) Opts {
	return func(t *Timer) {
		t.max = max
	}
}

func WithSleepFn(sleepFn func(context.Context, time.Duration)) Opts {
	return func(t *Timer) {
		t.sleepFn = sleepFn
	}
}
