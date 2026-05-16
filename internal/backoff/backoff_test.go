package backoff

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type sleepRecorder struct {
	durations []time.Duration
}

func (r *sleepRecorder) Sleep(_ context.Context, d time.Duration) {
	r.durations = append(r.durations, d)
}

func newTestTimer(opts ...Opts) (*Timer, *sleepRecorder) {
	recorder := new(sleepRecorder)
	opts = append([]Opts{WithSleepFn(recorder.Sleep)}, opts...)
	timer := NewTimer(opts...)
	return timer, recorder
}

func TestTimerStartsAtMinSleep(t *testing.T) {
	timer, recorder := newTestTimer()

	timer.Sleep(t.Context())

	require.Equal(t, []time.Duration{minSleep}, recorder.durations)
	require.Equal(t, minSleep*2, timer.cur)
	require.False(t, timer.lastFail.IsZero())
}

func TestTimerBacksOffExponentiallyUntilMax(t *testing.T) {
	const max = minSleep * 4
	timer, recorder := newTestTimer(WithMaxBackoff(max))

	for range 5 {
		timer.Sleep(t.Context())
	}

	require.Equal(t, []time.Duration{
		minSleep,
		minSleep * 2,
		max,
		max,
		max,
	}, recorder.durations)
	require.Equal(t, max, timer.cur)
}

func TestTimerResetsAfterQuietPeriod(t *testing.T) {
	timer, recorder := newTestTimer(WithMaxBackoff(minSleep * 8))

	timer.Sleep(t.Context())
	timer.Sleep(t.Context())
	timer.Sleep(t.Context())

	timer.lastFail = time.Now().UTC().Add(-timer.resetAfter)
	timer.Sleep(t.Context())

	require.Equal(t, []time.Duration{
		minSleep,
		minSleep * 2,
		minSleep * 4,
		minSleep,
	}, recorder.durations)
	require.Equal(t, minSleep*2, timer.cur)
}

func TestTimerDoesNotResetBeforeQuietPeriod(t *testing.T) {
	timer, recorder := newTestTimer(WithMaxBackoff(minSleep * 8))

	timer.Sleep(t.Context())
	timer.Sleep(t.Context())

	timer.lastFail = time.Now().UTC().Add(-timer.resetAfter + time.Millisecond)
	timer.Sleep(t.Context())

	require.Equal(t, []time.Duration{
		minSleep,
		minSleep * 2,
		minSleep * 4,
	}, recorder.durations)
	require.Equal(t, minSleep*8, timer.cur)
}

func TestTimerPassesContextToSleepFn(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(t.Context(), contextKey{}, "sentinel")
	var got context.Context
	timer := NewTimer(WithSleepFn(func(ctx context.Context, _ time.Duration) {
		got = ctx
	}))

	timer.Sleep(ctx)

	require.Equal(t, "sentinel", got.Value(contextKey{}))
}

func TestDefaultSleepReturnsWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	timer := NewTimer()
	timer.cur = maxSleep

	done := make(chan struct{})
	go func() {
		defer close(done)
		timer.Sleep(ctx)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Millisecond):
		require.Fail(t, "Sleep did not return after context cancellation")
	}
}
