package tunnel

import (
	"context"
	"sync"
	"testing"
)

func TestNoopTunneler(t *testing.T) {
	var (
		tunnel = NewNoop()
		ctx    = context.Background()
		wg     = new(sync.WaitGroup)
	)
	wg.Add(1)
	defer wg.Wait()
	defer ctx.Done()

	tunnel.Start(ctx, wg, 0)
}
