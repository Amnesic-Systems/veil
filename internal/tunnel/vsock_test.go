package tunnel

import (
	"context"
	"sync"
	"testing"
)

func TestVsockTunneler(t *testing.T) {
	var (
		tunnel = NewVSOCK()
		ctx    = context.Background()
		wg     = new(sync.WaitGroup)
	)
	wg.Add(1)
	defer wg.Wait()
	defer ctx.Done()

	tunnel.Start(ctx, wg)
}
