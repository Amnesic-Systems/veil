package tunnel

import (
	"context"
	"sync"
)

var (
	_ Mechanism = (*NoopTunneler)(nil)
	_ Mechanism = (*VsockTunneler)(nil)
)

type Mechanism interface {
	// Start starts the tunneling mechanism.  It returns immediately and calls
	// `Done()` on the given waitgroup after networking is set up.
	Start(context.Context, *sync.WaitGroup)
}

func New(ctx context.Context, m Mechanism) {
	var wg = new(sync.WaitGroup)
	wg.Add(1)
	defer wg.Wait()
	m.Start(ctx, wg)
}
