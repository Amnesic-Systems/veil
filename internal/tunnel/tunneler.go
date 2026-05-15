package tunnel

import (
	"context"
)

var (
	_ Mechanism = (*NoopTunneler)(nil)
	_ Mechanism = (*VsockTunneler)(nil)
)

type Mechanism interface {
	// Start starts the tunneling mechanism and blocks until networking is set up
	// or the context is canceled before setup completes.
	Start(ctx context.Context, port uint32) error
}

func New(ctx context.Context, m Mechanism, port uint32) error {
	return m.Start(ctx, port)
}
