package tunnel

import (
	"context"
)

var (
	_ Mechanism = (*NoopTunneler)(nil)
	_ Mechanism = (*VsockTunneler)(nil)
)

// Settings configures a VSOCK tunnel between the enclave and veil-proxy.
type Settings struct {
	// Port is the VSOCK port used by the tunnel.
	Port uint32

	// MTU is the tunnel interface MTU in bytes. Zero selects the default.
	MTU int
}

type Mechanism interface {
	// Start starts the tunneling mechanism and blocks until networking is set up
	// or the context is canceled before setup completes.
	Start(ctx context.Context, cfg Settings) error
}

func New(ctx context.Context, m Mechanism, cfg Settings) error {
	return m.Start(ctx, cfg)
}
