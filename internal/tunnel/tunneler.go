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
	// Port is the VSOCK port for the control stream. Data streams use Port+1
	// through Port+DataStreams.
	Port uint32

	// DataStreams is the number of VSOCK data streams in addition to the
	// control stream on Port. TCP and UDP flows are hashed across the data
	// streams; ICMP and other non-flow traffic uses the control stream.
	DataStreams uint
}

// StreamCount returns the total number of VSOCK connections: one control
// stream plus DataStreams data streams.
func StreamCount(dataStreams uint) uint {
	return 1 + dataStreams
}

type Mechanism interface {
	// Start starts the tunneling mechanism and blocks until networking is set up
	// or the context is canceled before setup completes.
	Start(ctx context.Context, cfg Settings) error
}

func New(ctx context.Context, m Mechanism, cfg Settings) error {
	return m.Start(ctx, cfg)
}
