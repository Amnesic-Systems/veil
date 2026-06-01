package config

import (
	"fmt"
	"math"

	"github.com/Amnesic-Systems/veil/internal/tunnel"
)

// VeilProxy represents veil-proxy's configuration.
type VeilProxy struct {
	// DNSForwarder enables a forwarding DNS resolver on the host side of
	// veil's TUN interface.
	DNSForwarder bool

	// Profile can be set to true to enable profiling.
	Profile bool

	// VSOCKPort determines the VSOCK port for the control stream. Data
	// streams use VSOCKPort+1 through VSOCKPort+VsockStreams.
	VSOCKPort uint32

	// VsockStreams is the number of data VSOCK streams in addition to the
	// control stream on VSOCKPort.
	VsockStreams uint
}

func (c *VeilProxy) Validate() map[string]string {
	problems := make(map[string]string)

	if c.VSOCKPort == 0 {
		problems["-vsock-port"] = "port must not be 0"
	}
	problems = validateVsockStreams(problems, c.VsockStreams, c.VSOCKPort)

	return problems
}

func validateVsockStreams(
	problems map[string]string,
	dataStreams uint,
	port uint32,
) map[string]string {
	if dataStreams > tunnel.MaxVsockDataStreams {
		problems["-vsock-streams"] = fmt.Sprintf(
			"must be between %d and %d",
			tunnel.DefaultVsockDataStreams,
			tunnel.MaxVsockDataStreams,
		)
	}
	if uint64(port)+uint64(dataStreams) > math.MaxUint32 {
		problems["-vsock-port"] = "port range exceeds maximum VSOCK port"
	}
	return problems
}
