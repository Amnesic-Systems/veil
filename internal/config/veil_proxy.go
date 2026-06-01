package config

import (
	"fmt"

	"github.com/Amnesic-Systems/veil/internal/net/tun"
)

// VeilProxy represents veil-proxy's configuration.
type VeilProxy struct {
	// DNSForwarder enables a forwarding DNS resolver on the host side of
	// veil's TUN interface.
	DNSForwarder bool

	// Profile can be set to true to enable profiling.
	Profile bool

	// VSOCKPort determines the VSOCK port that veil-proxy will be listening on
	// for incoming connections from the enclave.
	VSOCKPort uint32

	// TunMTU is the tunnel interface MTU in bytes. Zero selects the default.
	TunMTU int
}

func (c *VeilProxy) Validate() map[string]string {
	problems := make(map[string]string)

	if c.VSOCKPort == 0 {
		problems["-vsock-port"] = "port must not be 0"
	}
	problems = validateTunMTU(problems, c.TunMTU)

	return problems
}

func validateTunMTU(problems map[string]string, mtu int) map[string]string {
	if mtu != 0 && (mtu < tun.MinMTU || mtu > tun.MaxMTU) {
		problems["-tun-mtu"] = fmt.Sprintf(
			"must be between %d and %d",
			tun.MinMTU,
			tun.MaxMTU,
		)
	}
	return problems
}

// TunMTUOrDefault returns the configured tunnel MTU, defaulting when unset.
func TunMTUOrDefault(mtu int) int {
	if mtu == 0 {
		return tun.DefaultMTU
	}
	return mtu
}
