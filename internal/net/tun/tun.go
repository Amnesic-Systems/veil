package tun

const (
	Name = "tun0"

	// DefaultMTU is the default tunnel interface MTU. It matches the prior
	// hardcoded value so existing deployments behave the same without -tun-mtu.
	DefaultMTU = 65535

	// MinMTU is the smallest supported tunnel MTU.
	MinMTU = 576

	// MaxMTU is the largest supported tunnel MTU. It matches the largest packet
	// size that can be framed on the VSOCK tunnel.
	MaxMTU = 65535

	ProxyIP   = "10.0.0.1"
	EnclaveIP = "10.0.0.2"
)

// Config contains tun interface settings shared by veil-proxy and veil-daemon.
type Config struct {
	// MTU is the tunnel interface MTU in bytes. Zero selects DefaultMTU.
	MTU int
}

// MTUOrDefault returns the configured MTU, or DefaultMTU when unset.
func (c Config) MTUOrDefault() int {
	if c.MTU == 0 {
		return DefaultMTU
	}
	return c.MTU
}
