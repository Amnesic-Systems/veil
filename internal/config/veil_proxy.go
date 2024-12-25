package config

// VeilProxy represents veil-proxy's configuration.
type VeilProxy struct {
	// Profile can be set to true to enable profiling.
	Profile bool

	// VSOCKPort determines the VSOCK port that veil-proxy will be listening on
	// for incoming connections from the enclave.
	VSOCKPort uint32
}

func (c *VeilProxy) Validate() map[string]string {
	problems := make(map[string]string)

	if c.VSOCKPort == 0 {
		problems["-vsock-port"] = "port must not be 0"
	}

	return problems
}
