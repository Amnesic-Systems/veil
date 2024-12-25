package config

// VeilProxy represents veil-proxy's configuration.
type VeilProxy struct {
	// Profile can be set to true to enable profiling.
	Profile bool

	// Port determines the VSOCK port that veil-proxy will be listening on for
	// incoming connections from the enclave.
	Port uint32
}

func (c *VeilProxy) Validate() map[string]string {
	problems := make(map[string]string)

	if c.Port == 0 {
		problems["-port"] = "port must not be 0"
	}

	return problems
}
