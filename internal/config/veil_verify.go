package config

import (
	"fmt"
	"os"
	"path"
)

// VeilVerify represents veil-verify's configuration.
type VeilVerify struct {
	// Addr contains the enclave's address, e.g.:
	//	https://enclave.example.com
	Addr string

	// Dir contains the (relative or absolute) directory of the software
	// repository containing the enclave application.
	Dir string

	// Dockerfile contains the path (relative to `Dir`) of the Dockerfile that's
	// used to build the enclave application.
	Dockerfile string

	// Verbose prints extra information if set to true.
	Verbose bool

	// Testing facilitates local testing by disabling safety checks that we
	// would normally run.
	Testing bool
}

func (c *VeilVerify) Validate() map[string]string {
	problems := make(map[string]string)

	// Ensure that required arguments are set.
	if c.Addr == "" {
		problems["-addr"] = "argument is required"
	}
	if c.Dir == "" {
		problems["-dir"] = "argument is required"
	}

	// Make sure that the Dockerfile relative to the given directory exists.
	p := path.Join(c.Dir, c.Dockerfile)
	if _, err := os.Stat(p); err != nil {
		problems["-dockerfile"] = fmt.Sprintf("given Dockerfile %q does not exist", p)
	}

	return problems
}
