package tun

import (
	"os"
)

// veil-proxy does not support macOS but we can at least make it compile by
// implementing the following functions.
const err = "not implemented on darwin"

func SetupTunAsProxy() (*os.File, error) {
	panic(err)
}

func SetupTunAsEnclave() (*os.File, error) {
	panic(err)
}
