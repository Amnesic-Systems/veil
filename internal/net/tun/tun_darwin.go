package tun

import (
	"errors"
	"os"
)

var errNotImplemented = errors.New("not implemented on darwin")

func SetupTunAsProxy() (*os.File, error) {
	return nil, errNotImplemented
}

func SetupTunAsEnclave() (*os.File, error) {
	return nil, errNotImplemented
}
