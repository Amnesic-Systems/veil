package tun

import (
	"errors"
	"os"
)

var errNotImplemented = errors.New("not implemented on darwin")

func SetupTunAsProxy(_ Config) (*os.File, error) {
	return nil, errNotImplemented
}

func SetupTunAsEnclave(_ Config) (*os.File, error) {
	return nil, errNotImplemented
}
