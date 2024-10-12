package nonce

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"

	"github.com/Amnesic-Systems/veil/internal/errs"
)

const Len = 20 // The length of a nonce in bytes.

var (
	// Accessing rand.Reader via variable facilitates mocking.
	cryptoRead       = rand.Reader
	errNotEnoughRead = errors.New("failed to read enough random bytes")
)

type Nonce [Len]byte

func (n *Nonce) URLEncode() string {
	return url.QueryEscape(
		base64.StdEncoding.EncodeToString(n[:]),
	)
}

func New() (*Nonce, error) {
	// TODO: panic on error cause we may not be able to recover?
	var newNonce Nonce
	n, err := cryptoRead.Read(newNonce[:])
	if err != nil {
		return nil, errNotEnoughRead
	}
	if n != Len {
		return nil, errNotEnoughRead
	}
	return &newNonce, nil
}

func FromSlice(s []byte) (*Nonce, error) {
	if len(s) != Len {
		return nil, errs.InvalidLength
	}

	var n Nonce
	copy(n[:], s[:Len])
	return &n, nil
}
