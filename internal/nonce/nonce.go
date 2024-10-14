package nonce

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"

	"github.com/Amnesic-Systems/veil/internal/errs"
)

// Len is the length of a nonce in bytes.
const Len = 20

var (
	// Accessing rand.Reader via variable facilitates mocking.
	cryptoRead       = rand.Reader
	errNotEnoughRead = errors.New("failed to read enough random bytes")
)

// Nonce is a random value that guarantees attestation document freshness.
type Nonce [Len]byte

// URLEncode returns the nonce as a URL-encoded string.
func (n *Nonce) URLEncode() string {
	return url.QueryEscape(
		base64.StdEncoding.EncodeToString(n[:]),
	)
}

// New creates a new nonce.
func New() (*Nonce, error) {
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

// FromSlice turns a byte slice into a nonce.
func FromSlice(s []byte) (*Nonce, error) {
	if len(s) != Len {
		return nil, errs.InvalidLength
	}

	var n Nonce
	copy(n[:], s[:Len])
	return &n, nil
}
