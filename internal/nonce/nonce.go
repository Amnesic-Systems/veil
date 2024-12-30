// Package nonce implements a nonce type and its corresponding utility
// functions.
package nonce

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
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
	return url.QueryEscape(n.B64())
}

// B64 returns a Base64-encoded string representation of the nonce.
func (n *Nonce) B64() string {
	return base64.StdEncoding.EncodeToString(n[:])
}

// ToSlice returns a slice of the nonce.
func (n *Nonce) ToSlice() []byte {
	return n[:]
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
	if len(s) < Len {
		return nil, fmt.Errorf("%w: slice len is %d but need at least %d",
			errs.InvalidLength, len(s), Len)
	}

	var n Nonce
	copy(n[:], s[:Len])
	return &n, nil
}
