package attestation

import (
	"bytes"
	"crypto/sha256"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"
)

// Builder is a helper for setting auxiliary attestation both at initialization
// time and at attestation time.
type Builder struct {
	attester enclave.Attester
	aux      enclave.AuxInfo
}

type AuxField func(*Builder)

// NewBuilder returns a new Builder with the given attester and sets the given
// auxiliary fields.
func NewBuilder(attester enclave.Attester, opts ...AuxField) *Builder {
	b := &Builder{attester: attester}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Attest returns an attestation document with the auxiliary fields that were
// either already set, or are now passed in as options.
func (b *Builder) Attest(opts ...AuxField) (*enclave.RawDocument, error) {
	for _, opt := range opts {
		opt(b)
	}
	return b.attester.Attest(&b.aux)
}

// WithHashes sets the given hashes in an auxiliary field.
func WithHashes(h *Hashes) AuxField {
	return func(b *Builder) {
		b.aux.PublicKey = h.Serialize() // TODO: safe?
	}
}

// WithNonce sets the given nonce in an auxiliary field.
func WithNonce(n *nonce.Nonce) AuxField {
	return func(b *Builder) {
		b.aux.Nonce = n.ToSlice() // TODO: safe?
	}
}

// WithSHA256 sets the given SHA256 hash in an auxiliary field.
func WithSHA256(sha [sha256.Size]byte) AuxField {
	return func(b *Builder) {
		b.aux.UserData = sha[:]
	}
}

// GetNonce returns the nonce from the given auxiliary info.
func GetNonce(aux *enclave.AuxInfo) (*nonce.Nonce, error) {
	if aux.Nonce == nil {
		return nil, errs.IsNil
	}

	var n nonce.Nonce
	copy(n[:], aux.Nonce[:nonce.Len])
	return &n, nil
}

// GetSHA256 returns the SHA256 hash from the given auxiliary info.
func GetSHA256(aux *enclave.AuxInfo) (*[sha256.Size]byte, error) {
	if aux.UserData == nil {
		return nil, errs.IsNil
	}
	sha := [sha256.Size]byte{}
	copy(sha[:], aux.UserData[:])
	return &sha, nil
}

func GetHashes(aux *enclave.AuxInfo) (*Hashes, error) {
	if aux.PublicKey == nil {
		return nil, errs.IsNil
	}
	sanitized := bytes.Trim(aux.PublicKey[:], "\x00") // TODO: smth better?
	return DeserializeHashes(sanitized)
}
