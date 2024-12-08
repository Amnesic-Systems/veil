package attestation

import (
	"crypto/sha256"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/nonce"
)

// Builder is an abstraction purpose-built for veil's HTTP handlers.  It bundles
// an attester with auxiliary fields because these two are always used together.
// As a Builder is passed through the stack, its auxiliary fields are updated
// and eventually used to create an attestation document.
type Builder struct {
	enclave.Attester
	enclave.AuxInfo
}

type auxField func(*Builder)

// NewBuilder returns a new Builder with the given attester and sets the given
// auxiliary fields.
func NewBuilder(attester enclave.Attester, opts ...auxField) *Builder {
	b := &Builder{Attester: attester}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Update updates the builder with the given auxiliary fields.
func (b *Builder) Update(opts ...auxField) {
	for _, opt := range opts {
		opt(b)
	}
}

// Attest returns an attestation document with the auxiliary fields that were
// either already set, or are now passed in as options.
func (b *Builder) Attest(opts ...auxField) (*enclave.RawDocument, error) {
	for _, opt := range opts {
		opt(b)
	}
	return b.Attester.Attest(&b.AuxInfo)
}

// WithHashes sets the given hashes in an auxiliary field.
func WithHashes(h *Hashes) auxField {
	return func(b *Builder) {
		if h == nil {
			return
		}
		b.PublicKey = h.Serialize()
	}
}

// WithNonce sets the given nonce in an auxiliary field.
func WithNonce(n *nonce.Nonce) auxField {
	return func(b *Builder) {
		if n == nil {
			return
		}
		b.Nonce = n.ToSlice()
	}
}

// WithSHA256 sets the given SHA256 hash in an auxiliary field.
func WithSHA256(sha [sha256.Size]byte) auxField {
	return func(b *Builder) {
		b.UserData = sha[:]
	}
}
