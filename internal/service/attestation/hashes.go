package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/util"
)

// Hashes contains hashes over public key material which we embed in
// the enclave's attestation document for clients to verify.
type Hashes struct {
	sync.Mutex
	TlsKeyHash *[sha256.Size]byte `json:"tls_key_hash"` // Always set.
	AppKeyHash *[sha256.Size]byte `json:"app_key_hash"` // Only set if the application has keys.
}

func (a *Hashes) SetAppHash(hash *[sha256.Size]byte) {
	a.Lock()
	defer a.Unlock()

	a.AppKeyHash = hash
}

func (a *Hashes) SetTLSHash(hash *[sha256.Size]byte) {
	a.Lock()
	defer a.Unlock()

	a.TlsKeyHash = hash
}

func (a *Hashes) Serialize() []byte {
	a.Lock()
	defer a.Unlock()

	str := fmt.Sprintf("sha256:%s;sha256:",
		base64.StdEncoding.EncodeToString(a.TlsKeyHash[:]))
	// The application's hash is optional.
	if a.AppKeyHash != nil {
		str += base64.StdEncoding.EncodeToString(a.AppKeyHash[:])
	}
	return []byte(str)
}

func DeserializeHashes(b []byte) (h *Hashes, err error) {
	errs.Wrap(&err, "failed to deserialize hashes")

	// Examples of the serialized format are:
	//   sha256:3CMEDy2oTLyBCLE2BufzgUy6zIY=;sha256:92AfmU4AXOKZpz61NGqqII12Tlw=
	// or:
	//   sha256:gDH6rnBA5e+dzTDeZv429hmWuYg=;sha256:
	s := strings.Split(string(b), ";")
	if len(s) != 2 {
		return nil, errs.InvalidFormat
	}
	// Extract the base64-encoded hashes.
	tlsKeyHash := []byte(strings.TrimPrefix(s[0], "sha256:"))
	appKeyHash := []byte(strings.TrimPrefix(s[1], "sha256:"))
	h = &Hashes{
		TlsKeyHash: util.AddrOf([sha256.Size]byte{}),
	}

	if _, err := base64.StdEncoding.Decode(
		h.TlsKeyHash[:],
		tlsKeyHash,
	); err != nil {
		return nil, fmt.Errorf("%w: %w", errs.InvalidFormat, err)
	}

	// If the application hash is unset, we're done.
	if len(appKeyHash) == 0 {
		return h, nil
	}

	h.AppKeyHash = util.AddrOf([sha256.Size]byte{})
	if _, err := base64.StdEncoding.Decode(
		h.AppKeyHash[:],
		appKeyHash,
	); err != nil {
		return nil, fmt.Errorf("%w: %w", errs.InvalidFormat, err)
	}

	return h, nil
}
