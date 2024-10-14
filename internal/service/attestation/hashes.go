package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"github.com/Amnesic-Systems/veil/internal/errs"
)

// Hashes contains hashes over public key material which we embed in
// the enclave's attestation document for clients to verify.
type Hashes struct {
	sync.Mutex
	TlsKeyHash [sha256.Size]byte `json:"tls_key_hash"` // Always set.
	AppKeyHash [sha256.Size]byte `json:"app_key_hash"` // Only set if the application has keys.
}

func (a *Hashes) SetAppHash(hash *[sha256.Size]byte) {
	a.Lock()
	defer a.Unlock()

	a.AppKeyHash = *hash
}

func (a *Hashes) SetTLSHash(hash *[sha256.Size]byte) {
	a.Lock()
	defer a.Unlock()

	a.TlsKeyHash = *hash
}

func (a *Hashes) Serialize() []byte {
	a.Lock()
	defer a.Unlock()

	b64TLSHash := base64.StdEncoding.EncodeToString(a.TlsKeyHash[:])
	b64AppHash := base64.StdEncoding.EncodeToString(a.AppKeyHash[:])
	str := fmt.Sprintf("sha256:%s;sha256:%s", b64TLSHash, b64AppHash)
	return []byte(str)
}

func DeserializeHashes(b []byte) (h *Hashes, err error) {
	errs.Wrap(&err, "failed to deserialize hashes")

	// The expected format is "sha256:<tls>;sha256:<app>".
	s := strings.Split(string(b), ";")
	if len(s) != 2 {
		return nil, errs.InvalidFormat
	}
	s[0] = strings.TrimPrefix(s[0], "sha256:")
	s[1] = strings.TrimPrefix(s[1], "sha256:")

	h = new(Hashes)
	if _, err := base64.StdEncoding.Decode(h.TlsKeyHash[:], []byte(s[0])); err != nil {
		return nil, errs.InvalidFormat
	}
	if _, err := base64.StdEncoding.Decode(h.AppKeyHash[:], []byte(s[1])); err != nil {
		return nil, errs.InvalidFormat
	}

	return h, nil
}
