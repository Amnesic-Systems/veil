package attestation

import (
	"bytes"
	"crypto/sha256"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"
)

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
