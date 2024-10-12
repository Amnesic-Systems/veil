package attestation

// TODO: does this belong in the enclave package?

import (
	"slices"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"
)

// AuxToClient returns an enclave.AuxFunc that embeds the given hashes.
func AuxToClient(a *Hashes) enclave.AuxFunc {
	return func(n *nonce.Nonce) *enclave.AuxInfo {
		var aux = new(enclave.AuxInfo)
		copy(aux.PublicKey[:], a.Serialize())
		copy(aux.Nonce[:], n[:])
		return aux
	}
}

// AuxFromServer extracts the hashes and nonce from the given aux information.
func AuxFromServer(aux *enclave.AuxInfo) (h *Hashes, n *nonce.Nonce, err error) {
	errs.Wrap(&err, "failed to extract aux information from server")

	if aux == nil {
		return nil, nil, errs.IsNil
	}

	n, _ = nonce.FromSlice(aux.Nonce[:nonce.Len])

	// Cut off null bytes.
	idx := slices.Index(aux.PublicKey[:], 0x00)
	h, err = DeserializeHashes(aux.PublicKey[:idx])
	if err != nil {
		return nil, nil, err
	}
	return h, n, nil
}
