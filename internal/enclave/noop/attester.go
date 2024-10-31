package noop

import (
	"encoding/json"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/nonce"
)

var _ enclave.Attester = (*Attester)(nil)

type Attester struct{}

// NewAttester returns a new noop attester.
func NewAttester() enclave.Attester {
	return new(Attester)
}

func (*Attester) Type() string {
	return enclave.TypeNoop
}

func (*Attester) Attest(aux *enclave.AuxInfo) (*enclave.AttestationDoc, error) {
	// With the Nitro attester, the attestation document is a CBOR-encoded byte
	// array.  For simplicity, the Noop attester encodes the given AuxInfo as a
	// JSON object in the attestation document.
	a, err := json.Marshal(aux)
	if err != nil {
		return nil, err
	}
	return &enclave.AttestationDoc{
		Type: enclave.TypeNoop,
		Doc:  a,
	}, nil
}

func (*Attester) Verify(a *enclave.AttestationDoc, n *nonce.Nonce) (*enclave.AuxInfo, error) {
	var aux = new(enclave.AuxInfo)
	if err := json.Unmarshal(a.Doc, aux); err != nil {
		return nil, err
	}
	return aux, nil
}
