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

func (*Attester) Attest(aux *enclave.AuxInfo) (*enclave.RawDocument, error) {
	// With the Nitro attester, the attestation document is a CBOR-encoded byte
	// array.  For simplicity, the Noop attester encodes the given AuxInfo as a
	// JSON object in the attestation document.
	a, err := json.Marshal(aux)
	if err != nil {
		return nil, err
	}
	return &enclave.RawDocument{
		Type: enclave.TypeNoop,
		Doc:  a,
	}, nil
}

func (*Attester) Verify(a *enclave.RawDocument, n *nonce.Nonce) (*enclave.Document, error) {
	var doc = new(enclave.Document)
	var aux = new(enclave.AuxInfo)

	if err := json.Unmarshal(a.Doc, aux); err != nil {
		return nil, err
	}
	doc.AuxInfo = *aux
	return doc, nil
}
