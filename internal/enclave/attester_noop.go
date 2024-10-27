package enclave

import (
	"encoding/json"

	"github.com/Amnesic-Systems/veil/internal/nonce"
)

type NoopAttester struct{}

// NewNoopAttester returns a new noop attester.
func NewNoopAttester() Attester {
	return new(NoopAttester)
}

func (*NoopAttester) Type() string {
	return typeNoop
}

func (*NoopAttester) Attest(aux *AuxInfo) (*AttestationDoc, error) {
	// With the Nitro attester, the attestation document is a CBOR-encoded byte
	// array.  For simplicity, the Noop attester encodes the given AuxInfo as a
	// JSON object in the attestation document.
	a, err := json.Marshal(aux)
	if err != nil {
		return nil, err
	}
	return &AttestationDoc{
		Type: typeNoop,
		Doc:  a,
	}, nil
}

func (*NoopAttester) Verify(a *AttestationDoc, n *nonce.Nonce) (*AuxInfo, error) {
	var aux = new(AuxInfo)
	if err := json.Unmarshal(a.Doc, aux); err != nil {
		return nil, err
	}
	return aux, nil
}
