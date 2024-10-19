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
	if err := json.Unmarshal(a.Doc, &aux); err != nil {
		return nil, err
	}
	return aux, nil
}
