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
	return "noop"
}

func (*NoopAttester) Attest(aux *AuxInfo) (*AttestationDoc, error) {
	a, err := json.Marshal(aux) // TODO: Nested json?
	if err != nil {
		return nil, err
	}
	return &AttestationDoc{
		Type: "noop",
		Doc:  a,
	}, nil
}

func (*NoopAttester) Verify(a Attestation, n *nonce.Nonce) (*AuxInfo, error) {
	var aux = new(AuxInfo)
	if err := json.Unmarshal(a, &aux); err != nil {
		return nil, err
	}
	return aux, nil
}
