package noop

import (
	"encoding/json"
	"fmt"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
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
	if aux == nil {
		return nil, fmt.Errorf("%w: %s", errs.ErrIsNil, "aux info")
	}

	// With the Nitro attester, the attestation document is a CBOR-encoded byte
	// array.  For simplicity, the Noop attester encodes a Document containing the
	// given AuxInfo as a
	// JSON object in the attestation document.
	a, err := json.Marshal(&enclave.Document{AuxInfo: *aux})
	if err != nil {
		return nil, err
	}
	return &enclave.RawDocument{
		Type: enclave.TypeNoop,
		Doc:  a,
	}, nil
}

func (*Attester) Verify(a *enclave.RawDocument, n *nonce.Nonce) (*enclave.Document, error) {
	if a.Type != enclave.TypeNoop {
		return nil, errs.ErrTypeMismatch
	}

	doc := new(enclave.Document)
	if err := json.Unmarshal(a.Doc, doc); err != nil {
		return nil, err
	}
	if n != nil {
		docNonce, err := nonce.FromSlice(doc.Nonce)
		if err != nil {
			return nil, err
		}
		if *n != *docNonce {
			return nil, errs.ErrNonceMismatch
		}
	}
	return doc, nil
}
