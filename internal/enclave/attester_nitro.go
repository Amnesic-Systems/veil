package enclave

import (
	"errors"
	"time"

	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"

	"github.com/hf/nitrite"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

// NitroAttester implements the attester interface by drawing on the AWS Nitro
// Enclave hypervisor.
type NitroAttester struct {
	session *nsm.Session
}

// NewNitroAttester returns a new nitroAttester.
func NewNitroAttester() Attester {
	return new(NitroAttester)
}

func (*NitroAttester) Type() string {
	return typeNitro
}

// convertTo converts our representation of an auxiliary field to the nsm
// package's representation.
func convertTo(auxField *[AuxFieldLen]byte) []byte {
	if auxField == nil {
		return nil
	}
	return auxField[:]
}

// convertFrom converts the nsm package's representation of an auxiliary field
// to our representation.
func convertFrom(auxField []byte) *[AuxFieldLen]byte {
	if auxField == nil {
		return nil
	}
	var res [AuxFieldLen]byte
	copy(res[:], auxField)
	return &res
}

func (a *NitroAttester) Attest(aux *AuxInfo) (_ *AttestationDoc, err error) {
	defer errs.Wrap(&err, "failed to create attestation document")

	if a.session == nil {
		// Open a session to the Nitro Secure Module.
		if a.session, err = nsm.OpenDefaultSession(); err != nil {
			return nil, err
		}
	}

	if aux == nil {
		return nil, errors.New("aux info is nil")
	}

	req := &request.Attestation{
		Nonce:     convertTo(aux.Nonce),
		UserData:  convertTo(aux.UserData),
		PublicKey: convertTo(aux.PublicKey),
	}
	resp, err := a.session.Send(req)
	if err != nil {
		return nil, err
	}
	if resp.Attestation == nil || resp.Attestation.Document == nil {
		return nil, errors.New("required fields missing in attestation response")
	}

	return &AttestationDoc{
		Type: typeNitro,
		Doc:  resp.Attestation.Document,
	}, nil
}

func (a *NitroAttester) Verify(doc *AttestationDoc, ourNonce *nonce.Nonce) (_ *AuxInfo, err error) {
	defer errs.Wrap(&err, "failed to verify attestation document")

	if doc == nil {
		return nil, errors.New("attestation document is nil")
	}
	if doc.Type != a.Type() {
		return nil, errors.New("attestation document type mismatch")
	}

	// First, verify the attestation document.
	opts := nitrite.VerifyOptions{CurrentTime: time.Now().UTC()}
	res, err := nitrite.Verify(doc.Doc, opts)
	if err != nil {
		return nil, err
	}

	// Verify that the attestation document contains the nonce that we may have
	// asked it to embed.
	docNonce, err := nonce.FromSlice(res.Document.Nonce)
	if err != nil {
		return nil, err
	}
	if ourNonce != nil && *ourNonce != *docNonce {
		return nil, errNonceMismatch
	}

	return &AuxInfo{
		Nonce:     convertFrom(res.Document.Nonce),
		UserData:  convertFrom(res.Document.UserData),
		PublicKey: convertFrom(res.Document.PublicKey),
	}, nil
}
