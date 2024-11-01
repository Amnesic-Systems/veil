package nitro

import (
	"errors"
	"time"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
)

var _ enclave.Attester = (*Attester)(nil)
var ErrDebugMode = errors.New("attestation document was produced in debug mode")

// Attester implements the attester interface by drawing on the AWS Nitro
// Enclave hypervisor.
type Attester struct {
	session *nsm.Session
}

// NewAttester returns a new nitroAttester.
func NewAttester() enclave.Attester {
	return new(Attester)
}

func (*Attester) Type() string {
	return enclave.TypeNitro
}

// convertTo converts our representation of an auxiliary field to the nsm
// package's representation.
func convertTo(auxField *[enclave.AuxFieldLen]byte) []byte {
	if auxField == nil {
		return nil
	}
	return auxField[:]
}

// convertFrom converts the nsm package's representation of an auxiliary field
// to our representation.
func convertFrom(auxField []byte) *[enclave.AuxFieldLen]byte {
	if auxField == nil {
		return nil
	}
	var res [enclave.AuxFieldLen]byte
	copy(res[:], auxField)
	return &res
}

func (a *Attester) Attest(aux *enclave.AuxInfo) (_ *enclave.AttestationDoc, err error) {
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

	return &enclave.AttestationDoc{
		Type: enclave.TypeNitro,
		Doc:  resp.Attestation.Document,
	}, nil
}

func (a *Attester) Verify(
	doc *enclave.AttestationDoc,
	ourNonce *nonce.Nonce,
) (_ *enclave.AuxInfo, err error) {
	defer errs.Wrap(&err, "failed to verify attestation document")

	if doc == nil {
		return nil, errors.New("attestation document is nil")
	}
	if doc.Type != a.Type() {
		return nil, errors.New("attestation document type mismatch")
	}

	// First, verify the attestation document.
	opts := verifyOptions{CurrentTime: time.Now().UTC()}
	res, err := verify(doc.Doc, opts)
	if err != nil {
		return nil, err
	}

	// Verify that the attestation document contains the nonce that we may have
	// asked it to embed.
	if ourNonce != nil {
		docNonce, err := nonce.FromSlice(res.Document.Nonce)
		if err != nil {
			return nil, err
		}
		if *ourNonce != *docNonce {
			return nil, errors.New("nonce does not match")
		}
	}

	// If the enclave is running in debug mode, return an error *and* the
	// auxiliary information.
	if res.Document.PCRs.FromDebugMode() {
		err = ErrDebugMode
	}

	return &enclave.AuxInfo{
		Nonce:     convertFrom(res.Document.Nonce),
		UserData:  convertFrom(res.Document.UserData),
		PublicKey: convertFrom(res.Document.PublicKey),
	}, err
}
