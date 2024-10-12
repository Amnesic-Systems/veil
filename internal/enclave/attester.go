package enclave

import (
	"errors"

	"github.com/Amnesic-Systems/veil/internal/nonce"
)

// See page 65 of the AWS Nitro Enclaves user guide for reference:
// https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf
const userDataLen = 1024

var (
	errPCRMismatch   = errors.New("platform configuration registers differ")
	errNonceMismatch = errors.New("nonce does not match")

	// Check at compile-time if types implement the attester interface.
	_ Attester = (*NitroAttester)(nil)
	_ Attester = (*NoopAttester)(nil)
)

type Attestation []byte

// AttestationDoc holds the enclave's attestation document.
type AttestationDoc struct {
	Type string      `json:"type"`
	Doc  Attestation `json:"attestation_document"`
}

type AuxFunc func(*nonce.Nonce) *AuxInfo

type AuxInfo struct {
	PublicKey [userDataLen]byte `json:"workers_nonce"`
	UserData  [userDataLen]byte `json:"leaders_nonce"`
	Nonce     [userDataLen]byte `json:"public_key"`
}

func ToAuxField(s []byte) [userDataLen]byte {
	var a [userDataLen]byte
	copy(a[:], s)
	return a
}

// Attester defines functions for the creation and verification of attestation
// documents. Making this an interface helps with testing: It allows us to
// implement a dummy attester that works without the AWS Nitro hypervisor.
type Attester interface {
	Type() string
	Attest(*AuxInfo) (*AttestationDoc, error)
	Verify(Attestation, *nonce.Nonce) (*AuxInfo, error)
}
