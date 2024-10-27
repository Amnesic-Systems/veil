package enclave

import (
	"errors"

	"github.com/Amnesic-Systems/veil/internal/nonce"
)

const (
	// See page 65 of the AWS Nitro Enclaves user guide for reference:
	// https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf
	AuxFieldLen = 1024
	typeNoop    = "noop"
	typeNitro   = "nitro"
)

var (
	errNonceMismatch = errors.New("nonce does not match")

	// Check at compile-time if types implement the attester interface.
	_ Attester = (*NitroAttester)(nil)
	_ Attester = (*NoopAttester)(nil)
)

// AttestationDoc holds the enclave's attestation document.
type AttestationDoc struct {
	Type string `json:"type"`
	Doc  []byte `json:"attestation_document"`
}

type AuxInfo struct {
	PublicKey *[AuxFieldLen]byte `json:"public_key"`
	UserData  *[AuxFieldLen]byte `json:"user_data"`
	Nonce     *[AuxFieldLen]byte `json:"nonce"`
}

// Attester defines functions for the creation and verification of attestation
// documents. Making this an interface helps with testing: It allows us to
// implement a dummy attester that works without the AWS Nitro hypervisor.
type Attester interface {
	Type() string
	Attest(*AuxInfo) (*AttestationDoc, error)
	Verify(*AttestationDoc, *nonce.Nonce) (*AuxInfo, error)
}
