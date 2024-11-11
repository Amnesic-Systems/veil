package enclave

import (
	"github.com/Amnesic-Systems/veil/internal/nonce"
)

const (
	// See page 65 of the AWS Nitro Enclaves user guide for reference:
	// https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf
	AuxFieldLen = 1024
	TypeNoop    = "noop"
	TypeNitro   = "nitro"
)

// RawDocument holds the enclave's COSE-encoded attestation document.
type RawDocument struct {
	Type string `json:"type"`
	Doc  []byte `json:"attestation_document"`
}

// Document represents the AWS Nitro Enclave attestation document as specified
// on page 70 of:
// https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf
type Document struct {
	ModuleID    string   `cbor:"module_id" json:"module_id"`
	Timestamp   uint64   `cbor:"timestamp" json:"timestamp"`
	Digest      string   `cbor:"digest" json:"digest"`
	PCRs        PCR      `cbor:"pcrs" json:"pcrs"`
	Certificate []byte   `cbor:"certificate" json:"certificate"`
	CABundle    [][]byte `cbor:"cabundle" json:"cabundle"`
	AuxInfo
}

// AuxInfo represents auxiliary information that can be included in the
// attestation document, as specified on page 70 of:
// https://docs.aws.amazon.com/pdfs/enclaves/latest/user/enclaves-user.pdf
type AuxInfo struct {
	PublicKey []byte `json:"public_key,omitempty" cbor:"public_key"`
	UserData  []byte `json:"user_data,omitempty" cbor:"user_data"`
	Nonce     []byte `json:"nonce,omitempty" cbor:"nonce"`
}

// Attester defines functions for the creation and verification of attestation
// documents. Making this an interface helps with testing: It allows us to
// implement a dummy attester that works without the AWS Nitro hypervisor.
type Attester interface {
	Type() string
	Attest(*AuxInfo) (*RawDocument, error)
	Verify(*RawDocument, *nonce.Nonce) (*Document, error)
}
