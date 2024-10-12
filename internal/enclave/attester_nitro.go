package enclave

import (
	"errors"
	"time"

	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"

	"github.com/hf/nitrite"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

// NitroAttester implements the attester interface by drawing on the AWS Nitro
// Enclave hypervisor.
type NitroAttester struct{}

// NewNitroAttester returns a new nitroAttester.
func NewNitroAttester() Attester {
	return new(NitroAttester)
}

func (*NitroAttester) Type() string {
	return "nitro"
}

func (*NitroAttester) Attest(aux *AuxInfo) (*AttestationDoc, error) {
	var (
		err     error
		resp    response.Response
		session *nsm.Session
	)

	req := &request.Attestation{
		Nonce:     aux.Nonce[:],
		UserData:  aux.UserData[:],
		PublicKey: aux.PublicKey[:],
	}

	// TODO: do this once, at object creation time?
	if session, err = nsm.OpenDefaultSession(); err != nil {
		return nil, err
	}
	defer session.Close()

	if resp, err = session.Send(req); err != nil {
		return nil, err
	}
	if resp.Attestation == nil || resp.Attestation.Document == nil {
		return nil, errors.New("not good")
	}
	return &AttestationDoc{
		Type: "nitro",
		Doc:  resp.Attestation.Document,
	}, nil
}

func (*NitroAttester) Verify(a Attestation, ourNonce *nonce.Nonce) (_ *AuxInfo, err error) {
	defer errs.Wrap(&err, "failed to verify attestation document")

	// First, verify the remote enclave's attestation document.
	opts := nitrite.VerifyOptions{CurrentTime: time.Now().UTC()}
	their, err := nitrite.Verify(a, opts)
	if err != nil {
		return nil, err
	}

	// Verify that the remote enclave's PCR values (e.g., the image ID) are
	// identical to ours.
	ourPCRs, err := getPCRs()
	if err != nil {
		return nil, err
	}
	if !ourPCRs.Equal(their.Document.PCRs) {
		return nil, errPCRMismatch
	}

	// Verify that the remote enclave's attestation document contains the nonce
	// that we asked it to embed.
	theirNonce, err := nonce.FromSlice(their.Document.Nonce)
	if err != nil {
		return nil, err
	}
	if *ourNonce != *theirNonce {
		return nil, errNonceMismatch
	}

	return &AuxInfo{
		Nonce:     [1024]byte(their.Document.Nonce),
		UserData:  [1024]byte(their.Document.UserData),
		PublicKey: [1024]byte(their.Document.PublicKey),
	}, nil
}
