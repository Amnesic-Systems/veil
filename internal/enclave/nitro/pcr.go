package nitro

import (
	"bytes"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
)

// pcr represents the enclave's platform configuration register (PCR) values.
type pcr map[uint][]byte

// getPCRs returns the enclave's platform configuration register (PCR) values.
func getPCRs() (_ pcr, err error) {
	defer errs.Wrap(&err, "failed to get PCRs")

	attestation, err := NewAttester().Attest(&enclave.AuxInfo{})
	if err != nil {
		return nil, err
	}

	res, err := verify(attestation.Doc, verifyOptions{})
	if err != nil {
		return nil, err
	}

	return pcr(res.Document.PCRs), nil
}

// Equal returns true if (and only if) the two given PCR maps are identical.
func (ours pcr) Equal(theirs pcr) bool {
	// PCR4 contains a hash over the parent's instance ID.  Our enclaves run
	// on different parent instances, so PCR4 will therefore always differ:
	// https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html
	delete(ours, 4)
	delete(theirs, 4)

	if len(ours) != len(theirs) {
		return false
	}

	for i, ourValue := range ours {
		theirValue, exists := theirs[i]
		if !exists {
			return false
		}
		if !bytes.Equal(ourValue, theirValue) {
			return false
		}
	}
	return true
}
