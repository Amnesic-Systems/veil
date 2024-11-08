package nitro

import "github.com/Amnesic-Systems/veil/internal/enclave"

// IsEnclave returns true if the current process is running in an enclave.
func IsEnclave() bool {
	// The most straightforward way to determine if we're running in an enclave
	// is to try and request an attestation document.
	attestation, err := NewAttester().Attest(&enclave.AuxInfo{})
	if err != nil {
		return false
	}

	_, err = verify(attestation.Doc, verifyOptions{})
	return err == nil
}
