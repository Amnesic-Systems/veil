package enclave

// IsEnclave returns true if the current process is running in an enclave.
func IsEnclave() bool {
	// The most straightforward way to determine if we're running in an enclave
	// is to try and request an attestation document.
	if _, err := getPCRs(); err == nil {
		return true
	}
	return false
}
