package enclave

func ToAuxField(s []byte) *[AuxFieldLen]byte {
	var a [AuxFieldLen]byte
	copy(a[:], s)
	return &a
}
