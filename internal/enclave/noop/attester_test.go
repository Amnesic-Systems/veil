package noop

import (
	"testing"

	"github.com/Amnesic-Systems/veil/internal/addr"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/stretchr/testify/require"
)

func TestType(t *testing.T) {
	require.Equal(t, enclave.TypeNoop, NewAttester().Type())
}

func TestSuccessfulVerification(t *testing.T) {
	var (
		a       = NewAttester()
		origAux = &enclave.AuxInfo{
			PublicKey: addr.Of([enclave.AuxFieldLen]byte{'a', 'b', 'c'}),
			UserData:  addr.Of([enclave.AuxFieldLen]byte{'d', 'e', 'f'}),
			Nonce:     addr.Of([enclave.AuxFieldLen]byte{'g', 'h', 'i'}),
		}
	)

	attestation, err := a.Attest(origAux)
	require.Nil(t, err)

	aux, err := a.Verify(attestation, &nonce.Nonce{})
	require.Nil(t, err)
	require.Equal(t, origAux, aux)
}

func TestFailedVerification(t *testing.T) {
	var a = NewAttester()

	_, err := a.Verify(&enclave.AttestationDoc{
		Type: enclave.TypeNoop,
		Doc:  []byte(`"foo": "bar`),
	}, &nonce.Nonce{})
	require.NotNil(t, err)
}
