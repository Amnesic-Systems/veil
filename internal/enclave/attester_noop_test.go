package enclave

import (
	"testing"

	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/util"
	"github.com/stretchr/testify/require"
)

func TestType(t *testing.T) {
	require.Equal(t, typeNoop, NewNoopAttester().Type())
}

func TestSuccessfulVerification(t *testing.T) {
	var (
		a       = NewNoopAttester()
		origAux = &AuxInfo{
			PublicKey: util.AddrOf([AuxFieldLen]byte{'a', 'b', 'c'}),
			UserData:  util.AddrOf([AuxFieldLen]byte{'d', 'e', 'f'}),
			Nonce:     util.AddrOf([AuxFieldLen]byte{'g', 'h', 'i'}),
		}
	)

	attestation, err := a.Attest(origAux)
	require.Nil(t, err)

	aux, err := a.Verify(attestation, &nonce.Nonce{})
	require.Nil(t, err)
	require.Equal(t, origAux, aux)
}

func TestFailedVerification(t *testing.T) {
	var a = NewNoopAttester()

	_, err := a.Verify(&AttestationDoc{
		Type: typeNoop,
		Doc:  []byte(`"foo": "bar`),
	}, &nonce.Nonce{})
	require.NotNil(t, err)
}
