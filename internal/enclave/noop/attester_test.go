package noop

import (
	"strings"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/util/must"
	"github.com/stretchr/testify/require"
)

func TestType(t *testing.T) {
	require.Equal(t, enclave.TypeNoop, NewAttester().Type())
}

func TestSuccessfulVerification(t *testing.T) {
	var (
		a       = NewAttester()
		n       = must.Get(nonce.FromSlice([]byte(strings.Repeat("a", 20))))
		origAux = enclave.AuxInfo{
			PublicKey: []byte("abc"),
			UserData:  []byte("def"),
			Nonce:     n.ToSlice(),
		}
	)

	attestation, err := a.Attest(&origAux)
	require.Nil(t, err)

	doc, err := a.Verify(attestation, n)
	require.Nil(t, err)
	require.Equal(t, origAux, doc.AuxInfo)
}

func TestFailedVerification(t *testing.T) {
	var a = NewAttester()

	_, err := a.Verify(&enclave.RawDocument{
		Type: enclave.TypeNoop,
		Doc:  []byte(`"foo": "bar`),
	}, &nonce.Nonce{})
	require.NotNil(t, err)
}
