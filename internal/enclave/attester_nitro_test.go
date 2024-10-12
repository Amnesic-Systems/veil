package enclave

import (
	"testing"

	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/util"
	"github.com/stretchr/testify/require"
)

func TestAttest(t *testing.T) {
	t.Parallel()

	// It's difficult to test this function because it needs a Nitro Enclave to
	// run.  We can however test that it returns an error when it can't run.
	var nitro = NewNitroAttester()
	_, err := nitro.Attest(&AuxInfo{})
	require.Error(t, err)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	var (
		nitro = NewNitroAttester()
		n     = util.Must(nonce.New())
		a     = Attestation([]byte("foo"))
	)

	// Same as above.  We can really only test that we get an error.
	_, err := nitro.Verify(a, n)
	require.Error(t, err)
}
