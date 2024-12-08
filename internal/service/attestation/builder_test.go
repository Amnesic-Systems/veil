package attestation

import (
	"crypto/sha256"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/addr"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/enclave/nitro"
	"github.com/Amnesic-Systems/veil/internal/enclave/noop"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/util"
	"github.com/stretchr/testify/require"
)

func TestBuilder(t *testing.T) {
	attester := noop.NewAttester()
	if nitro.IsEnclave() {
		attester = nitro.NewAttester()
	}
	nonce1, nonce2 := util.Must(nonce.New()), util.Must(nonce.New())
	sha1, sha2 := sha256.Sum256([]byte("foo")), sha256.Sum256([]byte("bar"))
	hashes1 := &Hashes{TlsKeyHash: addr.Of(sha256.Sum256([]byte("foo")))}
	hashes2 := &Hashes{TlsKeyHash: addr.Of(sha256.Sum256([]byte("bar")))}

	cases := []struct {
		name         string
		initFields   []auxField
		attestFields []auxField
		wantAux      *enclave.AuxInfo
	}{
		{
			name:    "empty",
			wantAux: &enclave.AuxInfo{},
		},
		{
			name:       "nonce at initialization",
			initFields: []auxField{WithNonce(nonce1)},
			wantAux:    &enclave.AuxInfo{Nonce: nonce1.ToSlice()},
		},
		{
			name:         "nonce at attestation",
			attestFields: []auxField{WithNonce(nonce1)},
			wantAux:      &enclave.AuxInfo{Nonce: nonce1.ToSlice()},
		},
		{
			name:         "nonce being overwritten",
			initFields:   []auxField{WithNonce(nonce1)},
			attestFields: []auxField{WithNonce(nonce2)},
			wantAux:      &enclave.AuxInfo{Nonce: nonce2.ToSlice()},
		},
		{
			name:         "everything overwritten",
			initFields:   []auxField{WithHashes(hashes1), WithNonce(nonce1), WithSHA256(sha1)},
			attestFields: []auxField{WithHashes(hashes2), WithNonce(nonce2), WithSHA256(sha2)},
			wantAux: &enclave.AuxInfo{
				Nonce:     nonce2.ToSlice(),
				PublicKey: hashes2.Serialize(),
				UserData:  sha2[:],
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := NewBuilder(attester, c.initFields...)
			rawDoc, err := b.Attest(c.attestFields...)
			require.NoError(t, err)

			// Verify the attestation document.  We expect no error but if the
			// test is run inside a Nitro Enclave, we will get ErrDebugMode.
			doc, err := attester.Verify(rawDoc, nil)
			if err != nil {
				require.ErrorIs(t, err, nitro.ErrDebugMode)
			}
			require.Equal(t, c.wantAux, &doc.AuxInfo)
		})
	}
}
