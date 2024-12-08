package attestation

import (
	"crypto/sha256"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/addr"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/util"
	"github.com/stretchr/testify/require"
)

func TestGetters(t *testing.T) {
	n := util.Must(nonce.New())
	s := addr.Of(sha256.Sum256([]byte("foo")))
	h1 := &Hashes{TlsKeyHash: addr.Of(sha256.Sum256([]byte("foo")))}
	h2 := &Hashes{
		TlsKeyHash: addr.Of(sha256.Sum256([]byte("foo"))),
		AppKeyHash: addr.Of(sha256.Sum256([]byte("bar"))),
	}

	cases := []struct {
		name       string
		aux        *enclave.AuxInfo
		wantNonce  *nonce.Nonce
		wantSHA    *[sha256.Size]byte
		wantHashes *Hashes
		wantErr    error
	}{
		{
			name:    "no fields",
			aux:     &enclave.AuxInfo{},
			wantErr: errs.IsNil,
		},
		{
			name: "all fields, some hashes",
			aux: &enclave.AuxInfo{
				Nonce:     n.ToSlice(),
				UserData:  s[:],
				PublicKey: h1.Serialize(),
			},
			wantNonce:  n,
			wantSHA:    s,
			wantHashes: h1,
		},
		{
			name: "all fields, all hashes",
			aux: &enclave.AuxInfo{
				Nonce:     n.ToSlice(),
				UserData:  s[:],
				PublicKey: h2.Serialize(),
			},
			wantNonce:  n,
			wantSHA:    s,
			wantHashes: h2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, err := GetNonce(c.aux)
			require.Equal(t, c.wantErr, err)
			s, err := GetSHA256(c.aux)
			require.Equal(t, c.wantErr, err)
			h, err := GetHashes(c.aux)
			require.Equal(t, c.wantErr, err)

			require.Equal(t, c.wantNonce, n)
			require.Equal(t, c.wantSHA, s)
			require.Equal(t, c.wantHashes, h)
		})
	}
}
