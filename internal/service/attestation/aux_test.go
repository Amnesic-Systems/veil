package attestation

import (
	"crypto/sha256"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/enclave/nitro"
	"github.com/Amnesic-Systems/veil/internal/enclave/noop"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/util"
	"github.com/stretchr/testify/require"
)

func TestGetters(t *testing.T) {
	n := util.Must(nonce.New())
	s := util.AddrOf(sha256.Sum256([]byte("foo")))
	h1 := &Hashes{TlsKeyHash: util.AddrOf(sha256.Sum256([]byte("foo")))}
	h2 := &Hashes{
		TlsKeyHash: util.AddrOf(sha256.Sum256([]byte("foo"))),
		AppKeyHash: util.AddrOf(sha256.Sum256([]byte("bar"))),
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
				Nonce:     enclave.ToAuxField(n.ToSlice()),
				UserData:  enclave.ToAuxField(s[:]),
				PublicKey: enclave.ToAuxField(h1.Serialize()),
			},
			wantNonce:  n,
			wantSHA:    s,
			wantHashes: h1,
		},
		{
			name: "all fields, all hashes",
			aux: &enclave.AuxInfo{
				Nonce:     enclave.ToAuxField(n.ToSlice()),
				UserData:  enclave.ToAuxField(s[:]),
				PublicKey: enclave.ToAuxField(h2.Serialize()),
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

func TestBuilder(t *testing.T) {
	attester := noop.NewAttester()
	if nitro.IsEnclave() {
		attester = nitro.NewAttester()
	}
	nonce1, nonce2 := util.Must(nonce.New()), util.Must(nonce.New())
	sha1, sha2 := sha256.Sum256([]byte("foo")), sha256.Sum256([]byte("bar"))
	hashes1 := &Hashes{TlsKeyHash: util.AddrOf(sha256.Sum256([]byte("foo")))}
	hashes2 := &Hashes{TlsKeyHash: util.AddrOf(sha256.Sum256([]byte("bar")))}

	cases := []struct {
		name         string
		initFields   []AuxField
		attestFields []AuxField
		wantAux      *enclave.AuxInfo
	}{
		{
			name:    "empty",
			wantAux: &enclave.AuxInfo{},
		},
		{
			name:       "nonce at initialization",
			initFields: []AuxField{WithNonce(nonce1)},
			wantAux:    &enclave.AuxInfo{Nonce: enclave.ToAuxField(nonce1.ToSlice())},
		},
		{
			name:         "nonce at attestation",
			attestFields: []AuxField{WithNonce(nonce1)},
			wantAux:      &enclave.AuxInfo{Nonce: enclave.ToAuxField(nonce1.ToSlice())},
		},
		{
			name:         "nonce being overwritten",
			initFields:   []AuxField{WithNonce(nonce1)},
			attestFields: []AuxField{WithNonce(nonce2)},
			wantAux:      &enclave.AuxInfo{Nonce: enclave.ToAuxField(nonce2.ToSlice())},
		},
		{
			name:         "everything overwritten",
			initFields:   []AuxField{WithHashes(hashes1), WithNonce(nonce1), WithSHA256(sha1)},
			attestFields: []AuxField{WithHashes(hashes2), WithNonce(nonce2), WithSHA256(sha2)},
			wantAux: &enclave.AuxInfo{
				Nonce:     enclave.ToAuxField(nonce2.ToSlice()),
				PublicKey: enclave.ToAuxField(hashes2.Serialize()),
				UserData:  enclave.ToAuxField(sha2[:]),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := NewBuilder(attester, c.initFields...)
			doc, err := b.Attest(c.attestFields...)
			require.NoError(t, err)

			aux, err := attester.Verify(doc, nil)
			require.NoError(t, err)
			require.Equal(t, c.wantAux, aux)
		})
	}
}
