package nitro

import (
	"testing"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/util/must"
	"github.com/stretchr/testify/require"
)

func TestNitroAttest(t *testing.T) {
	if !IsEnclave() {
		t.Skip("skipping test; not running in an enclave")
	}
	attester := NewAttester()

	cases := []struct {
		name    string
		aux     *enclave.AuxInfo
		wantErr bool
	}{
		{
			name:    "nil aux info",
			wantErr: true,
		},
		{
			name: "empty aux info",
			aux:  &enclave.AuxInfo{},
		},
		{
			name: "aux info with nonce",
			aux: &enclave.AuxInfo{
				Nonce: must.Get(nonce.New()).ToSlice(),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc, err := attester.Attest(c.aux)
			if c.wantErr {
				require.NotNil(t, err)
				return
			}
			require.Equal(t, doc.Type, enclave.TypeNitro)
		})
	}
}

func TestNitroVerify(t *testing.T) {
	if !IsEnclave() {
		t.Skip("skipping test; not running in an enclave")
	}

	attester := NewAttester()
	getDoc := func(t *testing.T, n *nonce.Nonce) *enclave.RawDocument {
		doc, err := attester.Attest(&enclave.AuxInfo{Nonce: n.ToSlice()})
		require.NoError(t, err)
		return doc
	}
	testNonce := must.Get(nonce.New())

	cases := []struct {
		name    string
		doc     *enclave.RawDocument
		nonce   *nonce.Nonce
		wantErr bool
	}{
		{
			name:    "nil document and nonce",
			wantErr: true,
		},
		{
			name:    "document type mismatch",
			doc:     &enclave.RawDocument{Type: "foo"},
			wantErr: true,
		},
		{
			name: "invalid document",
			doc: &enclave.RawDocument{
				Type: enclave.TypeNitro,
				Doc:  []byte("foobar"),
			},
			wantErr: true,
		},
		{
			name:    "nonce mismatch",
			doc:     getDoc(t, must.Get(nonce.New())),
			nonce:   must.Get(nonce.New()),
			wantErr: true,
		},
		{
			name: "no nonce",
			doc:  getDoc(t, must.Get(nonce.New())),
		},
		{
			name:  "valid document and nonce",
			doc:   getDoc(t, testNonce),
			nonce: testNonce,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := attester.Verify(c.doc, c.nonce)
			if c.wantErr {
				require.Error(t, err)
				return
			}
		})
	}
}
