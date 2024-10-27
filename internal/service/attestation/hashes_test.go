package attestation

import (
	"crypto/sha256"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/util"
	"github.com/stretchr/testify/require"
)

func TestDeSerialization(t *testing.T) {
	var (
		origHashes = new(Hashes)
	)
	origHashes.SetAppHash(util.AddrOf(sha256.Sum256([]byte("foo"))))
	origHashes.SetTLSHash(util.AddrOf(sha256.Sum256([]byte("bar"))))

	hashes, err := DeserializeHashes(origHashes.Serialize())
	require.NoError(t, err)
	require.Equal(t, origHashes, hashes)
}

func TestFailedDeserialization(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{
			name: "nil",
			in:   nil,
		},
		{
			name: "no separator",
			in:   []byte("sha256:foo"),
		},
		{
			name: "too many separators",
			in:   []byte("sha256:foo;sha256:bar;sha256:baz"),
		},
		{
			name: "invalid tls base64",
			in:   []byte("sha256:123;sha256:456"),
		},
		{
			name: "invalid app base64",
			in:   []byte("sha256:Zm9vCg==;sha256:456"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DeserializeHashes(c.in)
			require.ErrorIs(t, err, errs.InvalidFormat)
		})
	}
}
