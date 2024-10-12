package enclave

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPCRs(t *testing.T) {
	_, err := getPCRs()
	// We expect an error when asking for PCRs outside of an enclave.
	require.Error(t, err)
}

func TestPCRsEqual(t *testing.T) {
	cases := []struct {
		name string
		pcr1 pcr
		pcr2 pcr
		want bool
	}{
		{
			name: "empty",
			pcr1: pcr{},
			pcr2: pcr{},
			want: true,
		},
		{
			name: "identical",
			pcr1: pcr{
				1: []byte("foobar"),
			},
			pcr2: pcr{
				1: []byte("foobar"),
			},
			want: true,
		},
		{
			name: "PCR mismatch",
			pcr1: pcr{
				1: []byte("foobar"),
			},
			pcr2: pcr{
				1: []byte("barfoo"),
			},
			want: false,
		},
		{
			name: "ignore PCR4",
			pcr1: pcr{
				1: []byte("foobar"),
				4: []byte("foo"),
			},
			pcr2: pcr{
				1: []byte("foobar"),
				4: []byte("bar"),
			},
			want: true,
		},
		{
			name: "length mismatch",
			pcr1: pcr{
				1: []byte("foobar"),
				2: []byte("foo"),
			},
			pcr2: pcr{
				1: []byte("foobar"),
			},
			want: false,
		},
		{
			name: "PCR index mismatch",
			pcr1: pcr{
				1: []byte("foo"),
			},
			pcr2: pcr{
				2: []byte("foo"),
			},
			want: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, c.pcr1.Equal(c.pcr2))
		})
	}
}
