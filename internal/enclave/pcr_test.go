package enclave

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPCRsFromDebugMode(t *testing.T) {
	cases := []struct {
		name string
		pcrs pcr
		want bool
	}{
		{
			name: "empty",
			pcrs: pcr{},
		},
		{
			name: "debug mode",
			pcrs: pcr{
				0: emptyPCR,
				1: emptyPCR,
				2: emptyPCR,
				3: []byte("foo"), // Should be ignored.
				4: []byte("bar"), // Should be ignored.
			},
			want: true,
		},
		{
			name: "not debug mode",
			pcrs: pcr{
				0: []byte("foo"),
				1: emptyPCR,
				2: emptyPCR,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, c.pcrs.FromDebugMode())
		})
	}
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