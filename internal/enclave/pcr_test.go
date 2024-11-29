package enclave

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPCRsFromDebugMode(t *testing.T) {
	cases := []struct {
		name string
		pcrs PCR
		want bool
	}{
		{
			name: "empty",
			pcrs: PCR{},
		},
		{
			name: "debug mode",
			pcrs: PCR{
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
			pcrs: PCR{
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
		pcr1 PCR
		pcr2 PCR
		want bool
	}{
		{
			name: "empty",
			pcr1: PCR{},
			pcr2: PCR{},
			want: true,
		},
		{
			name: "identical",
			pcr1: PCR{
				1: []byte("foobar"),
			},
			pcr2: PCR{
				1: []byte("foobar"),
			},
			want: true,
		},
		{
			name: "PCR mismatch",
			pcr1: PCR{
				1: []byte("foobar"),
			},
			pcr2: PCR{
				1: []byte("barfoo"),
			},
			want: false,
		},
		{
			name: "ignore PCR4",
			pcr1: PCR{
				1: []byte("foobar"),
				4: []byte("foo"),
			},
			pcr2: PCR{
				1: []byte("foobar"),
				4: []byte("bar"),
			},
			want: true,
		},
		{
			name: "length mismatch",
			pcr1: PCR{
				1: []byte("foobar"),
				2: []byte("foo"),
			},
			pcr2: PCR{
				1: []byte("foobar"),
			},
			want: false,
		},
		{
			name: "length mismatch due to PCR4",
			pcr1: PCR{
				1: []byte("foo"),
				4: []byte("bar"),
			},
			pcr2: PCR{
				1: []byte("foo"),
			},
			want: true,
		},
		{
			name: "PCR index mismatch",
			pcr1: PCR{
				1: []byte("foo"),
			},
			pcr2: PCR{
				2: []byte("foo"),
			},
			want: false,
		},
		{
			name: "one PCR missing",
			pcr1: PCR{},
			pcr2: PCR{
				0: []byte("foo"),
				1: []byte("bar"),
				2: []byte("baz"),
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
