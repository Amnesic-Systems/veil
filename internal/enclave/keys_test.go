package enclave

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		keys    *Keys
		numErrs int
	}{
		{
			"valid",
			&Keys{
				VeilKey:  []byte("veil_key"),
				VeilCert: []byte("veil_cert"),
				AppKeys:  []byte("app_keys"),
			},
			0,
		},
		{
			"empty keys",
			&Keys{
				VeilKey:  []byte(""),
				VeilCert: []byte(""),
				AppKeys:  []byte(""),
			},
			3,
		},
		{
			"missing veil key",
			&Keys{
				VeilCert: []byte("veil_cert"),
				AppKeys:  []byte("app_keys"),
			},
			1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotErrs := len(c.keys.Validate(context.Background()))
			require.Equal(t, c.numErrs, gotErrs)
		})
	}
}

func TestSetAndEqual(t *testing.T) {
	var (
		ours = &Keys{
			VeilKey:  []byte("foo"),
			VeilCert: []byte("foo"),
			AppKeys:  []byte("foo"),
		}
		theirs = &Keys{
			VeilKey:  []byte("bar"),
			VeilCert: []byte("bar"),
			AppKeys:  []byte("bar"),
		}
	)

	// At first, our two sets of keys are not equal.  Also, comparison is
	// commutative.
	assert.False(t, ours.Equal(theirs))
	assert.False(t, theirs.Equal(ours))

	ours.Set(theirs)

	// Keys should now be equal.
	assert.True(t, ours.Equal(theirs))
	assert.True(t, theirs.Equal(ours))
}
