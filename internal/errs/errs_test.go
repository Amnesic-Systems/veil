package errs

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWrap(t *testing.T) {
	var err = errors.New("foo")
	Wrap(&err, "bar")
	require.Equal(t, "bar: foo", err.Error())
}

func TestWrapErr(t *testing.T) {
	var wrapper, wrapped = errors.New("foo"), errors.New("bar")
	WrapErr(&wrapped, wrapper)
	require.ErrorIs(t, wrapped, wrapper)
	require.Equal(t, "foo: bar", wrapped.Error())
}

func TestAdd(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{
			name: "error",
			err:  errors.New("foo"),
		},
		{
			name: "no error",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Add(c.err, "bar")
			if c.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, c.err)
			}
		})
	}
}
