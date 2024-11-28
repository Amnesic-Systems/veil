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
	bar := errors.New("bar")
	err := Add(bar, "foo")
	require.Equal(t, "foo: bar", err.Error())
	require.ErrorIs(t, err, bar)
}
