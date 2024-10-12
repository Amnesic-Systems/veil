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
