package util

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMust(t *testing.T) {
	t.Parallel()

	require.Equal(t, 1, Must(1, nil))
	require.Panics(t, func() {
		_ = Must("foo", errors.New("an error"))
	})
}
