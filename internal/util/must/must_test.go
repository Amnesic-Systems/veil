package must

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMust(t *testing.T) {
	t.Parallel()

	require.Equal(t, 1, Get(1, nil))
	require.Panics(t, func() {
		_ = Get("foo", errors.New("an error"))
	})
}
