package addr

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOf(t *testing.T) {
	t.Parallel()

	x := 1
	require.Equal(t, &x, Of(x))
}
