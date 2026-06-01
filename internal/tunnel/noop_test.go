package tunnel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoopTunneler(t *testing.T) {
	require.NoError(t, NewNoop().Start(t.Context(), Settings{}))
}
