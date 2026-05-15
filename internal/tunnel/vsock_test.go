package tunnel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVsockTunneler(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	require.ErrorIs(t, NewVSOCK().Start(ctx, 0), context.Canceled)
}
