package nat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func withIPForwardFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ip_forward")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	oldPath := ipForwardPath
	oldRestore := restoreIPForward
	ipForwardPath = path
	restoreIPForward = nil
	t.Cleanup(func() {
		ipForwardPath = oldPath
		restoreIPForward = oldRestore
	})

	return path
}

func TestEnableIPForwardingLeavesEnabledStateAlone(t *testing.T) {
	path := withIPForwardFile(t, "1\n")

	require.NoError(t, enableIPForwarding())
	require.Nil(t, restoreIPForward)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "1\n", string(got))
}

func TestEnableIPForwardingRestoresDisabledState(t *testing.T) {
	path := withIPForwardFile(t, "0\n")

	require.NoError(t, enableIPForwarding())
	require.NotNil(t, restoreIPForward)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "1\n", string(got))

	require.NoError(t, restorePriorIPForwarding())
	require.Nil(t, restoreIPForward)

	got, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "0\n", string(got))
}
