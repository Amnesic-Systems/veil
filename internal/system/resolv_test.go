package system

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Amnesic-Systems/veil/internal/addr"
)

func TestRenderResolvConf(t *testing.T) {
	got := renderResolvConf("10.0.0.1", []string{
		"ec2.internal",
		"example.com",
	}, addr.Of(2))
	require.Equal(t, `nameserver 10.0.0.1
search ec2.internal example.com
options ndots:2
`, got)
}

func TestRenderResolvConfOnlyNameserver(t *testing.T) {
	got := renderResolvConf("1.1.1.1", nil, nil)
	require.Equal(t, "nameserver 1.1.1.1\n", got)
}
