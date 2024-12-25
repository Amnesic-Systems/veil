package config

import (
	"testing"

	"github.com/Amnesic-Systems/veil/internal/types/validate"
	"github.com/stretchr/testify/require"
)

func TestVeilProxyConfig(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *VeilProxy
		wantErrs int
	}{
		{
			name:     "invalid port",
			cfg:      &VeilProxy{VSOCKPort: 0},
			wantErrs: 1,
		},
		{
			name: "valid port",
			cfg:  &VeilProxy{VSOCKPort: 1},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := c.cfg.Validate()
			require.Equal(t, c.wantErrs, len(errs), validate.SprintErrs(errs))
		})
	}
}
