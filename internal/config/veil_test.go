package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Amnesic-Systems/veil/internal/addr"
	"github.com/Amnesic-Systems/veil/internal/types/validate"
)

func TestVeilConfig(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *Veil
		wantErrs int
	}{
		{
			name: "valid config",
			cfg:  &Veil{ExtPort: 8443, IntPort: 8080, VSOCKPort: 1024},
		},
		{
			name: "still valid config",
			cfg:  &Veil{ExtPort: 1, IntPort: 65535, VSOCKPort: 1024},
		},
		{
			name:     "invalid ports",
			cfg:      &Veil{ExtPort: 0, IntPort: 65536, VSOCKPort: 0},
			wantErrs: 3,
		},
		{
			name: "invalid flag combination",
			cfg: &Veil{
				SilenceApp: true,
				ExtPort:    8443,
				IntPort:    8080,
				VSOCKPort:  1024,
			},
			wantErrs: 1,
		},
		{
			name: "valid flag combination",
			cfg: &Veil{
				SilenceApp: true,
				AppCmd:     "echo",
				ExtPort:    8443,
				IntPort:    8080,
				VSOCKPort:  1024,
			},
		},
		{
			name: "invalid ndots",
			cfg: &Veil{
				ExtPort:   8443,
				IntPort:   8080,
				NDots:     addr.Of(16),
				VSOCKPort: 1024,
			},
			wantErrs: 1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := c.cfg.Validate()
			require.Equal(t, c.wantErrs, len(errs), validate.SprintErrs(errs))
		})
	}
}
