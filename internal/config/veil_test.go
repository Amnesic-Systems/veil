package config

import (
	"testing"

	"github.com/Amnesic-Systems/veil/internal/types/validate"
	"github.com/stretchr/testify/require"
)

func TestVeilConfig(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *Veil
		wantErrs int
	}{
		{
			name: "valid config",
			cfg:  &Veil{ExtPort: 8443, IntPort: 8080},
		},
		{
			name: "still valid config",
			cfg:  &Veil{ExtPort: 1, IntPort: 65535},
		},
		{
			name:     "invalid ports",
			cfg:      &Veil{ExtPort: 0, IntPort: 65536},
			wantErrs: 2,
		},
		{
			name: "invalid flag combination",
			cfg: &Veil{
				SilenceApp: true,
				ExtPort:    8443,
				IntPort:    8080,
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
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := c.cfg.Validate()
			require.Equal(t, c.wantErrs, len(errs), validate.SprintErrs(errs))
		})
	}
}
