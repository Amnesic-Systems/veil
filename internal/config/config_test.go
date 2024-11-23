package config

import (
	"context"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/util"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *Config
		wantErrs int
	}{
		{
			name: "valid config",
			cfg:  &Config{ExtPort: 8443, IntPort: 8080},
		},
		{
			name: "still valid config",
			cfg:  &Config{ExtPort: 1, IntPort: 65535},
		},
		{
			name:     "invalid ports",
			cfg:      &Config{ExtPort: 0, IntPort: 65536},
			wantErrs: 2,
		},
		{
			name: "invalid flag combination",
			cfg: &Config{
				SilenceApp: true,
				ExtPort:    8443,
				IntPort:    8080,
			},
			wantErrs: 1,
		},
		{
			name: "valid flag combination",
			cfg: &Config{
				SilenceApp: true,
				AppCmd:     "echo",
				ExtPort:    8443,
				IntPort:    8080,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := c.cfg.Validate(context.Background())
			require.Equal(t, c.wantErrs, len(errs), util.SprintErrs(errs))
		})
	}
}
