package config

import (
	"context"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/util"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	defaultConfig := Config{
		ExtPort: "443",
		IntPort: "8081",
	}

	cases := []struct {
		name     string
		cfgFn    func() *Config
		wantErrs int
	}{
		{
			name: "default config",
			cfgFn: func() *Config {
				return &defaultConfig
			},
			wantErrs: 0,
		},
		{
			name: "missing ports",
			cfgFn: func() *Config {
				confCopy := defaultConfig
				confCopy.IntPort = "foo"
				confCopy.ExtPort = ""
				return &confCopy
			},
			wantErrs: 2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := c.cfgFn().Validate(context.Background())
			require.Equal(t, c.wantErrs, len(errs), util.SprintErrs(errs))
		})
	}
}
