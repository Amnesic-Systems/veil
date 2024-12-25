package config

import (
	"testing"

	"github.com/Amnesic-Systems/veil/internal/types/validate"
	"github.com/stretchr/testify/require"
)

func TestVeilVerifyConfig(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *VeilVerify
		wantErrs int
	}{
		{
			name:     "missing addr, dir, and dockerfile",
			cfg:      &VeilVerify{},
			wantErrs: 3,
		},
		{
			name:     "missing addr and dockerfile",
			cfg:      &VeilVerify{Dir: "foo"},
			wantErrs: 2,
		},
		{
			name:     "missing dir and dockerfile",
			cfg:      &VeilVerify{Addr: "https://example.com"},
			wantErrs: 2,
		},
		{
			name: "missing dockerfile",
			cfg: &VeilVerify{
				Dir:  "foo",
				Addr: "https://example.com",
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
