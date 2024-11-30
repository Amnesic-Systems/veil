package main

import (
	"testing"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/stretchr/testify/require"
)

func TestToPCR(t *testing.T) {
	cases := []struct {
		name     string
		in       []byte
		wantPCRs enclave.PCR
		wantErr  bool
	}{
		{
			name:    "invalid json",
			in:      []byte("invalid"),
			wantErr: true,
		},
		{
			name: "invalid hash",
			in: []byte(`{
				"Measurements": {
					"HashAlgorithm": "Sha512 { ... }",
					"PCR0": "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161",
					"PCR1": "626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262",
					"PCR2": "636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363"
				}
			}`),
			wantErr: true,
		},
		{
			name: "invalid PCR value",
			in: []byte(`{
				"Measurements": {
					"HashAlgorithm": "Sha512 { ... }",
					"PCR0": "foobar",
				}
			}`),
			wantErr: true,
		},
		{
			name: "valid",
			in:   []byte(validPCRs),
			wantPCRs: enclave.PCR{
				0: []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
				1: []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
				2: []byte("cccccccccccccccccccccccccccccccccccccccccccccccc"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotPCRs, err := toPCR(c.in)
			require.Equal(t, c.wantErr, err != nil)
			require.True(t, gotPCRs.Equal(c.wantPCRs))
		})
	}
}
