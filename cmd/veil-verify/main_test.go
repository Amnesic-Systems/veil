package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Amnesic-Systems/veil/internal/enclave"
)

// validPCRs represents a well-formatted sample output from running:
//
//	nitro-cli build-enclave ...
const validPCRs = `{
	"Measurements": {
		"HashAlgorithm": "Sha384 { ... }",
		"PCR0": "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161",
		"PCR1": "626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262",
		"PCR2": "636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363"
	}
}`

func TestRun(t *testing.T) {
	// Set up a test server that returns a dummy attestation.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
			"type": "noop",
			"attestation_document": "e30K"
		}`) // e30K is Base64 for {}
	}))
	defer srv.Close()

	cases := []struct {
		name    string
		args    []string
		wantErr error
	}{
		{
			name:    "missing addr",
			wantErr: errFailedToParse,
		},
		{
			name:    "missing PCRs",
			args:    []string{"-addr", srv.URL},
			wantErr: errFailedToParse,
		},
		{
			name:    "invalid PCRs",
			args:    []string{"-addr", srv.URL, "-pcrs", "invalid"},
			wantErr: errFailedToConvert,
		},
		{
			name:    "attestation error",
			args:    []string{"-addr", srv.URL, "-pcrs", validPCRs},
			wantErr: errFailedToAttest,
		},
		{
			name: "no attestation error",
			// By passing -insecure, we end up with no error because the noop
			// attester is used.
			args: []string{"-insecure", "-addr", srv.URL, "-pcrs", validPCRs},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := run(context.Background(), io.Discard, c.args)
			require.ErrorIs(t, err, c.wantErr)
		})
	}
}

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
