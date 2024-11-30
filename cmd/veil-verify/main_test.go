package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
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
			name:    "missing dir",
			args:    []string{"-addr", srv.URL},
			wantErr: errFailedToParse,
		},
		{
			name:    "missing dockerfile",
			args:    []string{"-addr", srv.URL, "-dir", "/foo"},
			wantErr: errFailedToParse,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := run(context.Background(), io.Discard, c.args)
			require.ErrorIs(t, err, c.wantErr)
		})
	}
}
