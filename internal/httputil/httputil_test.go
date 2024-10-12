package httputil

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/util"
)

func TestExtractNonce(t *testing.T) {
	cases := []struct {
		name      string
		req       *http.Request
		wantNonce *nonce.Nonce
		wantErr   error
	}{
		{
			name: "invalid form",
			req: &http.Request{
				// Semicolons aren't allowed in the query.
				URL: util.Must(url.Parse("https://example.com/endpoint?;")),
			},
			wantErr: errBadForm,
		},
		{
			name: "no nonce",
			req: &http.Request{
				URL: util.Must(url.Parse("https://example.com/endpoint?foo=bar")),
			},
			wantErr: errNoNonce,
		},
		{
			name: "bad nonce format",
			req: &http.Request{
				URL: util.Must(url.Parse("https://example.com/endpoint?nonce=%21")),
			},
			wantErr: errBadNonceFormat,
		},
		{
			name: "nonce too short",
			req: &http.Request{
				URL: util.Must(url.Parse("https://example.com/endpoint?nonce=AAAAAAAAAAAAAA%3D%3D")),
			},
			wantErr: errs.InvalidLength,
		},
		{
			name: "valid nonce",
			req: &http.Request{
				URL: util.Must(url.Parse("https://example.com/endpoint?nonce=AAAAAAAAAAAAAAAAAAAAAAAAAAA%3D")),
			},
			wantNonce: &nonce.Nonce{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNonce, gotErr := ExtractNonce(c.req)
			require.ErrorIs(t, gotErr, c.wantErr)
			require.Equal(t, c.wantNonce, gotNonce)
		})
	}
}
