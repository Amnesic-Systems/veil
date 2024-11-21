package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/util"
)

func TestWaitForSvc(t *testing.T) {
	ctx := context.Background()
	deadline := 500 * time.Millisecond

	cases := []struct {
		name         string
		unresponsive bool
		wantErr      error
	}{
		{
			name:         "unresponsive web server",
			unresponsive: true,
			wantErr:      errDeadlineExceeded,
		},
		{
			name: "responsive web server",
		},
	}

	newWebSrv := func(unresponsive bool) *httptest.Server {
		return httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if unresponsive {
					<-r.Context().Done()
				}
				w.WriteHeader(http.StatusOK)
			}),
		)
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			websrv := newWebSrv(c.unresponsive)
			defer websrv.Close()

			ctx, cancelFunc := context.WithDeadline(ctx, time.Now().Add(deadline))
			defer cancelFunc()
			require.ErrorIs(t, WaitForSvc(ctx, websrv.Client(), websrv.URL), c.wantErr)
		})
	}
}

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
