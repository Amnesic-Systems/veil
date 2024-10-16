package handle

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/httperr"
)

func TestEncodeAndAttest(t *testing.T) {
	cases := []struct {
		name       string
		nonce      string
		status     int
		attester   enclave.Attester
		body       interface{}
		wantBody   string
		wantStatus int
	}{
		{
			name:       "bad nonce",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:  "bad body",
			nonce: "hJkjpaP/6cVT+vikk06HcN0aOdU=",
			// Trigger an error by passing a channel, which is not supported by
			// json.Marshal.
			body:       make(chan int),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "valid encoding",
			nonce:      "hJkjpaP/6cVT+vikk06HcN0aOdU=",
			status:     http.StatusOK,
			attester:   enclave.NewNoopAttester(),
			body:       httperr.New("random error"),
			wantBody:   `{"error":"random error"}`,
			wantStatus: http.StatusOK,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				http.MethodGet,
				fmt.Sprintf("/foo?nonce=%s", url.QueryEscape(c.nonce)),
				nil,
			)
			encodeAndAttest(rec, req, c.status, c.attester, c.body)

			resp := rec.Result()
			require.Equal(t, c.wantStatus, resp.StatusCode, httperr.FromBody(resp))
		})
	}
}
