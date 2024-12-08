package handle

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/enclave/nitro"
	"github.com/Amnesic-Systems/veil/internal/enclave/noop"
	"github.com/Amnesic-Systems/veil/internal/httperr"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/Amnesic-Systems/veil/internal/util"
)

func TestEncodeAndAttest(t *testing.T) {
	attester := nitro.NewAttester()
	if !nitro.IsEnclave() {
		attester = noop.NewAttester()
	}

	cases := []struct {
		name       string
		nonce      *nonce.Nonce
		body       any
		wantStatus int
		wantBody   string
	}{
		{
			name: "bad body",
			// Trigger an error by passing a channel, which is not supported by
			// json.Marshal.
			body:       make(chan int),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "missing nonce",
			wantStatus: http.StatusInternalServerError,
			body:       httperr.New("random error"),
		},
		{
			name:       "everything valid",
			nonce:      util.Must(nonce.New()),
			wantStatus: http.StatusOK,
			body:       httperr.New("random error"),
			wantBody:   `{"error":"random error"}` + "\n",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			builder := attestation.NewBuilder(attester, attestation.WithNonce(c.nonce))
			encodeAndAttest(rec, http.StatusOK, builder, c.body)

			resp := rec.Result()
			require.Equal(t, c.wantStatus, resp.StatusCode, httperr.FromBody(resp))

			if c.wantBody != "" {
				require.Equal(t, c.wantBody, rec.Body.String())
			}

			if resp.StatusCode != http.StatusOK {
				return
			}

			// Extract the attestation document from the response header.
			var rawDoc enclave.RawDocument
			err := json.Unmarshal([]byte(resp.Header.Get(attestationHeader)), &rawDoc)
			require.NoError(t, err)

			// The call to Verify is going to fail if we're inside a Nitro
			// Enclave because the attestation document was produced in debug
			// mode, which we need to see the test output.
			if attester.Type() == enclave.TypeNitro {
				return
			}
			doc, err := attester.Verify(&rawDoc, c.nonce)
			require.NoError(t, err)

			// Ensure that the nonce is correct.
			n, err := nonce.FromSlice(doc.AuxInfo.Nonce)
			require.NoError(t, err)
			require.Equal(t, c.nonce, n)
		})
	}
}
