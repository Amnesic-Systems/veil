package handle

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/enclave/noop"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/Amnesic-Systems/veil/internal/util/must"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndex(t *testing.T) {
	cases := []struct {
		name    string
		codeURI string
	}{
		{
			name: "without code URI",
		},
		{
			name:    "with code URI",
			codeURI: "https://example.com",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := Index(c.codeURI)
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

			assert.Equal(t, http.StatusOK, resp.Code)
			assert.Contains(t, resp.Body.String(), c.codeURI)
		})
	}
}
func TestConfig(t *testing.T) {
	cases := []struct {
		name      string
		withNonce bool
	}{
		{
			name: "without nonce",
		},
		{
			name:      "with nonce",
			withNonce: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := config.Veil{EnclaveCodeURI: "https://example.com"}
			builder := attestation.NewBuilder(noop.NewAttester())
			handler := Config(builder, &cfg)

			target := "/config"
			if c.withNonce {
				n := must.Get(nonce.New())
				target += "?nonce=" + n.B64()
			}
			req := httptest.NewRequest(http.MethodGet, target, http.NoBody)

			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)

			assert.Equal(t, http.StatusOK, resp.Code)

			var gotCfg config.Veil
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&gotCfg))
			assert.Equal(t, cfg, gotCfg)
		})
	}
}

func TestReady(t *testing.T) {
	cases := []struct {
		name       string
		callTwice  bool
		wantStatus int
	}{
		{
			name:       "first call",
			wantStatus: http.StatusOK,
		},
		{
			name:       "second call",
			callTwice:  true,
			wantStatus: http.StatusGone,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ready := make(chan struct{})
			handler := Ready(ready)
			req := httptest.NewRequest(http.MethodGet, "/ready", http.NoBody)
			resp := httptest.NewRecorder()

			if c.callTwice {
				// Ignore the first call because we only care about what the
				// second call returns.
				handler.ServeHTTP(httptest.NewRecorder(), req)
			}
			handler.ServeHTTP(resp, req)

			assert.Equal(t, c.wantStatus, resp.Code)

			// The ready channel should be closed after the first call.
			select {
			case <-ready:
				// Channel was closed as expected.
			default:
				t.Error("Ready channel was not closed.")
			}
		})
	}
}
