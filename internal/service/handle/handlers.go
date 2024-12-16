package handle

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/Amnesic-Systems/veil/internal/addr"
	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/httperr"
	"github.com/Amnesic-Systems/veil/internal/httpx"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/Amnesic-Systems/veil/internal/util"
)

// Index informs the visitor that this host runs inside an enclave. This is
// useful for testing.
func Index(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page := "This host runs inside an AWS Nitro Enclave."
		if cfg.EnclaveCodeURI != "" {
			page += fmt.Sprintf("\nThe application's source code is available at: %s.",
				cfg.EnclaveCodeURI)
		}
		fmt.Fprintln(w, page)
	}
}

// Config returns the enclave's configuration.
func Config(
	builder *attestation.Builder,
	cfg *config.Config,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If the client provided a nonce, we will add an attestation document
		// to the response header.  Otherwise there's no need to be pedantic
		// because this isn't a security-sensitive endpoint, so we simply return
		// the configuration without attestation.
		if n, err := httpx.ExtractNonce(r); err == nil {
			builder.Update(attestation.WithNonce(n))
			encodeAndAttest(w, http.StatusOK, builder, cfg)
		} else {
			encode(w, http.StatusOK, cfg)
		}
	}
}

// Hashes returns the attestation hashes that we embed in the attestation
// document.
func Hashes(hashes *attestation.Hashes) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hashes.Lock()
		defer hashes.Unlock()
		encode(w, http.StatusOK, hashes)
	}
}

// AppHash sets the application hash in the attestation document.
func AppHash(
	setAppHash func(*[sha256.Size]byte),
) http.HandlerFunc {
	b := util.Must(json.Marshal(&attestation.Hashes{
		TlsKeyHash: addr.Of(sha256.Sum256([]byte("foo"))),
		AppKeyHash: addr.Of(sha256.Sum256([]byte("bar"))),
	}))
	maxHashesLen := len(b) + 1 // Allow extra byte for the \n.

	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxHashesLen)))
		if err != nil {
			encode(w, http.StatusInternalServerError, httperr.New(err.Error()))
			return
		}

		// Try to decode the hash from the request body.
		var theirHashes = new(attestation.Hashes)
		if err := json.Unmarshal(body, theirHashes); err != nil {
			encode(w, http.StatusBadRequest, httperr.New(err.Error()))
			return
		}
		setAppHash(theirHashes.AppKeyHash)
	}
}

// Ready closes the ready channel when the handler is invoked.
func Ready(ready chan struct{}) http.HandlerFunc {
	var (
		m       sync.Mutex
		invoked bool
	)

	return func(w http.ResponseWriter, r *http.Request) {
		m.Lock()
		defer m.Unlock()

		if !invoked {
			close(ready)
			invoked = true
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusGone)
		}
	}
}

// Attestation returns an attestation document.
func Attestation(
	builder *attestation.Builder,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n, err := httpx.ExtractNonce(r)
		if err != nil {
			encode(w, http.StatusBadRequest, httperr.New(err.Error()))
			return
		}

		attestation, err := builder.Attest(attestation.WithNonce(n))
		if err != nil {
			encode(w, http.StatusInternalServerError, httperr.New(err.Error()))
			return
		}
		encode(w, http.StatusOK, attestation)
	}
}
