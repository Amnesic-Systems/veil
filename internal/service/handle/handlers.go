package handle

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/httperr"
	"github.com/Amnesic-Systems/veil/internal/httputil"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/Amnesic-Systems/veil/internal/util"
)

const (
	// The maximum length of the key material (in bytes) that enclave
	// applications can PUT to our HTTP API.
	maxKeyMaterialLen = 1024 * 1024
)

var (
	errFailedReqBody         = errors.New("failed to read request body")
	errDesignationInProgress = errors.New("leader designation in progress")
	errEndpointGone          = errors.New("endpoint not meant to be used")
)

// Index informs the visitor that this host runs inside an enclave. This is
// useful for testing.
func Index(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page := "This host runs inside an AWS Nitro Enclave."
		if cfg.SourceCodeURI != "" {
			page += fmt.Sprintf("\nThe application's source code is available at: %s.",
				cfg.SourceCodeURI)
		}
		fmt.Fprintln(w, page)
	}
}

// Config returns the enclave's configuration.
func Config(attester enclave.Attester, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encodeAndAttest(w, r, http.StatusOK, attester, cfg)
	}
}

// hashHandler returns an HTTP handler that allows the enclave application to
// register a hash over a public key which is going to be included in
// attestation documents.  This allows clients to tie the attestation document
// (which acts as the root of trust) to key material that's used by the enclave
// application.
//
// This is an enclave-internal endpoint that can only be accessed by the
// trusted enclave application.
// func hashHandler(e *Enclave) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// Allow an extra byte for the \n.
// 		maxReadLen := base64.StdEncoding.EncodedLen(sha256.Size) + 1
// 		body, err := io.ReadAll(newLimitReader(r.Body, maxReadLen))
// 		if errors.Is(err, errTooMuchToRead) {
// 			http.Error(w, errTooMuchToRead.Error(), http.StatusBadRequest)
// 			return
// 		}
// 		if err != nil {
// 			http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
// 		}

// 		keyHash, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
// 		if err != nil {
// 			http.Error(w, errNoBase64.Error(), http.StatusBadRequest)
// 			return
// 		}

// 		if len(keyHash) != sha256.Size {
// 			http.Error(w, errHashWrongSize.Error(), http.StatusBadRequest)
// 			return
// 		}
// 		copy(e.hashes.appKeyHash[:], keyHash)
// 	}
// }

func Hashes(hashes *attestation.Hashes) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hashes.Lock()
		defer hashes.Unlock()
		encode(w, http.StatusOK, hashes)
	}
}

func AppHash(
	setAppHash func(*[sha256.Size]byte),
) http.HandlerFunc {
	b := util.Must(json.Marshal(new(attestation.Hashes)))
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
		setAppHash(util.AddrOf(theirHashes.AppKeyHash))
	}
}

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

func Attestation(
	attester enclave.Attester,
	makeAuxInfo attestation.AuxFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n, err := httputil.ExtractNonce(r)
		if err != nil {
			encode(w, http.StatusBadRequest, httperr.New(err.Error()))
			return
		}

		attestation, err := attester.Attest(makeAuxInfo(n))
		if err != nil {
			encode(w, http.StatusInternalServerError, httperr.New(err.Error()))
			return
		}
		encode(w, http.StatusOK, attestation)
	}
}

// func heartbeatHandler(e *Enclave) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		var (
// 			hb heartbeatRequest
// 			// syncAndRegister = func(keys *enclaveKeys, worker *url.URL) {
// 			// 	if err := asLeader(keys, e.attester).syncWith(worker); err == nil {
// 			// 		e.workers.register(worker)
// 			// 	}
// 			// }
// 		)

// 		body, err := io.ReadAll(newLimitReader(r.Body, maxHeartbeatBody))
// 		if err != nil {
// 			http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
// 			return
// 		}
// 		if err := json.Unmarshal(body, &hb); err != nil {
// 			http.Error(w, err.Error(), http.StatusBadRequest)
// 			return
// 		}
// 		worker, err := e.getWorker(&hb)
// 		if err != nil {
// 			http.Error(w, err.Error(), http.StatusInternalServerError)
// 			return
// 		}

// 		elog.Printf("Heartbeat from worker %s.", worker.Host)
// 		ourKeysHash, theirKeysHash := e.keys.hashAndB64(), hb.HashedKeys
// 		if ourKeysHash != theirKeysHash {
// 			elog.Printf("Worker's keys are invalid.  Re-synchronizing.")
// 			//go syncAndRegister(e.keys, worker)
// 		} else {
// 			e.workers.register(worker)
// 		}
// 		w.WriteHeader(http.StatusOK)
// 	}
// }

// func getLeaderHandler(ourNonce nonce, weAreLeader chan struct{}) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		var (
// 			err        error
// 			theirNonce nonce
// 		)
// 		theirNonce, err = getNonceFromReq(r)
// 		if err != nil {
// 			http.Error(w, err.Error(), http.StatusBadRequest)
// 			return
// 		}

// 		if ourNonce == theirNonce {
// 			if len(weAreLeader) == 0 {
// 				weAreLeader <- struct{}{}
// 			}
// 		} else {
// 			// We may end up in this branch for two reasons:
// 			// 1. We're the leader and a worker beat us to talking to this
// 			//    endpoint.
// 			// 2. We're a worker and some other entity in the private network is
// 			//    talking to this endpoint.  That shouldn't happen.
// 			elog.Println("Received nonce that does not match our own.")
// 		}
// 		w.WriteHeader(http.StatusOK)
// 	}
// }
