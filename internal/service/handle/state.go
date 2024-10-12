package handle

import (
	"io"
	"log"
	"net/http"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/httperr"
	"github.com/Amnesic-Systems/veil/internal/util"
)

const ( // TODO: remove this
	// The states the enclave can be in relating to key synchronization.
	noSync     = iota // The enclave is not configured to synchronize keys.
	inProgress        // Leader designation is in progress.
	isLeader          // The enclave is the leader.
	isWorker          // The enclave is a worker.
)

const (
	msgInProgress       = "leader designation is in progress"
	msgEndpointGone     = "endpoint not meant to be used"
	msgSyncDisabled     = "key synchronization is disabled"
	msgUnknownSyncState = "unknown sync state"
)

type State struct {
	keys *enclave.Keys
}

// NewState returns a new handler for the enclave's GET and PUT state endpoints.
func NewState(keys *enclave.Keys) http.Handler {
	return &State{
		keys: keys,
	}
}

func (s *State) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	get := getState(func() int { return 3 }, s.keys)
	put := putState(func() int { return 0 }, s.keys)
	switch r.Method {
	case http.MethodGet:
		get(w, r)
	case http.MethodPut:
		put(w, r)
	}
}

// getState lets the enclave application retrieve previously-set state.  This is
// an enclave-internal endpoint that can only be accessed by the trusted enclave
// application.
func getState(
	getSyncState func() int,
	keys *enclave.Keys,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := getSyncState()
		switch s {
		case noSync:
			encode(w, http.StatusForbidden, httperr.New(msgSyncDisabled))
		case isLeader:
			encode(w, http.StatusGone, httperr.New(msgEndpointGone))
		case inProgress:
			encode(w, http.StatusServiceUnavailable, httperr.New(msgInProgress))
		case isWorker:
			if errs := keys.Validate(r.Context()); len(errs) > 0 {
				encode(w, http.StatusInternalServerError, httperr.New(util.SprintErrs(errs)))
				log.Panicf("Enclave has invalid keys: %v", errs)
			} else {
				encode(w, http.StatusOK, keys)
			}
		default:
			encode(w, http.StatusInternalServerError, httperr.New(msgUnknownSyncState))
			log.Panicf("Enclave is in unknown sync state: %d", s)
		}
	}
}

// putState returns a handler that lets the enclave application set
// state that's synchronized with another enclave in case of horizontal
// scaling.  The state can be arbitrary bytes.
//
// This is an enclave-internal endpoint that can only be accessed by the
// trusted enclave application.
func putState(
	getSyncState func() int,
	enclaveKeys *enclave.Keys,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch getSyncState() {
		case noSync:
			encode(w, http.StatusForbidden, httperr.New(msgSyncDisabled))
			//http.Error(w, errKeySyncDisabled.Error(), http.StatusForbidden)
		case isWorker:
			http.Error(w, errEndpointGone.Error(), http.StatusGone)
		case inProgress:
			http.Error(w, errDesignationInProgress.Error(), http.StatusServiceUnavailable)
		case isLeader:
			keys, err := io.ReadAll(io.LimitReader(r.Body, maxKeyMaterialLen))
			//keys, err := io.LimitReader(r.Body, maxKeyMaterialLen)
			if err != nil {
				http.Error(w, errFailedReqBody.Error(), http.StatusInternalServerError)
				return
			}
			enclaveKeys.SetAppKeys(keys)
			w.WriteHeader(http.StatusOK)

			// The leader's application keys have changed.  Re-synchronize the key
			// material with all registered workers.  If synchronization fails for a
			// given worker, unregister it.
			//log.Printf("Application keys have changed.  Re-synchronizing with %d worker(s).",
			//	workers.length())
			// go workers.forAll(
			// 	func(worker *url.URL) {
			// 		if err := asLeader(enclaveKeys, a).syncWith(worker); err != nil {
			// 			workers.unregister(worker)
			// 		}
			// 	},
			// )
		}
	}
}
