package handle

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/Amnesic-Systems/veil/internal/httperr"
	"github.com/Amnesic-Systems/veil/internal/httpx"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
)

const attestationHeader = "X-Veil-Attestation"

func encode[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "failed to encode JSON", http.StatusInternalServerError)
		panic(fmt.Errorf("failed to encode json: %w", err))
	}
}

func encodeAndMaybeAttest[T any](
	w http.ResponseWriter,
	r *http.Request,
	status int,
	builder *attestation.Builder,
	v T,
) {
	// Depending on if the request contains a nonce, either return the JSON
	// response without attestation or include an attestation document in the
	// response.
	if _, err := httpx.ExtractNonce(r); err != nil {
		encode(w, status, v)
	} else {
		encodeAndAttest(w, r, status, builder, v)
	}
}

func encodeAndAttest[T any](
	w http.ResponseWriter,
	r *http.Request,
	status int,
	builder *attestation.Builder,
	v T,
) {
	// Try to extract the client's nonce from the request. If this fails, abort
	// attestation because the client no longer has a way to verify the
	// attestation document's freshness.
	n, err := httpx.ExtractNonce(r)
	if err != nil {
		log.Println(err)
		encode(w, http.StatusBadRequest, httperr.New("found no valid nonce in HTTP request"))
		return
	}

	body, err := json.Marshal(v)
	if err != nil {
		encode(w, http.StatusInternalServerError, httperr.New("failed to encode JSON"))
		return
	}

	// Hash the JSON body and request an attestation document containing the
	// hash and the client's nonce.
	hash := sha256.Sum256(body)
	attestation, err := builder.Attest(
		attestation.WithNonce(n),
		attestation.WithSHA256(hash),
	)
	if err != nil {
		encode(w, http.StatusInternalServerError, httperr.New("failed to attest HTTP request"))
		return
	}

	// Marshal the attestation document.
	b, err := json.Marshal(attestation)
	if err != nil {
		encode(w, http.StatusInternalServerError, httperr.New("failed to encode JSON"))
		return
	}

	// Add the Base64-encoded attestation document to the response header. This
	// header may exceed 8 KiB but still fits comfortably into the 1 MiB default
	// limit for HTTP headers. See http.Server's MaxHeaderBytes for more
	// details.
	w.Header().Set(attestationHeader, string(b))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintln(w, string(body))
}
