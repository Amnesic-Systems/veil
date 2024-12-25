package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/fatih/color"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/enclave/nitro"
	"github.com/Amnesic-Systems/veil/internal/enclave/noop"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/httpx"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/service"
	"github.com/Amnesic-Systems/veil/internal/util/must"
)

var (
	errFailedToAttest  = errors.New("failed to attest enclave")
	errFailedToConvert = errors.New("failed to convert measurements to PCR")
)

func attestEnclave(
	ctx context.Context,
	cfg *config.VeilVerify,
	pcrs enclave.PCR,
) (err error) {
	defer errs.WrapErr(&err, errFailedToAttest)

	// Generate a nonce to ensure that the attestation document is fresh.
	nonce, err := nonce.New()
	if err != nil {
		return err
	}

	req, err := buildReq(ctx, cfg.Addr, nonce)
	if err != nil {
		return err
	}
	// Request the enclave's attestation document.  We don't verify HTTPS
	// certificates because authentication is happening via the attestation
	// document.
	client := httpx.NewUnauthClient()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	// Read the response body first, so we can log it in case of an error.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enclave returned %q with body: %s", resp.Status, string(body))
	}

	// Parse the attestation document.
	var rawDoc enclave.RawDocument
	if err := json.Unmarshal(body, &rawDoc); err != nil {
		return err
	}

	// Verify the attestation document, which provides assurance that we are
	// talking to an enclave.  The nonce provides assurance that we are talking
	// to an alive enclave (instead of a replayed attestation document).
	var attester enclave.Attester = nitro.NewAttester()
	if cfg.Testing {
		attester = noop.NewAttester()
	}
	doc, err := attester.Verify(&rawDoc, nonce)
	if err != nil {
		return err
	}

	// Delete empty PCR values from the attestation document.  This is not
	// ideal; we should either have the rest of the code tolerate empty PCR
	// values or fix the nsm package, so it doesn't return empty PCR values.
	empty := make([]byte, sha512.Size384)
	for i, pcr := range doc.PCRs {
		if bytes.Equal(pcr, empty) {
			delete(doc.PCRs, i)
		}
	}

	// Verify the attestation document's PCR values, which provide assurance
	// that the remote enclave's image and kernel match the local copy.
	if !pcrs.Equal(doc.PCRs) {
		log.Printf("Expected PCRs:\n%sbut got PCRs:\n%s", pcrs, doc.PCRs)
		color.Red("Enclave's code DOES NOT match local code!")
	} else {
		color.Green("Enclave's code matches local code!")
	}

	return nil
}

func buildReq(
	ctx context.Context,
	addr string,
	nonce *nonce.Nonce,
) (_ *http.Request, err error) {
	defer errs.Wrap(&err, "failed to build request")

	// Compile the request URL.  The given address should be of the form:
	// https://example.com
	u, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	u.Path = service.PathAttestation
	query := u.Query()
	query.Set(httpx.ParamNonce, nonce.B64())
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func toPCR(jsonMsmts []byte) (_ enclave.PCR, err error) {
	defer errs.WrapErr(&err, errFailedToConvert)

	// This structs represents the JSON-encoded measurements of the enclave
	// image.  The JSON tags must match the output of the nitro-cli command
	// line tool. An example:
	//
	//	{
	//	  "Measurements": {
	//	    "HashAlgorithm": "Sha384 { ... }",
	//	    "PCR0": "8b927cf0bbf2d668a8c24c69afd23bff2dda713b4f0d70195205950f9a5a1fbb7089ad937e3025ee8d5a084f3d6c9126",
	//	    "PCR1": "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
	//	    "PCR2": "22d2194eb27a7cda42e66dd5b91ef13e5a153d797c04ae179e59bef1c93438d6ad0365c175c119230e36d0f8d6b6b59e"
	//	  }
	//	}
	m := struct {
		Measurements struct {
			HashAlgorithm string `json:"HashAlgorithm"`
			PCR0          string `json:"PCR0"`
			PCR1          string `json:"PCR1"`
			PCR2          string `json:"PCR2"`
		} `json:"Measurements"`
	}{}
	if err := json.Unmarshal(jsonMsmts, &m); err != nil {
		return nil, err
	}

	const want = "sha384"
	got := strings.ToLower(m.Measurements.HashAlgorithm)
	if !strings.HasPrefix(got, want) {
		return nil, fmt.Errorf("expected hash algorithm %q but got %q", want, got)
	}

	return enclave.PCR{
		0: must.Get(hex.DecodeString(m.Measurements.PCR0)),
		1: must.Get(hex.DecodeString(m.Measurements.PCR1)),
		2: must.Get(hex.DecodeString(m.Measurements.PCR2)),
	}, nil
}
