package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/enclave/nitro"
	"github.com/Amnesic-Systems/veil/internal/enclave/noop"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/httputil"
	"github.com/Amnesic-Systems/veil/internal/nonce"
	"github.com/Amnesic-Systems/veil/internal/util"
)

type config struct {
	Verbose bool
	Addr    string
	Testing bool
	PCRs    enclave.PCR
}

func parseFlags(out io.Writer, args []string) (_ *config, err error) {
	defer errs.Wrap(&err, "failed to parse flags")

	fs := flag.NewFlagSet("veil-verify", flag.ContinueOnError)
	fs.SetOutput(out)

	addr := fs.String(
		"addr",
		"",
		"Address of the enclave, e.g.: https://example.com:8443",
	)
	measurements := fs.String(
		"measurements",
		"",
		"JSON-encoded enclave image measurements",
	)
	verbose := fs.Bool(
		"verbose",
		false,
		"Enable extra logging",
	)
	testing := fs.Bool(
		"insecure",
		false,
		"Enable testing by disabling attestation",
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// Ensure that required arguments are set.
	if *addr == "" {
		return nil, errors.New("flag -addr must be provided")
	}
	if *measurements == "" {
		return nil, errors.New("flag -measurements must be provided")
	}

	// Convert the given JSON enclave measurements to a PCR struct.
	pcr, err := toPCR([]byte(*measurements))
	if err != nil {
		return nil, err
	}

	return &config{
		Addr:    *addr,
		Testing: *testing,
		Verbose: *verbose,
		PCRs:    pcr,
	}, nil
}

func toPCR(jsonMsmts []byte) (_ enclave.PCR, err error) {
	defer errs.Wrap(&err, "failed to convert measurements to PCR")

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
		0: util.Must(hex.DecodeString(m.Measurements.PCR0)),
		1: util.Must(hex.DecodeString(m.Measurements.PCR1)),
		2: util.Must(hex.DecodeString(m.Measurements.PCR2)),
	}, nil
}

func run(ctx context.Context, out *os.File, args []string) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	cfg, err := parseFlags(out, args)
	if err != nil {
		return err
	}
	if cfg.Addr == "" {
		return fmt.Errorf("missing addr argument")
	}

	return attestEnclave(ctx, cfg)
}

func attestEnclave(ctx context.Context, cfg *config) (err error) {
	defer errs.Wrap(&err, "failed to attest enclave")

	nonce, err := nonce.New()
	if err != nil {
		return err
	}

	// Request the enclave's attestation document.  We don't care about HTTPS
	// certificates because authentication is happening via the attestation
	// document.
	client := httputil.NewNoAuthHTTPClient()
	url := cfg.Addr + "/enclave/attestation?nonce=" + nonce.URLEncode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("got status %d from enclave", resp.StatusCode)
	}

	// Parse the attestation document.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
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
	for key, value := range doc.PCRs {
		if bytes.Equal(value, empty) {
			delete(doc.PCRs, key)
		}
	}

	// Verify the attestation document's PCR values, which provide assurance
	// that the remote enclave's image and kernel match the local copy.
	if !cfg.PCRs.Equal(doc.PCRs) {
		log.Println("Enclave's code DOES NOT match local code!")
		if cfg.Verbose {
			log.Printf("Expected\n%sbut got\n%s", cfg.PCRs, doc.PCRs)
		}
	} else {
		log.Println("Enclave's code matches local code!")
	}

	return nil
}

func main() {
	ctx := context.Background()
	if err := run(ctx, os.Stdout, os.Args[1:]); err != nil {
		log.Fatalf("Failed to run verifier: %v", err)
	}
}
