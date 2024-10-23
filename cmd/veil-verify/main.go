package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/httputil"
	"github.com/Amnesic-Systems/veil/internal/nonce"
)

type config struct {
	Addr    string
	Testing bool
}

func parseFlags(out io.Writer, args []string) (*config, error) {
	fs := flag.NewFlagSet("veil-verify", flag.ContinueOnError)
	fs.SetOutput(out)

	addr := fs.String(
		"addr",
		"",
		"Address of the enclave, e.g.: https://example.com:8443",
	)
	testing := fs.Bool(
		"insecure",
		false,
		"Enable testing by disabling attestation",
	)

	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %w", err)
	}

	return &config{
		Addr:    *addr,
		Testing: *testing,
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
	var doc enclave.AttestationDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}

	// Finally, verify the attestation document.
	var attester enclave.Attester = enclave.NewNitroAttester()
	if cfg.Testing {
		attester = enclave.NewNoopAttester()
	}
	_, err = attester.Verify(&doc, nonce)
	return err
}

func main() {
	ctx := context.Background()
	if err := run(ctx, os.Stdout, os.Args[1:]); err != nil {
		log.Fatalf("Failed to run verifier: %v", err)
	}
	log.Println("Attestation successful")
}
