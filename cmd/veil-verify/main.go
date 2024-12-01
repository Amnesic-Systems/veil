package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path"

	"github.com/docker/docker/client"

	"github.com/Amnesic-Systems/veil/internal/errs"
)

var errFailedToParse = errors.New("failed to parse flags")

type config struct {
	addr       string
	dir        string
	dockerfile string
	verbose    bool
	testing    bool
}

func parseFlags(out io.Writer, args []string) (_ *config, err error) {
	defer errs.WrapErr(&err, errFailedToParse)

	fs := flag.NewFlagSet("veil-verify", flag.ContinueOnError)
	fs.SetOutput(out)

	addr := fs.String(
		"addr",
		"",
		"Address of the enclave, e.g.: https://example.com:8443",
	)
	dir := fs.String(
		"dir",
		"",
		"Directory containing the enclave application's source code",
	)
	dockerfile := fs.String(
		"dockerfile",
		"Dockerfile",
		"Path to the Dockerfile used to build the enclave image, relative to 'dir'",
	)
	verbose := fs.Bool(
		"verbose",
		false,
		"Enable verbose logging",
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
	if *dir == "" {
		return nil, errors.New("flag -dir must be provided")
	}

	// Make sure that the Dockerfile relative to the given directory exists.
	p := path.Join(*dir, *dockerfile)
	if _, err := os.Stat(p); err != nil {
		return nil, fmt.Errorf("given Dockerfile %q does not exist", p)
	}

	return &config{
		addr:       *addr,
		dir:        *dir,
		dockerfile: *dockerfile,
		testing:    *testing,
		verbose:    *verbose,
	}, nil
}

func run(ctx context.Context, out io.Writer, args []string) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	cfg, err := parseFlags(out, args)
	if err != nil {
		return err
	}

	// By default, we discard Docker's logs but we print them in verbose mode.
	writer := io.Discard
	if cfg.verbose {
		writer = log.Writer()
	}

	// Create a new Docker client to interact with the Docker daemon.
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		// The Docker API errors are poor, so we wrap them in an attempt to
		// provide useful context.
		return errs.Add(err, "failed to create Docker client")
	}
	defer cli.Close()
	log.Print("Created Docker client.")

	// Create a deterministically-built enclave image.  The image is written to
	// disk as a tar archive.
	if err := buildEnclaveImage(ctx, cli, cfg, writer); err != nil {
		return err
	}
	// Load the tar archive into Docker as an image.
	if err := loadEnclaveImage(ctx, cli, cfg, writer); err != nil {
		return err
	}
	// Create a container that compiles the previously created enclave image
	// into AWS's EIF format, which is what we need for remote attestation.
	if err := buildCompilerImage(ctx, cli, writer); err != nil {
		return err
	}
	// Compile the enclave image as discussed above.
	pcrs, err := compileEnclaveImage(ctx, cli)
	if err != nil {
		return err
	}

	// Fetch the attestation document from the enclave and compare its PCR
	// values to the ones we just computed.
	return attestEnclave(ctx, cfg, pcrs)
}

func main() {
	if err := run(context.Background(), os.Stdout, os.Args[1:]); err != nil {
		log.Fatalf("Failed to verify enclave: %v", err)
	}
}
