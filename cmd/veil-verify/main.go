package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/docker/docker/client"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/types/validate"
)

var errFailedToParse = errors.New("failed to parse flags")

func parseFlags(out io.Writer, args []string) (_ *config.VeilVerify, err error) {
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

	// Build and validate the configuration.
	cfg := &config.VeilVerify{
		Addr:       *addr,
		Dir:        *dir,
		Dockerfile: *dockerfile,
		Testing:    *testing,
		Verbose:    *verbose,
	}
	return cfg, validate.Object(cfg)
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
	if cfg.Verbose {
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
