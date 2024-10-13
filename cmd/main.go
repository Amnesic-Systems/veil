package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/service"
	"github.com/Amnesic-Systems/veil/internal/tunnel"
	"github.com/Amnesic-Systems/veil/internal/util"
)

const (
	defaultExtPubPort = "8080"
	defaultIntPort    = "8081"
)

func parseFlags(out io.Writer, args []string) (*config.Config, error) {
	fs := flag.NewFlagSet("veil", flag.ContinueOnError)
	fs.SetOutput(out)

	debug := fs.Bool(
		"debug",
		false,
		"enable debug logging",
	)
	extPubPort := fs.String(
		"ext-pub-port",
		defaultExtPubPort,
		"external public port",
	)
	intPort := fs.String(
		"int-port",
		defaultIntPort,
		"internal port",
	)
	appWebSrv := fs.String(
		"app-web-srv",
		"localhost:8082",
		"application web server",
	)
	waitForApp := fs.Bool(
		"wait-for-app",
		false,
		"wait for the application to signal readiness",
	)
	enableTesting := fs.Bool(
		"insecure",
		false,
		"enable testing by disabling attestation",
	)

	if err := fs.Parse(args); err != nil {
		fs.PrintDefaults()
		return nil, fmt.Errorf("failed to parse flags: %w", err)
	}

	// Build and validate the config.
	return &config.Config{
		Debug:      *debug,
		ExtPubPort: *extPubPort,
		IntPort:    *intPort,
		Testing:    *enableTesting,
		WaitForApp: *waitForApp,
		AppWebSrv:  util.Must(url.Parse(*appWebSrv)),
	}, nil
}

func run(ctx context.Context, out io.Writer, args []string) (err error) {
	defer errs.Wrap(&err, "failed to run service")

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	// Set up logging.
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.LUTC)
	log.SetOutput(out)

	// Parse command line flags.
	cfg, err := parseFlags(out, args)
	if err != nil {
		return err
	}

	// Validate the configuration.
	if problems := cfg.Validate(ctx); len(problems) > 0 {
		err := errors.New("invalid configuration")
		for field, problem := range problems {
			err = errors.Join(err, fmt.Errorf("field %q: %v", field, problem))
		}
		return err
	}

	// Initialize dependencies and start the service.
	attester := enclave.NewNitroAttester()
	if cfg.Testing {
		attester = enclave.NewNoopAttester()
	}
	service.Run(ctx, cfg, attester, tunnel.NewNoop())
	return nil
}

func main() {
	ctx := context.Background()
	if err := run(ctx, os.Stdout, os.Args[1:]); err != nil {
		log.Fatalf("Failed to run veil: %v", err)
	}
}
