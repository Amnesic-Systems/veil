package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/enclave/nitro"
	"github.com/Amnesic-Systems/veil/internal/enclave/noop"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/httputil"
	"github.com/Amnesic-Systems/veil/internal/service"
	"github.com/Amnesic-Systems/veil/internal/tunnel"
	"github.com/Amnesic-Systems/veil/internal/util"
)

const (
	defaultExtPort = 8443
	defaultIntPort = 8080
)

func parseFlags(out io.Writer, args []string) (*config.Config, error) {
	fs := flag.NewFlagSet("veil", flag.ContinueOnError)
	fs.SetOutput(out)

	appCmd := fs.String(
		"app-cmd",
		"",
		"command to run to invoke application",
	)
	appWebSrv := fs.String(
		"app-web-srv",
		"localhost:8081",
		"application web server",
	)
	debug := fs.Bool(
		"debug",
		false,
		"enable debug logging",
	)
	enclaveCodeURI := fs.String(
		"enclave-code-uri",
		"",
		"the enclave application's source code",
	)
	extPort := fs.Int(
		"ext-pub-port",
		defaultExtPort,
		"external public port",
	)
	fqdn := fs.String(
		"fqdn",
		"",
		"the enclave's fully qualified domain name",
	)
	intPort := fs.Int(
		"int-port",
		defaultIntPort,
		"internal port",
	)
	resolver := fs.String(
		"resolver",
		"1.1.1.1",
		"the DNS resolver used by veil",
	)
	testing := fs.Bool(
		"insecure",
		false,
		"enable testing by disabling attestation",
	)
	waitForApp := fs.Bool(
		"wait-for-app",
		false,
		"wait for the application to signal readiness",
	)

	if err := fs.Parse(args); err != nil {
		fs.PrintDefaults()
		return nil, fmt.Errorf("failed to parse flags: %w", err)
	}

	// Build and validate the config.
	return &config.Config{
		AppCmd:         *appCmd,
		AppWebSrv:      util.Must(url.Parse(*appWebSrv)),
		Debug:          *debug,
		EnclaveCodeURI: *enclaveCodeURI,
		ExtPort:        *extPort,
		FQDN:           *fqdn,
		IntPort:        *intPort,
		Resolver:       *resolver,
		Testing:        *testing,
		WaitForApp:     *waitForApp,
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

	// Run the application command, if specified.
	if cfg.AppCmd != "" {
		go func() {
			if err := eventuallyRunAppCmd(ctx, cfg, cfg.AppCmd); err != nil {
				log.Printf("App unavailable: %v", err)
				// Shut down the service if the app command fails.
				cancel()
			}
		}()
	}

	// Initialize dependencies and start the service.
	var attester enclave.Attester = nitro.NewAttester()
	var tunneler tunnel.Mechanism = tunnel.NewVSOCK()
	if cfg.Testing {
		attester = noop.NewAttester()
		tunneler = tunnel.NewNoop()
	}
	service.Run(ctx, cfg, attester, tunneler)
	return nil
}

func eventuallyRunAppCmd(ctx context.Context, cfg *config.Config, cmd string) (err error) {
	defer errs.Wrap(&err, "failed to run app command")

	// Wait for the internal service to be ready.
	deadlineCtx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Second))
	defer cancel()
	url := fmt.Sprintf("http://localhost:%d", cfg.IntPort)
	if err := httputil.WaitForSvc(deadlineCtx, httputil.NewNoAuthHTTPClient(), url); err != nil {
		return err
	}
	log.Print("Internal service ready; running app command.")

	return runAppCmd(ctx, cmd)
}

func runAppCmd(ctx context.Context, cmdStr string) error {
	args := strings.Split(cmdStr, " ")
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)

	// Print the enclave application's stdout and stderr.
	appStderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	appStdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	go forward(appStderr, io.Discard)
	go forward(appStdout, io.Discard)

	// Start the application and wait for it to terminate.
	log.Println("Starting application.")
	if err := cmd.Start(); err != nil {
		return err
	}
	log.Println("Waiting for application to terminate.")
	if err := cmd.Wait(); err != nil {
		return err
	}
	log.Println("Application terminated.")

	return nil
}

func forward(from io.Reader, to io.Writer) {
	s := bufio.NewScanner(from)
	for s.Scan() {
		fmt.Fprintln(to, s.Text())
	}
	if err := s.Err(); err != nil {
		log.Printf("Error reading application output: %v", err)
	}
}

func main() {
	if err := run(context.Background(), os.Stdout, os.Args[1:]); err != nil {
		log.Fatalf("Failed to run veil: %v", err)
	}
}
