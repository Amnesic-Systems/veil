package main

import (
	"bufio"
	"context"
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
	"github.com/Amnesic-Systems/veil/internal/httpx"
	"github.com/Amnesic-Systems/veil/internal/service"
	"github.com/Amnesic-Systems/veil/internal/tunnel"
	"github.com/Amnesic-Systems/veil/internal/types/validate"
)

const (
	defaultExtPort = 8443
	defaultIntPort = 8080
)

func parseFlags(out io.Writer, args []string) (*config.Veil, error) {
	fs := flag.NewFlagSet("veil", flag.ContinueOnError)
	fs.SetOutput(out)

	appCmd := fs.String(
		"app-cmd",
		"",
		"command to run to invoke application",
	)
	appWebSrv := fs.String(
		"app-web-srv",
		"",
		"application web server, e.g. http://localhost:8081",
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
		"ext-port",
		defaultExtPort,
		"external port",
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
	silenceApp := fs.Bool(
		"silence-app",
		false,
		"discard the application's stdout and stderr if -app-cmd is used",
	)
	testing := fs.Bool(
		"insecure",
		false,
		"enable testing by disabling attestation",
	)
	vsockPort := fs.Uint(
		"vsock-port",
		tunnel.DefaultVSOCKPort,
		"VSOCK port that veil-proxy is listening on",
	)
	waitForApp := fs.Bool(
		"wait-for-app",
		false,
		"wait for the application to signal readiness",
	)

	var err error
	if err = fs.Parse(args); err != nil {
		return nil, fmt.Errorf("failed to parse flags: %w", err)
	}

	var u *url.URL
	if *appWebSrv != "" {
		u, err = url.Parse(*appWebSrv)
		if err != nil {
			return nil, fmt.Errorf("failed to parse -app-web-srv: %w", err)
		}
	}

	// Build and validate the configuration.
	cfg := &config.Veil{
		AppCmd:         *appCmd,
		AppWebSrv:      u,
		Debug:          *debug,
		EnclaveCodeURI: *enclaveCodeURI,
		ExtPort:        *extPort,
		FQDN:           *fqdn,
		IntPort:        *intPort,
		Resolver:       *resolver,
		SilenceApp:     *silenceApp,
		Testing:        *testing,
		VSOCKPort:      uint32(*vsockPort),
		WaitForApp:     *waitForApp,
	}
	return cfg, validate.Object(cfg)
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

	// Run the application command, if specified.
	if cfg.AppCmd != "" {
		go func() {
			if err := eventuallyRunAppCmd(ctx, cfg, cfg.AppCmd); err != nil {
				log.Printf("App unavailable: %v", err)
			}
			// Shut down the service if the app command has terminated,
			// successfully or not.
			cancel()
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

func eventuallyRunAppCmd(ctx context.Context, cfg *config.Veil, cmd string) (err error) {
	defer errs.Wrap(&err, "failed to run app command")

	// Wait for the internal service to be ready.
	deadlineCtx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Second))
	defer cancel()
	url := fmt.Sprintf("http://localhost:%d", cfg.IntPort)
	if err := httpx.WaitForSvc(deadlineCtx, httpx.NewUnauthClient(), url); err != nil {
		return err
	}
	log.Print("Internal service ready; running app command.")

	return runAppCmd(ctx, cmd, cfg.SilenceApp)
}

func runAppCmd(ctx context.Context, cmdStr string, silence bool) error {
	args := strings.Split(cmdStr, " ")
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)

	// Discard the enclave application's stdout and stderr.  Regardless, we have
	// to consume its output to prevent the application from blocking.
	appStderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	appStdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var out io.Writer = os.Stdout
	if silence {
		out = io.Discard
	}
	go forward(appStderr, out)
	go forward(appStdout, out)

	// Start the application and wait for it to terminate.
	log.Println("Starting application.")
	if err := cmd.Start(); err != nil {
		return err
	}
	log.Println("Waiting for application to terminate.")
	defer log.Println("Application terminated.")
	return cmd.Wait()
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
