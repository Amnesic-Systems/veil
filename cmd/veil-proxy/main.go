package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"

	"github.com/Amnesic-Systems/veil/internal/backoff"
	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/net/nat"
	"github.com/Amnesic-Systems/veil/internal/net/proxy"
	"github.com/Amnesic-Systems/veil/internal/net/tun"
	"github.com/Amnesic-Systems/veil/internal/tunnel"
	"github.com/Amnesic-Systems/veil/internal/types/validate"
	"github.com/mdlayher/vsock"
)

func parseFlags(out io.Writer, args []string) (_ *config.VeilProxy, err error) {
	defer errs.Wrap(&err, "failed to parse flags")

	fs := flag.NewFlagSet("veil-proxy", flag.ContinueOnError)
	fs.SetOutput(out)

	profile := fs.Bool(
		"profile",
		false,
		"enable profiling",
	)
	vsockPort := fs.Uint(
		"vsock-port",
		tunnel.DefaultVSOCKPort,
		"VSOCK listening port that veil connects to",
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// Build and validate the configuration.
	cfg := &config.VeilProxy{
		Profile:   *profile,
		VSOCKPort: uint32(*vsockPort),
	}
	return cfg, validate.Object(cfg)
}

func listenVSOCK(port uint32) (_ net.Listener, err error) {
	defer errs.Wrap(&err, "failed to create VSOCK listener")

	cid, err := vsock.ContextID()
	if err != nil {
		return nil, err
	}
	return vsock.ListenContextID(cid, port, nil)
}

func acceptLoop(ctx context.Context, ln net.Listener) {
	// Print errors that occur while forwarding packets.
	ch := make(chan error)
	defer close(ch)
	go func(ch chan error) {
		for err := range ch {
			log.Print(err)
		}
	}(ch)

	timer := backoff.NewTimer()
	// Listen for connections from the enclave and begin forwarding packets
	// once a new connection is established. At any given point, we only expect
	// to have a single TCP-over-VSOCK connection with the enclave.
	for {
		if err := func() error { // Use a function so we can use defer below.
			log.Println("Waiting for new connection from enclave.")
			vm, err := ln.Accept()
			if err != nil {
				return fmt.Errorf("failed to accept connection: %w", err)
			}
			defer func() { _ = vm.Close() }()
			log.Printf("Accepted new connection from %s.", vm.RemoteAddr())

			tunDev, err := tun.SetupTunAsProxy()
			if err != nil {
				return fmt.Errorf("failed to create tun device: %w", err)
			}
			defer func() { _ = tunDev.Close() }()
			log.Print("Created tun device.")

			var wg sync.WaitGroup
			wg.Add(2)
			go proxy.VSOCKToTun(vm, tunDev, ch, &wg)
			go proxy.TunToVSOCK(tunDev, vm, ch, &wg)
			wg.Wait()

			return nil
		}(); err != nil {
			if ctx.Err() != nil {
				return // Main context is done; time to exit.
			}
			log.Printf("Failed to set up tunnel: %v", err)
			timer.Sleep(ctx)
		} else {
			timer.Reset()
		}
	}
}

func run(ctx context.Context, out io.Writer, args []string) (origErr error) {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	cfg, err := parseFlags(out, args)
	if err != nil {
		return err
	}

	// Enable NAT.
	if err := nat.Enable(); err != nil {
		return errs.Add(err, "failed to enable NAT")
	}
	log.Print("Enabled NAT.")
	defer func() {
		errs.Join(&origErr, errs.Add(nat.Disable(), "failed to disable NAT"))
		log.Print("Disabled NAT.")
	}()

	// Create a VSOCK listener that listens for incoming connections from the
	// enclave.
	ln, err := listenVSOCK(cfg.VSOCKPort)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	// If desired, set up a Web server for the profiler.
	if cfg.Profile {
		go func() {
			const hostPort = "localhost:6060"
			log.Printf("Starting profiling Web server at: http://%s", hostPort)
			err := http.ListenAndServe(hostPort, nil)
			if err != nil && err != http.ErrServerClosed {
				log.Printf("Error running profiling server: %v", err)
			}
		}()
	}

	// Accept new connections from the VSOCK listener and begin forwarding
	// packets.
	acceptLoop(ctx, ln)
	return nil
}

func main() {
	if err := run(context.Background(), os.Stdout, os.Args[1:]); err != nil {
		log.Fatalf("Failed to run proxy: %v", err)
	}
}
