package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/net/nat"
	"github.com/Amnesic-Systems/veil/internal/net/proxy"
	"github.com/Amnesic-Systems/veil/internal/net/tun"
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
		"Enable profiling.",
	)
	port := fs.Uint(
		"port",
		1024,
		"VSOCK port that the enclave connects to.",
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// Build and validate the configuration.
	cfg := &config.VeilProxy{
		Profile: *profile,
		Port:    uint32(*port),
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

func acceptLoop(ln net.Listener) {
	// Print errors that occur while forwarding packets.
	ch := make(chan error)
	defer close(ch)
	go func(ch chan error) {
		for err := range ch {
			log.Print(err)
		}
	}(ch)

	// Listen for connections from the enclave and begin forwarding packets
	// once a new connection is established. At any given point, we only expect
	// to have a single TCP-over-VSOCK connection with the enclave.
	for {
		tunDev, err := tun.SetupTunAsProxy()
		if err != nil {
			log.Printf("Error creating tun device: %v", err)
			continue
		}
		log.Print("Created tun device.")

		log.Println("Waiting for new connection from enclave.")
		vm, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		log.Printf("Accepted new connection from %s.", vm.RemoteAddr())

		var wg sync.WaitGroup
		wg.Add(2)
		go proxy.VsockToTun(vm, tunDev, ch, &wg)
		go proxy.TunToVsock(tunDev, vm, ch, &wg)
		wg.Wait()
	}
}

func run(ctx context.Context, out io.Writer, args []string) (origErr error) {
	_, cancel := signal.NotifyContext(ctx, os.Interrupt)
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
	ln, err := listenVSOCK(cfg.Port)
	if err != nil {
		return err
	}
	defer func() {
		errs.Join(&origErr, errs.Add(ln.Close(), "failed to close listener"))
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
	acceptLoop(ln)
	return nil
}

func main() {
	if err := run(context.Background(), os.Stdout, os.Args[1:]); err != nil {
		log.Fatalf("Failed to run proxy: %v", err)
	}
}
