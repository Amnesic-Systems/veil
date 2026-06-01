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
	"github.com/Amnesic-Systems/veil/internal/net/dns"
	"github.com/Amnesic-Systems/veil/internal/net/nat"
	"github.com/Amnesic-Systems/veil/internal/net/proxy"
	"github.com/Amnesic-Systems/veil/internal/net/tun"
	"github.com/Amnesic-Systems/veil/internal/tunnel"
	"github.com/Amnesic-Systems/veil/internal/types/validate"
	"github.com/mdlayher/vsock"
)

const hostResolvConf = "/etc/resolv.conf"

func parseFlags(out io.Writer, args []string) (_ *config.VeilProxy, err error) {
	defer errs.Wrap(&err, "failed to parse flags")

	fs := flag.NewFlagSet("veil-proxy", flag.ContinueOnError)
	fs.SetOutput(out)

	dnsForwarder := fs.Bool(
		"dns-forwarder",
		false,
		`Enable DNS forwarder on the tun interface. Have veil-daemon use this
resolver by passing "-dns-resolver 10.0.0.1". The resolver forwards queries
to the nameservers configured in /etc/resolv.conf.`,
	)
	profile := fs.Bool(
		"profile",
		false,
		"Enable profiling.",
	)
	vsockPort := fs.Uint(
		"vsock-port",
		tunnel.DefaultVSOCKPort,
		"First VSOCK port that veil connects to.",
	)
	vsockStreams := fs.Uint(
		"vsock-streams",
		tunnel.DefaultVsockDataStreams,
		"Number of data VSOCK streams in addition to the control stream (default 0)",
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// Build and validate the configuration.
	cfg := &config.VeilProxy{
		DNSForwarder: *dnsForwarder,
		Profile:      *profile,
		VSOCKPort:    uint32(*vsockPort),
		VsockStreams: uint(*vsockStreams),
	}
	return cfg, validate.Object(cfg)
}

func listenVSOCKPorts(base uint32, dataStreams uint) (_ []net.Listener, err error) {
	defer errs.Wrap(&err, "failed to create VSOCK listeners")

	cid, err := vsock.ContextID()
	if err != nil {
		return nil, err
	}

	streams := tunnel.StreamCount(dataStreams)
	listeners := make([]net.Listener, streams)
	for i := uint(0); i < streams; i++ {
		listeners[i], err = vsock.ListenContextID(cid, base+uint32(i), nil)
		if err != nil {
			for j := uint(0); j < i; j++ {
				_ = listeners[j].Close()
			}
			return nil, fmt.Errorf("listen stream %d: %w", i, err)
		}
	}
	return listeners, nil
}

func acceptVSOCKStreams(listeners []net.Listener) (_ []net.Conn, err error) {
	conns := make([]net.Conn, len(listeners))
	for i, ln := range listeners {
		conns[i], err = ln.Accept()
		if err != nil {
			for j := 0; j < i; j++ {
				_ = conns[j].Close()
			}
			return nil, fmt.Errorf("accept stream %d: %w", i, err)
		}
	}
	return conns, nil
}

func acceptLoop(ctx context.Context, listeners []net.Listener, cfg *config.VeilProxy) {
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
	// once all VSOCK streams are established.
	for {
		if err := func() error { // Use a function so we can use defer below.
			log.Printf(
				"Waiting for %d VSOCK stream(s) from enclave.",
				len(listeners),
			)
			conns, err := acceptVSOCKStreams(listeners)
			if err != nil {
				return err
			}
			defer func() {
				for _, conn := range conns {
					_ = conn.Close()
				}
			}()
			for i, conn := range conns {
				log.Printf("Accepted stream %d from %s.", i, conn.RemoteAddr())
			}

			tunDev, err := tun.SetupTunAsProxy()
			if err != nil {
				return fmt.Errorf("failed to create tun device: %w", err)
			}
			defer func() { _ = tunDev.Close() }()
			log.Print("Created tun device.")

			dnsFwd, err := startDNSForwarder(ctx, cfg)
			if err != nil {
				return fmt.Errorf("failed to start DNS forwarder: %w", err)
			}
			if dnsFwd != nil {
				defer func() { _ = dnsFwd.Close() }()
				log.Printf("Started DNS forwarder at %s.", dnsFwd.UDPAddr())
			}

			streams := make([]io.WriteCloser, len(conns))
			for i, conn := range conns {
				streams[i] = conn
			}

			stopCh := make(chan struct{})
			defer close(stopCh)
			// Close VSOCK streams and tunDev when the context is canceled to
			// unblock the forwarding goroutines before wg.Wait().
			go func() {
				select {
				case <-ctx.Done():
					for _, conn := range conns {
						_ = conn.Close()
					}
					_ = tunDev.Close()
				case <-stopCh:
				}
			}()

			var wg sync.WaitGroup
			// Spawn goroutines that forward traffic and wait for them to finish.
			wg.Add(1 + len(conns))
			go proxy.TunToVSOCKStreams(tunDev, streams, ch, &wg)
			for _, conn := range conns {
				go proxy.VSOCKToTun(conn, tunDev, ch, &wg)
			}
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

func startDNSForwarder(
	ctx context.Context,
	cfg *config.VeilProxy,
) (*dns.Forwarder, error) {
	if !cfg.DNSForwarder {
		return nil, nil
	}

	upstreams, err := dns.UpstreamsFromFile(hostResolvConf)
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS upstreams from %s: %w",
			hostResolvConf, err)
	}

	return dns.Start(ctx, dns.Config{
		ListenAddr: net.JoinHostPort(tun.ProxyIP, "53"),
		Upstreams:  upstreams,
	})
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

	// Create VSOCK listeners for the control stream and any data streams.
	listeners, err := listenVSOCKPorts(cfg.VSOCKPort, cfg.VsockStreams)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		for _, ln := range listeners {
			_ = ln.Close()
		}
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

	// Accept connections from the enclave and begin forwarding packets.
	acceptLoop(ctx, listeners, cfg)
	return nil
}

func main() {
	if err := run(context.Background(), os.Stdout, os.Args[1:]); err != nil {
		log.Fatalf("Failed to run proxy: %v", err)
	}
}
