package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"

	"github.com/Amnesic-Systems/veil/internal/addr"
	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/errs"
	"github.com/Amnesic-Systems/veil/internal/httpx"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/Amnesic-Systems/veil/internal/system"
	"github.com/Amnesic-Systems/veil/internal/tunnel"
	"github.com/Amnesic-Systems/veil/internal/util/must"
	"github.com/go-chi/chi/v5"
)

func Run(
	ctx context.Context,
	config *config.Config,
	attester enclave.Attester,
	mechanism tunnel.Mechanism,
) {
	var appReady = make(chan struct{})

	// Run safety checks and setup tasks before starting.
	if err := checkSystemSafety(config); err != nil {
		log.Fatalf("Failed safety check: %v", err)
	}
	if err := setupSystem(config); err != nil {
		log.Fatalf("Failed to set up system: %v", err)
	}

	// Create a TLS certificate for the external Web server.
	cert, key, err := httpx.CreateCertificate(config.FQDN)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Initialize hashes for the attestation document.
	hashes := new(attestation.Hashes)
	hashes.SetTLSHash(addr.Of(sha256.Sum256(cert)))

	// Initialize Web servers.
	intSrv := newIntSrv(config, hashes, appReady)
	builder := attestation.NewBuilder(
		attester,
		attestation.WithHashes(hashes),
	)
	extSrv := newExtSrv(config, builder)
	extSrv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{
			must.Get(tls.X509KeyPair(cert, key)),
		},
	}

	// Set up the networking tunnel. This function will block until the tunnel
	// is ready to use.
	tunnel.New(ctx, mechanism)

	// Start all Web servers and block until all Web servers have stopped, which
	// should only happen if the given context is canceled.
	startAllWebSrvs(ctx, appReady, intSrv, extSrv)

	log.Println("Exiting.")
}

func checkSystemSafety(config *config.Config) (err error) {
	defer errs.Wrap(&err, "failed system safety check")
	if config.Testing {
		return nil
	}

	if !system.HasSecureRNG() {
		return errors.New("system does not use desired RNG")
	}
	return nil
}

func setupSystem(config *config.Config) (err error) {
	defer errs.Wrap(&err, "failed to set up system")

	// GitHub Actions won't allow us to set up the lo interface.
	if config.Testing {
		return nil
	}

	if err := system.SetResolver(config.Resolver); err != nil {
		return err
	}

	if err := system.SeedRandomness(); err != nil {
		return err
	}
	// When running unit tests inside a Nitro Enclave, the loopback interface
	// may already exist, in which case we ignore the error.
	if err := system.SetupLo(); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

func startAllWebSrvs(
	ctx context.Context,
	ready chan struct{},
	intSrv *http.Server,
	extSrv *http.Server,
) {
	go func(srv *http.Server) {
		log.Printf("Starting internal web server at: %s", intSrv.Addr)
		err := intSrv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error serving internal web server: %v", err)
		}
	}(intSrv)
	// If desired, wait for the application's "ready" signal before starting the
	// external Web server.
	<-ready

	go func(srv *http.Server) {
		log.Printf("Starting external web server at: %s", extSrv.Addr)
		err := extSrv.ListenAndServeTLS("", "")
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error serving external web server: %v", err)
		}
	}(extSrv)

	// Wait until the context is canceled, at which point it's time to stop web
	// servers.
	<-ctx.Done()
	log.Print("Context cancelled; shutting down veil.")
	if err := intSrv.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down internal server: %v", err)
	}
	if err := extSrv.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down external server: %v", err)
	}
}

func newIntSrv(
	config *config.Config,
	hashes *attestation.Hashes,
	appReady chan struct{},
) *http.Server {
	r := chi.NewRouter()
	addInternalRoutes(r, config, hashes, appReady)

	return &http.Server{
		Addr:    net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", config.IntPort)),
		Handler: http.Handler(r),
	}
}

func newExtSrv(
	config *config.Config,
	builder *attestation.Builder,
) *http.Server {
	r := chi.NewRouter()
	addExternalPublicRoutes(r, config, builder)

	return &http.Server{
		Addr:    net.JoinHostPort("0.0.0.0", fmt.Sprintf("%d", config.ExtPort)),
		Handler: http.Handler(r),
	}
}
