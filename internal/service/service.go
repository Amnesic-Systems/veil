package service

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/Amnesic-Systems/veil/internal/system"
	"github.com/Amnesic-Systems/veil/internal/tunnel"
	"github.com/go-chi/chi/v5"
)

type service struct {
	extSrv *http.Server
	intSrv *http.Server
}

func Run(
	ctx context.Context,
	config *config.Config,
	attester enclave.Attester,
	mechanism tunnel.Mechanism,
) {
	var (
		svc      = new(service)
		appReady = make(chan struct{})
	)

	// Perform basic safety checks before starting.
	if !system.HasSecureRNG() {
		log.Fatal("Nitro hardware RNG is not in use.")
	}

	// Initialize the enclave keys for enclave synchronization.
	keys := new(enclave.Keys)
	// TODO: Remove debug code
	keys.SetAppKeys([]byte("app_keys"))
	keys.SetVeilKeys([]byte("veil_key"), []byte("veil_cert"))
	// Initialize hashes for the attestation document.
	hashes := new(attestation.Hashes)

	// Initialize Web servers.
	svc.extSrv = NewExtSrv(config, attester, attestation.AuxToClient(hashes))
	svc.intSrv = NewIntSrv(config, keys, hashes, appReady)

	// Set up the networking tunnel. This function will block until the tunnel
	// is ready to use.
	tunnel.New(ctx, mechanism)

	// Start all Web servers and block until all Web servers have stopped, which
	// should only happen if the given context is canceled.
	startAllWebSrvs(ctx, config.WaitForApp, appReady, svc.intSrv, svc.extSrv)

	log.Println("Exiting.")
}

func startAllWebSrvs(
	ctx context.Context,
	waitForApp bool,
	ready chan struct{},
	intSrv *http.Server,
	extSrv *http.Server,
) {
	var wg = new(sync.WaitGroup)
	defer wg.Wait()

	// Start the internal Web server first.  If desired, we'll wait for the
	// application's "ready" signal before starting the external Web server.
	startWebSrv(ctx, intSrv, wg)
	if waitForApp {
		<-ready
	}
	log.Print("Application is ready.")
	startWebSrv(ctx, extSrv, wg)
}

func startWebSrv(
	ctx context.Context,
	srv *http.Server,
	wg *sync.WaitGroup,
) {
	go func(srv *http.Server) {
		log.Printf("Starting web server: %v", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error listening and serving: %v", err)
		}
	}(srv)

	wg.Add(1)
	go func(ctx context.Context, srv *http.Server, wg *sync.WaitGroup) {
		defer wg.Done()
		log.Print("Waiting for web server to shut down.")
		<-ctx.Done()
		log.Printf("Got signal – shutting down: %s", srv.Addr)
		// TODO: only do shutdown if server is actually running
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down server: %v", err)
		}
		log.Print("Web server is done.")
	}(ctx, srv, wg)
}

func NewIntSrv(
	config *config.Config,
	keys *enclave.Keys,
	hashes *attestation.Hashes,
	appReady chan struct{},
) *http.Server {
	r := chi.NewRouter()
	addInternalRoutes(r, config, keys, hashes, appReady)

	return &http.Server{
		Addr: net.JoinHostPort(
			config.IntHost,
			config.IntPort,
		),
		Handler: http.Handler(r),
	}
}

func NewExtSrv(
	config *config.Config,
	attester enclave.Attester,
	auxFn enclave.AuxFunc,
) *http.Server {
	r := chi.NewRouter()
	addExternalPublicRoutes(r, config, attester, auxFn)

	return &http.Server{
		Addr: net.JoinHostPort(
			config.ExtPubHost,
			config.ExtPubPort,
		),
		Handler: http.Handler(r),
	}
}
