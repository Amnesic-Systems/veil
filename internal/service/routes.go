package service

import (
	"net/http/httputil"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/Amnesic-Systems/veil/internal/service/handle"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Veil's URL paths.
const (
	PathIndex       = "/veil"
	PathConfig      = "/veil/config"
	PathAttestation = "/veil/attestation"
	PathReady       = "/veil/ready"
	PathHashes      = "/veil/hashes"
	PathHash        = "/veil/hash"
)

func setupMiddlewares(r *chi.Mux, config *config.Config) {
	if config.Debug {
		r.Use(middleware.Logger)
	}
}

func addExternalPublicRoutes(
	r *chi.Mux,
	config *config.Config,
	builder *attestation.Builder,
) {
	setupMiddlewares(r, config)

	r.Get(PathIndex, handle.Index(config))
	r.Get(PathConfig, handle.Config(builder, config))
	r.Get(PathAttestation, handle.Attestation(builder))

	// Set up reverse proxy for the application' Web server.
	if config.AppWebSrv != nil {
		reverseProxy := httputil.NewSingleHostReverseProxy(config.AppWebSrv)
		r.Handle("/*", reverseProxy)
	}
}

func addInternalRoutes(
	r *chi.Mux,
	config *config.Config,
	hashes *attestation.Hashes,
	appReady chan struct{},
) {
	setupMiddlewares(r, config)

	if config.WaitForApp {
		r.Get(PathReady, handle.Ready(appReady))
	} else {
		close(appReady)
	}
	r.Get(PathHashes, handle.Hashes(hashes))
	r.Post(PathHash, handle.AppHash(hashes.SetAppHash))
}
