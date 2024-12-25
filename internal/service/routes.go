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

func setupMiddlewares(r *chi.Mux, cfg *config.Veil) {
	if cfg.Debug {
		r.Use(middleware.Logger)
	}
}

func addExternalPublicRoutes(
	r *chi.Mux,
	cfg *config.Veil,
	builder *attestation.Builder,
) {
	setupMiddlewares(r, cfg)

	r.Get(PathIndex, handle.Index(cfg))
	r.Get(PathConfig, handle.Config(builder, cfg))
	r.Get(PathAttestation, handle.Attestation(builder))

	// Set up reverse proxy for the application' Web server.
	if cfg.AppWebSrv != nil {
		reverseProxy := httputil.NewSingleHostReverseProxy(cfg.AppWebSrv)
		r.Handle("/*", reverseProxy)
	}
}

func addInternalRoutes(
	r *chi.Mux,
	cfg *config.Veil,
	hashes *attestation.Hashes,
	appReady chan struct{},
) {
	setupMiddlewares(r, cfg)

	if cfg.WaitForApp {
		r.Get(PathReady, handle.Ready(appReady))
	} else {
		close(appReady)
	}
	r.Get(PathHashes, handle.Hashes(hashes))
	r.Post(PathHash, handle.AppHash(hashes.SetAppHash))
}
