package service

import (
	"net/http/httputil"

	"github.com/Amnesic-Systems/veil/internal/config"
	"github.com/Amnesic-Systems/veil/internal/enclave"
	"github.com/Amnesic-Systems/veil/internal/service/attestation"
	"github.com/Amnesic-Systems/veil/internal/service/handle"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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

	r.Get("/enclave", handle.Index(config))
	r.Get("/enclave/config", handle.Config(builder, config))
	r.Get("/enclave/attestation", handle.Attestation(builder))

	// Set up reverse proxy for the application' Web server.
	if config.AppWebSrv != nil {
		reverseProxy := httputil.NewSingleHostReverseProxy(config.AppWebSrv)
		r.Handle("/*", reverseProxy)
	}
}

func addInternalRoutes(
	r *chi.Mux,
	config *config.Config,
	keys *enclave.Keys,
	hashes *attestation.Hashes,
	appReady chan struct{},
) {
	setupMiddlewares(r, config)

	if config.WaitForApp {
		r.Get("/enclave/ready", handle.Ready(appReady))
	} else {
		close(appReady)
	}
	r.Get("/enclave/hashes", handle.Hashes(hashes))
	r.Post("/enclave/hash", handle.AppHash(hashes.SetAppHash))
	r.Handle("/enclave/state", handle.NewState(keys))
}
