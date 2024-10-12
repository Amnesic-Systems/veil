package config

import (
	"context"
	"net/url"
	"strconv"

	"github.com/Amnesic-Systems/veil/internal/util"
)

var _ = util.Validator(&Config{})

// Config represents the configuration of our enclave service.
type Config struct {
	SourceCodeURI string

	// FQDN contains the fully qualified domain name that's set in the HTTPS
	// certificate of the enclave's Web server, e.g. "example.com".  This field
	// is required.
	FQDN string

	// FQDNLeader contains the fully qualified domain name of the leader
	// enclave, which coordinates enclave synchronization.  Only set this field
	// if horizontal scaling is required.
	FQDNLeader string

	// ExtPubPort contains the TCP port that the public Web server should
	// listen on, e.g. 443.  This port is not *directly* reachable by the
	// Internet but the EC2 host's proxy *does* forward Internet traffic to
	// this port.  This field is required.
	ExtPubPort string
	ExtPubHost string

	IntHost string
	IntPort string

	EnableTesting bool

	// ExtPrivPort contains the TCP port that the non-public Web server should
	// listen on.  The Web server behind this port exposes confidential
	// endpoints and is therefore only meant to be reachable by the enclave
	// administrator but *not* the public Internet.
	ExtPrivPort uint16

	// IntPort contains the enclave-internal TCP port of the Web server that
	// provides an HTTP API to the enclave application.  This field is
	// required.
	//IntPort uint16

	// UseVsockForExtPort must be set to true if direct communication
	// between the host and Web server via VSOCK is desired. The daemon will listen
	// on the enclave's VSOCK address and the port defined in ExtPubPort.
	UseVsockForExtPort bool

	// DisableKeepAlives must be set to true if keep-alive connections
	// should be disabled for the HTTPS service.
	DisableKeepAlives bool

	// HostProxyPort indicates the TCP port of the proxy application running on
	// the EC2 host.  Note that VSOCK ports are 32 bits large.  This field is
	// required.
	HostProxyPort uint32

	// PrometheusPort contains the TCP port of the Web server that exposes
	// Prometheus metrics.  Prometheus metrics only reveal coarse-grained
	// information and are safe to export in production.
	PrometheusPort uint16

	// PrometheusNamespace specifies the namespace for exported Prometheus
	// metrics.  Consider setting this to your application's name.
	PrometheusNamespace string

	// UseProfiling enables profiling via pprof.  Profiling information will be
	// available at /enclave/debug.  Note that profiling data is privacy
	// sensitive and therefore must not be enabled in production.
	UseProfiling bool

	// UseACME must be set to true if you want your enclave application to
	// request a Let's Encrypt-signed certificate.  If this is set to false,
	// the enclave creates a self-signed certificate.
	UseACME bool

	// Debug can be set to true to see debug messages, i.e., if you are
	// starting the enclave in debug mode by running:
	//
	//	nitro-cli run-enclave --debug-mode ....
	//
	// Do not set this to true in production because printing debug messages
	// for each HTTP request slows down the enclave application, and you are
	// not able to see debug messages anyway unless you start the enclave using
	// nitro-cli's "--debug-mode" flag.
	Debug bool

	// FdCur and FdMax set the soft and hard resource limit, respectively.  The
	// default for both variables is 65536.
	FdCur uint64
	FdMax uint64

	// RepoURL should be set to the URL of the software repository that's
	// running inside the enclave, e.g., "https://github.com/foo/bar".  The URL
	// is shown on the enclave's index page, as part of instructions on how to
	// do remote attestation.
	RepoURL *url.URL

	// AppWebSrv should be set to the enclave-internal Web server of the
	// enclave application, e.g., "http://127.0.0.1:8080".  Nitriding acts as a
	// TLS-terminating reverse proxy and forwards incoming HTTP requests to
	// this Web server.  Note that this configuration option is only necessary
	// if the enclave application exposes an HTTP server.  Non-HTTP enclave
	// applications can ignore this.
	AppWebSrv *url.URL

	// WaitForApp instructs nitriding to wait for the application's signal
	// before launching the Internet-facing Web server.  Set this flag if your
	// application takes a while to bootstrap and you don't want to risk
	// inconsistent state when syncing, or unexpected attestation documents.
	// If set, your application must make the following request when ready:
	//
	//     GET http://127.0.0.1:{IntPort}/enclave/ready
	WaitForApp bool

	// MockCertFp specifies a mock TLS certificate fingerprint
	// to use in attestation documents.
	MockCertFp string
}

func isValidPort(port string) bool {
	num, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if num < 1 || num > 65535 {
		return false
	}
	return true
}

func (c *Config) Validate(_ context.Context) map[string]string {
	problems := make(map[string]string)

	// Check required fields.
	if !isValidPort(c.ExtPubPort) {
		problems["ExtPubPort"] = "must be a valid port number"
	}
	if !isValidPort(c.IntPort) {
		problems["IntPort"] = "must be a valid port number"
	}

	return problems
}
