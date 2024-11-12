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
	// AppWebSrv should be set to the enclave-internal Web server of the
	// enclave application, e.g., "http://127.0.0.1:8080".  Nitriding acts as a
	// TLS-terminating reverse proxy and forwards incoming HTTP requests to
	// this Web server.  Note that this configuration option is only necessary
	// if the enclave application exposes an HTTP server.  Non-HTTP enclave
	// applications can ignore this.
	AppWebSrv *url.URL

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

	// ExtPubPort contains the TCP port that the public Web server should
	// listen on, e.g. 443.  This port is not *directly* reachable by the
	// Internet but the EC2 host's proxy *does* forward Internet traffic to
	// this port.  This field is required.
	ExtPubPort string

	// FQDN contains the fully qualified domain name that's set in the HTTPS
	// certificate of the enclave's Web server, e.g. "example.com".  This field
	// is required.
	FQDN string

	// IntPort contains the TCP port that the internal Web server should listen
	// on, e.g., 8080.  This port is only reachable from within the enclave and
	// is only used by the enclave application.  This field is required.
	IntPort string

	// SourceCodeURI contains the URI of the software repository that's running
	// inside the enclave, e.g., "https://github.com/foo/bar".  The URL is shown
	// on the enclave's index page, as part of instructions on how to do remote
	// attestation.
	SourceCodeURI string

	// Testing facilitates local testing by disabling safety checks that we
	// would normally run on the enclave and by using the noop attester instead
	// of the real attester.
	Testing bool

	// WaitForApp instructs nitriding to wait for the application's signal
	// before launching the Internet-facing Web server.  Set this flag if your
	// application takes a while to bootstrap and you don't want to risk
	// inconsistent state when syncing, or unexpected attestation documents.
	// If set, your application must make the following request when ready:
	//
	//     GET http://127.0.0.1:{IntPort}/enclave/ready
	WaitForApp bool
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
