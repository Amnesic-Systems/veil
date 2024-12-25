package config

import (
	"net/url"
)

// Veil represents veil's configuration.
type Veil struct {
	// AppCmd can be set to the command that starts the enclave application.
	// For example:
	//
	//	nc -l -p 1234
	//
	// Veil starts the given application after its internal Web server is
	// running, and subsequently waits for the application to finish.  When the
	// application stops or crashes, veil terminates.
	AppCmd string

	// AppWebSrv should be set to the enclave-internal Web server of the
	// enclave application, e.g., "http://127.0.0.1:8080".  Veil acts as a
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

	// EnclaveCodeURI contains the URI of the software repository that's running
	// inside the enclave, e.g., "https://github.com/foo/bar".  The URL is shown
	// on the enclave's index page, as part of instructions on how to do remote
	// attestation.
	EnclaveCodeURI string

	// ExtPort contains the TCP port that the public Web server should
	// listen on, e.g. 443.  This port is not *directly* reachable by the
	// Internet but the EC2 host's proxy *does* forward Internet traffic to
	// this port.  This field is required.
	ExtPort int

	// FQDN contains the fully qualified domain name that's set in the HTTPS
	// certificate of the enclave's Web server, e.g. "example.com".  This field
	// is required.
	FQDN string

	// IntPort contains the TCP port that the internal Web server should listen
	// on, e.g., 8080.  This port is only reachable from within the enclave and
	// is only used by the enclave application.  This field is required.
	IntPort int

	// Resolver contains the IP address of the DNS resolver that the enclave
	// should use, e.g., 1.1.1.1.
	Resolver string

	// SilenceApp can be set to discard the application's stdout and stderr if
	// -app-cmd is used.
	SilenceApp bool

	// Testing facilitates local testing by disabling safety checks that we
	// would normally run on the enclave and by using the noop attester instead
	// of the real attester.
	Testing bool

	// VSOCKPort contains the port that veil uses to communicate with veil-proxy
	// on the EC2 host.
	VSOCKPort uint32

	// WaitForApp instructs veil to wait for the application's signal
	// before launching the Internet-facing Web server.  Set this flag if your
	// application takes a while to bootstrap and you don't want to risk
	// inconsistent state when syncing, or unexpected attestation documents.
	// If set, your application must make the following request when ready:
	//
	//     GET http://127.0.0.1:{IntPort}/enclave/ready
	WaitForApp bool
}

func isValidPort(port int) bool {
	return port > 0 && port < 65536
}

func (c *Veil) Validate() map[string]string {
	problems := make(map[string]string)

	// Check required fields.
	if !isValidPort(c.ExtPort) {
		problems["-ext-port"] = "must be a valid port number"
	}
	if !isValidPort(c.IntPort) {
		problems["-int-port"] = "must be a valid port number"
	}

	if c.VSOCKPort == 0 {
		problems["-vsock-port"] = "port must not be 0"
	}

	// Check invalid field combinations.
	if c.SilenceApp && c.AppCmd == "" {
		problems["-silence-app"] = "requires -app-cmd to be set"
	}

	return problems
}
